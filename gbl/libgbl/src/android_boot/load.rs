// Copyright 2024, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::cstr_bytes_to_str;
use crate::{
    android_boot::{
        avf::{build_pvmfw_data_region, BootInfo},
        kernel::{parse_kernel_attributes, KernelAttributes},
    },
    constants::PAGE_SIZE,
    device_tree::DtComponentSource,
    gbl_avb::LoadPartition,
    gbl_println,
    ops::GblOps,
    slots::{slotted_part, Slot},
};
use avb::SlotVerifyData;
use bootimg::{
    defs::{
        boot_img_hdr_v0, boot_img_hdr_v3, vendor_boot_img_hdr_v3, vendor_ramdisk_table_entry_v4,
        VENDOR_RAMDISK_TYPE_DLKM, VENDOR_RAMDISK_TYPE_NONE, VENDOR_RAMDISK_TYPE_PLATFORM,
        VENDOR_RAMDISK_TYPE_RECOVERY,
    },
    BootImage, VendorImageHeader,
};
use core::ops::Range;
use gbl_decompress::decompress_or_copy;
use liberror::Error;
use safemath::SafeNum;
use zerocopy::{IntoBytes, Ref};

// Helper for constructing a range that ends at a page aligned boundary. Specifically, it returns
// `start..round_up(start + sz, page_size)`
fn page_aligned_range(
    start: impl Into<SafeNum>,
    sz: impl Into<SafeNum>,
    page_size: impl Into<SafeNum>,
) -> Result<Range<usize>, Error> {
    let start = start.into();
    Ok(start.try_into()?..(start + sz.into()).round_up(page_size.into()).try_into()?)
}

/// Returns the exact payload range without including alignment padding.
fn exact_range(start: impl Into<SafeNum>, sz: impl Into<SafeNum>) -> Result<Range<usize>, Error> {
    let start = start.into();
    Ok(start.try_into()?..(start + sz.into()).try_into()?)
}

/// Represents a loaded boot image of version 2 and lower.
///
/// TODO(b/578052925): Investigate if the APIs are better suited for bootimg.rs. The issue
/// is that it uses `Error` and `SafeNum` from GBL.
#[derive(Clone)]
struct BootImageV2Info<'a> {
    cmdline: &'a str,
    /// Kernel payload without the page alignment padding.
    kernel_exact_range: Range<usize>,
    ramdisk_range: Range<usize>,
    dtb_range: Range<usize>,
}

impl<'a> BootImageV2Info<'a> {
    /// Creates a new instance.
    fn new(buffer: &'a [u8]) -> Result<Self, Error> {
        let header = BootImage::parse(buffer)?;
        if matches!(header, BootImage::V3(_) | BootImage::V4(_)) {
            return Err(Error::InvalidInput);
        }
        // This is valid since v1/v2 are superset of v0.
        let v0 = Ref::into_ref(Ref::<_, boot_img_hdr_v0>::from_prefix(buffer).unwrap().0);
        let page_size: usize = v0.page_size.try_into()?;
        let cmdline = cstr_bytes_to_str(&v0.cmdline[..])?;
        let kernel_range = page_aligned_range(page_size, v0.kernel_size, page_size)?;
        let kernel_exact_range = exact_range(page_size, v0.kernel_size)?;
        let ramdisk_range = page_aligned_range(kernel_range.end, v0.ramdisk_size, page_size)?;
        let second_range = page_aligned_range(ramdisk_range.end, v0.second_size, page_size)?;

        let start = u64::try_from(second_range.end)?;
        let (off, sz) = match header {
            BootImage::V1(v) => (v.recovery_dtbo_offset, v.recovery_dtbo_size),
            BootImage::V2(v) => (v._base.recovery_dtbo_offset, v._base.recovery_dtbo_size),
            _ => (start, 0),
        };
        let recovery_dtb_range = match off >= start {
            true => page_aligned_range(off, sz, page_size)?,
            _ if off == 0 => page_aligned_range(start, 0, page_size)?,
            _ => return Err(Error::Other(Some("Unexpected recovery_dtbo_offset"))),
        };
        let dtb_sz: usize = match header {
            BootImage::V2(v) => v.dtb_size.try_into().unwrap(),
            _ => 0,
        };
        let dtb_range = page_aligned_range(recovery_dtb_range.end, dtb_sz, page_size)?;
        Ok(Self { cmdline, kernel_exact_range, ramdisk_range, dtb_range })
    }
}

// Contains information of a V3/V4 boot image.
#[derive(Clone)]
pub(crate) struct BootImageV3Info {
    pub kernel_range: Range<usize>,
    /// Kernel payload without the page alignment padding.
    kernel_exact_range: Range<usize>,
    pub ramdisk_range: Range<usize>,
}

impl BootImageV3Info {
    /// Creates a new instance.
    pub(crate) fn new(buffer: &[u8]) -> Result<Self, Error> {
        let header = BootImage::parse(buffer)?;
        if !matches!(header, BootImage::V3(_) | BootImage::V4(_)) {
            return Err(Error::InvalidInput);
        }
        let v3 = Self::v3(buffer);
        let kernel_range = page_aligned_range(PAGE_SIZE, v3.kernel_size, PAGE_SIZE)?;
        let kernel_exact_range = exact_range(PAGE_SIZE, v3.kernel_size)?;
        let ramdisk_range = page_aligned_range(kernel_range.end, v3.ramdisk_size, PAGE_SIZE)?;
        Ok(Self { kernel_range, kernel_exact_range, ramdisk_range })
    }

    /// Gets the v3 base header.
    fn v3(buffer: &[u8]) -> &boot_img_hdr_v3 {
        // This is valid since v4 is superset of v3.
        Ref::into_ref(Ref::from_prefix(buffer).unwrap().0)
    }

    // Decodes the kernel cmdline
    fn cmdline(buffer: &[u8]) -> Result<&str, Error> {
        cstr_bytes_to_str(&Self::v3(buffer).cmdline[..])
    }
}

#[repr(u32)]
#[derive(Debug)]
enum VendorBootRamdiskType {
    NONE = VENDOR_RAMDISK_TYPE_NONE,
    PLTFORM = VENDOR_RAMDISK_TYPE_PLATFORM,
    RECOVERY = VENDOR_RAMDISK_TYPE_RECOVERY,
    DLKM = VENDOR_RAMDISK_TYPE_DLKM,
}

impl TryFrom<u32> for VendorBootRamdiskType {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            VENDOR_RAMDISK_TYPE_NONE => Ok(VendorBootRamdiskType::NONE),
            VENDOR_RAMDISK_TYPE_PLATFORM => Ok(VendorBootRamdiskType::PLTFORM),
            VENDOR_RAMDISK_TYPE_RECOVERY => Ok(VendorBootRamdiskType::RECOVERY),
            VENDOR_RAMDISK_TYPE_DLKM => Ok(VendorBootRamdiskType::DLKM),
            _ => Err(Error::InvalidInput),
        }
    }
}

#[derive(Debug)]
struct VendorBootRamdiskEntry {
    ramdisk_range: Range<usize>,
    ramdisk_type: VendorBootRamdiskType,
}

/// Contains vendor boot image information.
struct VendorBootImageInfo {
    ramdisk_range: Range<usize>,
    dtb_range: Range<usize>,
    bootconfig_range: Range<usize>,
    ramdisk_table: arrayvec::ArrayVec<VendorBootRamdiskEntry, RAMDISK_TABLE_MAX_ENTRIES>,
}

impl VendorBootImageInfo {
    /// Creates a new instance.
    fn new(buffer: &[u8]) -> Result<Self, Error> {
        let header = VendorImageHeader::parse(buffer)?;
        let v3 = Self::v3(buffer);
        let page_size = v3.page_size;
        let header_size = match header {
            VendorImageHeader::V3(hdr) => SafeNum::from(hdr.as_bytes().len()),
            VendorImageHeader::V4(hdr) => SafeNum::from(hdr.as_bytes().len()),
        }
        .round_up(page_size);
        let ramdisk_range = page_aligned_range(header_size, v3.vendor_ramdisk_size, page_size)?;
        let dtb_sz: usize = v3.dtb_size.try_into().unwrap();
        let dtb_range = page_aligned_range(ramdisk_range.end, dtb_sz, page_size)?;

        let (table_sz, bootconfig_sz) = match header {
            VendorImageHeader::V4(hdr) => (hdr.vendor_ramdisk_table_size, hdr.bootconfig_size),
            _ => (0, 0),
        };
        let table = page_aligned_range(dtb_range.end, table_sz, page_size)?;
        let bootconfig_range = table.end..(table.end + usize::try_from(bootconfig_sz)?);
        let mut ramdisk_table = arrayvec::ArrayVec::new();
        if let VendorImageHeader::V4(hdr) = header
            && hdr.vendor_ramdisk_table_entry_num > 0
        {
            let table_entries: Ref<_, [vendor_ramdisk_table_entry_v4]> =
                Ref::from_prefix_with_elems(
                    &buffer[table],
                    hdr.vendor_ramdisk_table_entry_num as usize,
                )
                .map_err(|_| Error::InvalidInput)?
                .0;
            if hdr.vendor_ramdisk_table_entry_num as usize > RAMDISK_TABLE_MAX_ENTRIES {
                return Err(Error::Other(Some(
                    "Ramdisk table entry exceeded max supported entry count",
                )));
            }

            ramdisk_table.extend(table_entries.iter().map(|e| {
                let start = ramdisk_range.start + e.ramdisk_offset as usize;
                let end = start + e.ramdisk_size as usize;
                VendorBootRamdiskEntry {
                    ramdisk_range: start..end,
                    ramdisk_type: e.ramdisk_type.try_into().unwrap(),
                }
            }));
        }
        Ok(Self { ramdisk_range, dtb_range, bootconfig_range, ramdisk_table })
    }

    /// Gets the v3 base header.
    fn v3(buffer: &[u8]) -> &vendor_boot_img_hdr_v3 {
        Ref::into_ref(Ref::<_, _>::from_prefix(buffer).unwrap().0)
    }

    // Decodes the vendor cmdline
    fn cmdline(buffer: &[u8]) -> Result<&str, Error> {
        cstr_bytes_to_str(&Self::v3(buffer).cmdline[..])
    }
}

// Max number of ramdisks supported in vendor_boot partition.
// There's currently no limit on how many ramdisks entries can be
// in the vendor_boot ramdisk table, so we set a reasonable limit here.
// Feel free to adjust
pub const RAMDISK_TABLE_MAX_ENTRIES: usize = 8;
// init_boot/boot + however many ramdisks in vendor_boot
//                + however many ramdisks in vendor_kernel_boot
pub const RAMDISK_MAX_ENTRIES: usize = RAMDISK_TABLE_MAX_ENTRIES * 2 + 2;

/// Contains various loaded image components by `android_load_verified`
#[derive(Default)]
pub struct LoadedImages<'a> {
    /// dtbo image.
    pub dtbo: &'a [u8],
    /// Kernel commandline.
    pub boot_cmdline: &'a str,
    /// Vendor commandline,
    pub vendor_cmdline: &'a str,
    /// Vendor commandline,
    pub vendor_bootconfig: &'a [u8],
    /// DTB.
    pub dtb: &'a [u8],
    /// DTB source.
    pub dtb_source: Option<DtComponentSource>,
    /// DTB from partition.
    pub dtb_part: &'a [u8],
    /// pVM firmware image.
    pub pvmfw: &'a [u8],
    /// kernel from boot image,
    pub kernel: &'a [u8],
    /// ramdisks to be concatenated (vendor_boot+vendor_kernel_boot+init_boot/boot)
    pub ramdisks: arrayvec::ArrayVec<&'a [u8], RAMDISK_MAX_ENTRIES>,
}

/// Helper for getting a successfully verified partition from `SlotVerifyData`
fn get_verified_partition<'a, 'b>(
    ops: &mut impl GblOps<'a>,
    part: LoadPartition,
    slot: Option<Slot>,
    unlocked: bool,
    optional: bool,
    verify_data: &'b SlotVerifyData,
) -> Result<&'b [u8], Error> {
    let slotted = slotted_part(part.name(), slot.map(|s| s.suffix));
    let part_res =
        verify_data.partition_data().iter().find(|v| v.partition_name() == part.name_cstr());
    match part_res {
        None if optional => {
            gbl_println!(ops, "{slotted:?} is not loaded by avb. Image is optional. Skipping.");
            Ok(&[][..])
        }
        None => {
            gbl_println!(
                ops,
                "Error: {slotted:?} is required but is not loaded by avb. \
                The partition may be missing or not included in the vbmeta."
            );
            Err(Error::NotFound)
        }
        Some(v) => match v.verify_result() {
            Ok(_) => Ok(v.data()),
            Err(_) if unlocked => {
                gbl_println!(
                    ops,
                    "{slotted:?} verification failed. Device is unlocked. Continuing."
                );
                Ok(v.data())
            }
            _ => unreachable!(), // Should not reach here if locked and verification failed.
        },
    }
}

/// Helper for parsing and logging boot image version.
fn log_and_parse_bootimg<'a, 'b>(
    ops: &mut impl GblOps<'a>,
    data: &'b [u8],
) -> Result<BootImage<&'b [u8]>, Error> {
    let bootimg = BootImage::parse(data).map_err(Error::from)?;
    let ver_str = match bootimg {
        BootImage::V0(_) => "V0",
        BootImage::V1(_) => "V1",
        BootImage::V2(_) => "V2",
        BootImage::V3(_) => "V3",
        BootImage::V4(_) => "V4",
    };
    gbl_println!(ops, "Boot image {ver_str}.");
    Ok(bootimg)
}

/// Loads android images from avb verified partitions.
///
/// # Args
///
/// * `ops`: An implementation of `GblOps`.
/// * `slot`: The target slot to loader.
/// * `unlocked`: The unlock state.
/// * `is_recovery`: Whether we are booting to recovery.
/// * `verify_data`: `SlotVerifyData` returns from `avb_slot_verify`.
pub(super) fn android_load_verified<'a, 'b>(
    ops: &mut impl GblOps<'a>,
    slot: Option<Slot>,
    unlocked: bool,
    is_recovery: bool,
    verify_data: &'b SlotVerifyData,
) -> Result<LoadedImages<'b>, Error> {
    let mut images = LoadedImages {
        dtb_part: get_verified_partition(
            ops,
            LoadPartition::Dtb,
            slot,
            unlocked,
            true,
            verify_data,
        )?,
        dtbo: get_verified_partition(ops, LoadPartition::Dtbo, slot, unlocked, true, verify_data)?,
        ..Default::default()
    };
    if ops.avf_is_supported()? {
        images.pvmfw =
            get_verified_partition(ops, LoadPartition::Pvmfw, slot, unlocked, true, verify_data)?;
    }
    let boot =
        get_verified_partition(ops, LoadPartition::Boot, slot, unlocked, false, verify_data)?;
    match log_and_parse_bootimg(ops, boot)? {
        BootImage::V3(_) | BootImage::V4(_) => load_v3_and_v4_verified(
            ops,
            boot,
            slot,
            unlocked,
            is_recovery,
            verify_data,
            &mut images,
        ),
        BootImage::V0(_) | BootImage::V1(_) | BootImage::V2(_) => {
            load_v2_or_lower_verified(boot, &mut images)
        }
    }?;
    Ok(images)
}

/// Loads android boot images of version 0, 1 and 2 from avb verified partitions.
///
/// # Args
///
/// * `boot`: A buffer containing the boot image loaded by avb.
/// * `images`: The output `LoadedImages` that stores image slices from `boot`.
///
/// For v0, v1, v2 images:
///
/// * Both kernel and ramdisk come from the boot image.
/// * vendor_boot, init_boot are irrelevant.
fn load_v2_or_lower_verified<'a>(
    boot: &'a [u8],
    images: &mut LoadedImages<'a>,
) -> Result<(), Error> {
    let info = BootImageV2Info::new(boot).unwrap();
    images.boot_cmdline = info.cmdline;
    images.dtb = get_range(boot, &info.dtb_range)?;
    images.dtb_source = Some(DtComponentSource::Boot);
    images.kernel = get_range(boot, &info.kernel_exact_range)?;
    images.ramdisks.push(get_range(boot, &info.ramdisk_range)?);
    Ok(())
}

fn parse_vendor_ramdisks<'a, const CAP: usize>(
    image_data: &'a [u8],
    info: &VendorBootImageInfo,
    is_recovery: bool,
    ramdisks: &mut arrayvec::ArrayVec<&'a [u8], CAP>,
) -> Result<(), Error> {
    // Recovery ramdisk is only needed in recovery mode. So if we are not
    // booting recovery, skip recovery ramdisk
    if info.ramdisk_table.is_empty() {
        // No ramdisk table (v3 image), just load all ramdisks.
        ramdisks.push(get_range(image_data, &info.ramdisk_range)?);
    } else {
        for e in info.ramdisk_table.iter() {
            // Skips recovery ramdisk when booting to normal android
            if !is_recovery && matches!(e.ramdisk_type, VendorBootRamdiskType::RECOVERY) {
                continue;
            }
            ramdisks.push(get_range(image_data, &e.ramdisk_range)?);
        }
    }
    Ok(())
}

/// Loads android boot images of version 3 and 4 from avb verified partitions.
///
/// # Args
///
/// * `ops`: An implementation of `GblOps`.
/// * `boot`: A buffer containing the boot image.
/// * `slot`: The target slot to loader.
/// * `unlocked`: The unlock state.
/// * `is_recovery`: Whether we are booting to recovery.
/// * `verify_data`: `SlotVerifyData` returns from `avb_slot_verify`.
/// * `images`: The output `LoadedImages` that stores image slices from partitions in `verify_data`.
///
/// V3, V4 images have the following characteristics:
///
/// * Kernel comes from "boot_a/b" partition.
/// * Generic ramdisk may come from either "boot_a/b" or "init_boot_a/b" partitions.
/// * Vendor ramdisk comes from "vendor_boot_a/b" partition.
/// * V4 vendor_boot contains additional bootconfig.
///
/// From the perspective of Android versions:
///
/// Android 11:
///
/// * Can use v3 header.
/// * Generic ramdisk is in the "boot_a/b" partitions.
///
/// Android 12:
///
/// * Can use v3 or v4 header.
/// * Generic ramdisk is in the "boot_a/b" partitions.
///
/// Android 13:
///
/// * Can use v3 or v4 header.
/// * Generic ramdisk is in the "init_boot_a/b" partitions.
///
/// # References
///
/// https://source.android.com/docs/core/architecture/bootloader/boot-image-header
/// https://source.android.com/docs/core/architecture/partitions/vendor-boot-partitions
/// https://source.android.com/docs/core/architecture/partitions/generic-boot
fn load_v3_and_v4_verified<'a, 'b>(
    ops: &mut impl GblOps<'a>,
    boot: &'b [u8],
    slot: Option<Slot>,
    unlocked: bool,
    is_recovery: bool,
    verify_data: &'b SlotVerifyData,
    images: &mut LoadedImages<'b>,
) -> Result<(), Error> {
    let boot_info = BootImageV3Info::new(boot).unwrap();
    images.boot_cmdline = BootImageV3Info::cmdline(boot)?;

    // Loads vendor_boot partition, including ramdisk, dtb, commandline etc.
    let vendor_boot =
        get_verified_partition(ops, LoadPartition::VendorBoot, slot, unlocked, false, verify_data)?;
    let vendor_boot_info = VendorBootImageInfo::new(vendor_boot)?;
    images.vendor_cmdline = VendorBootImageInfo::cmdline(vendor_boot)?;
    images.dtb = get_range(vendor_boot, &vendor_boot_info.dtb_range)?;
    images.dtb_source = Some(DtComponentSource::VendorBoot);
    images.vendor_bootconfig = get_range(vendor_boot, &vendor_boot_info.bootconfig_range)?;
    images.kernel = get_range(boot, &boot_info.kernel_exact_range)?;
    parse_vendor_ramdisks(vendor_boot, &vendor_boot_info, is_recovery, &mut images.ramdisks)?;

    // Finds and loads vendor_kernel_boot partition if provided.
    let vendor_kernel_boot = get_verified_partition(
        ops,
        LoadPartition::VendorKernelBoot,
        slot,
        unlocked,
        true,
        verify_data,
    )?;
    if !vendor_kernel_boot.is_empty() {
        let info = VendorBootImageInfo::new(vendor_kernel_boot)?;
        // DTB should be provided by vendor_kerenl_boot if it exists.
        images.dtb = get_range(vendor_kernel_boot, &info.dtb_range)?;
        parse_vendor_ramdisks(vendor_kernel_boot, &info, is_recovery, &mut images.ramdisks)?;
    }

    // Loads generic ramdisk, which may come from either boot or init_boot.
    let generic_ramdisk = match boot_info.ramdisk_range.is_empty() {
        true => get_verified_partition(
            ops,
            LoadPartition::InitBoot,
            slot,
            unlocked,
            false,
            verify_data,
        )?,
        false => boot,
    };
    let generic_ramdisk_range = BootImageV3Info::new(generic_ramdisk)?.ramdisk_range;
    images.ramdisks.push(get_range(generic_ramdisk, &generic_ramdisk_range)?);
    Ok(())
}

/// Wrapper of `split_at_mut_checked` with error conversion.
pub(crate) fn split(buffer: &mut [u8], size: usize) -> Result<(&mut [u8], &mut [u8]), Error> {
    buffer.split_at_mut_checked(size).ok_or(Error::BufferTooSmall(Some(size)))
}

/// Wrapper of slice::get with error conversion.
fn get_range<'a>(buffer: &'a [u8], range: &Range<usize>) -> Result<&'a [u8], Error> {
    buffer.get(range.clone()).ok_or(Error::InvalidInput)
}

/// Parses and returns the kernel image from a boot image.
#[cfg(feature = "fuchsia")]
pub fn get_kernel(boot: &[u8]) -> Result<&[u8], Error> {
    match BootImage::parse(boot).map_err(Error::from)? {
        BootImage::V3(_) | BootImage::V4(_) => {
            boot.get(BootImageV3Info::new(boot)?.kernel_exact_range)
        }
        _ => boot.get(BootImageV2Info::new(boot)?.kernel_exact_range),
    }
    .ok_or(Error::InvalidInput)
}

/// Decompresses and loads kernel into `load`, which must span the kernel's `reserved_size`.
///
/// Returns the decompressed kernel and the kernel attributes.
pub(super) fn kernel_load<'b>(
    kernel: &[u8],
    load: &'b mut [u8],
) -> Result<(&'b [u8], KernelAttributes), Error> {
    let sz = decompress_or_copy(kernel, load)?;
    let attrs = parse_kernel_attributes(&load[..sz])?;
    if attrs.reserved_size > load.len() {
        return Err(Error::BufferTooSmall(Some(attrs.reserved_size)));
    }
    Ok((&load[..sz], attrs))
}

/// Loads pvmfw image into `load`.
///
/// Returns the pvmfw data region and the size of the pvmfw binary in it.
pub(super) fn pvmfw_load<'a, 'b>(
    ops: &mut impl GblOps<'a>,
    img: &[u8],
    load: &'b mut [u8],
    kernel_attrs: &KernelAttributes,
    boot_info: &BootInfo<SlotVerifyData>,
    dtbo_part: &[u8],
) -> Result<(&'b mut [u8], usize), Error> {
    // Parse the partition header and extract the pvmfw binary
    let info = BootImageV3Info::new(img)?;
    let pvmfw_bin = img.get(info.kernel_range.clone()).ok_or(Error::BadBufferSize)?;
    let sz = build_pvmfw_data_region(ops, load, pvmfw_bin, kernel_attrs, boot_info, dtbo_part)?;
    Ok((&mut load[..sz], pvmfw_bin.len()))
}

/// Loads ramdisks into `load`.
///
/// Returns the total size of the loaded ramdisks.
pub(super) fn ramdisk_load(ramdisks: &[&[u8]], load: &mut [u8]) -> Result<usize, Error> {
    let sz = ramdisks.iter().map(|v| v.len()).sum();
    let mut rem = split(load, sz)?.0;
    let mut curr;
    for v in ramdisks {
        (curr, rem) = split(rem, v.len())?;
        curr.clone_from_slice(v);
    }
    Ok(sz)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::read_test_data;
    use bootimg::defs::{boot_img_hdr_v4, BOOT_MAGIC, BOOT_MAGIC_SIZE};

    fn add_header<T: zerocopy::Immutable + IntoBytes>(buffer: &mut [u8], header: T) {
        header.write_to_prefix(buffer).unwrap();
    }

    #[test]
    fn v0_kernel_exact_range_excludes_page_padding() {
        let mut image = [0u8; PAGE_SIZE * 4];
        let kernel_size = PAGE_SIZE as u32 + 13;
        add_header(
            &mut image,
            boot_img_hdr_v0 {
                magic: BOOT_MAGIC[..BOOT_MAGIC_SIZE as usize].try_into().unwrap(),
                kernel_size,
                ramdisk_size: 17,
                page_size: PAGE_SIZE as u32,
                header_version: 0,
                ..Default::default()
            },
        );

        let info = BootImageV2Info::new(&image).unwrap();
        assert_eq!(info.kernel_exact_range, PAGE_SIZE..PAGE_SIZE + kernel_size as usize);
        assert_eq!(info.ramdisk_range.start, PAGE_SIZE * 3);
    }

    #[test]
    fn v4_kernel_exact_range_excludes_page_padding() {
        let mut image = [0u8; PAGE_SIZE * 4];
        let kernel_size = PAGE_SIZE as u32 + 13;
        add_header(
            &mut image,
            boot_img_hdr_v4 {
                _base: boot_img_hdr_v3 {
                    magic: BOOT_MAGIC[..BOOT_MAGIC_SIZE as usize].try_into().unwrap(),
                    kernel_size,
                    ramdisk_size: 17,
                    header_version: 4,
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        let info = BootImageV3Info::new(&image).unwrap();
        assert_eq!(info.kernel_exact_range, PAGE_SIZE..PAGE_SIZE + kernel_size as usize);
        assert_eq!(info.kernel_range, PAGE_SIZE..PAGE_SIZE * 3);
        assert_eq!(info.ramdisk_range.start, PAGE_SIZE * 3);
    }

    #[test]
    fn test_kernel_load_buffer_too_small() {
        let kernel = read_test_data("android/kernel_a.img");
        let mut load = vec![0u8; kernel.len() - 1];
        let res = kernel_load(&kernel, &mut load);
        assert_eq!(res.err(), Some(Error::BufferTooSmall(Some(kernel.len()))));
    }

    #[test]
    fn test_ramdisk_load_buffer_too_small() {
        assert_eq!(ramdisk_load(&[b"ab", b"c"], &mut [0; 2]), Err(Error::BufferTooSmall(Some(3))));
    }
}
