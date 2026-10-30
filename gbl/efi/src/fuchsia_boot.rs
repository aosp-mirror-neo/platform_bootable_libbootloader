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

use crate::utils::efi_to_zbi_mem_range_type;
use efi::{EfiMemoryAttributesTable, EfiMemoryMap};
use efi_types::{
    EfiMemoryAttributesTableHeader, EfiMemoryDescriptor, EFI_MEMORY_ATTRIBUTE_EMA_RUNTIME,
};
use liberror::{Error, Error::BufferTooSmall, Result as EfiResult};
use libgbl::constants::PAGE_SIZE as PAGE_SIZE_USIZE;
use safemath::SafeNum;
use zbi::{zbi_format::zbi_mem_range_t, ZbiContainer, ZbiFlags, ZbiType};
use zerocopy::{Ref, SplitByteSliceMut};
#[cfg(not(test))]
use {
    crate::{
        efi::{efi_println, EfiEntry},
        efi_blocks::EfiGblDisk,
        fastboot::efi_gbl_fastboot_entry,
        ops::Ops,
    },
    core::convert::Infallible,
    libgbl::{
        fuchsia_boot::{zircon_main, LoadedVerifiedZircon},
        gbl_println,
        partition::check_part_unique,
        GblOps, Result,
    },
};

const PAGE_SIZE: u64 = PAGE_SIZE_USIZE as u64;

/// Check if the disk GPT layout is a Fuchsia device layout.
#[cfg(not(test))]
pub fn is_fuchsia_gpt(disks: &[EfiGblDisk]) -> Result<()> {
    let partitions: &[&[&str]] = &[
        &["zircon_a", "zircon-a"],
        &["zircon_b", "zircon-b"],
        &["zircon_r", "zircon-r"],
        &["vbmeta_a"],
        &["vbmeta_b"],
        &["vbmeta_r"],
        &["misc", "durable_boot"],
    ];
    if !partitions
        .iter()
        .all(|&partition| partition.iter().any(|v| check_part_unique(disks, v).is_ok()))
    {
        return Err(Error::NotFound.into());
    }

    Ok(())
}

/// Loads and verifies Fuchsia according to A/B/R.
///
/// On success, returns a `LoadedVerifiedZircon`
#[cfg(not(test))]
pub fn efi_fuchsia_load<'a>(ops: &mut Ops, load: &'a mut [u8]) -> Result<LoadedVerifiedZircon<'a>> {
    let entry = ops.efi_entry;
    gbl_println!(ops, "Try booting as Fuchsia/Zircon");
    zircon_main(ops, load, |fb| efi_gbl_fastboot_entry(entry, fb))
}

/// Exits boot services and boots loaded fuchsia images.
#[cfg(not(test))]
pub fn efi_fuchsia_boot(
    efi_entry: EfiEntry,
    images: LoadedVerifiedZircon<'_>,
) -> Result<Infallible> {
    let LoadedVerifiedZircon { zbi_items, kernel, .. } = images;
    efi_println!(
        efi_entry,
        "Booting Fuchsia kernel @{:#x}, ZBI items @{:#x}",
        kernel.as_ptr() as usize,
        zbi_items.as_ptr() as usize
    );
    #[cfg(target_arch = "aarch64")]
    {
        // Uses the unused buffer for `exit_boot_services` to store output memory map.
        // The map is not used for now. We currently rely on UEFI firmware to pass memory map via
        // a raw zbi blob in device tree. Long term we want to support adding from EFI memory maps
        // if none is provided.
        let item_size = zbi::ZbiContainer::parse(&mut zbi_items[..])?.container_size()?;
        let (_, remains) = zbi_items.split_at_mut(item_size);
        let _ = efi::exit_boot_services(efi_entry, remains).unwrap();
        // SAFETY: The kernel has passed libavb verification or device is unlocked, in which case we
        // assume the caller has addressed all safety and security concerns.
        unsafe { boot::aarch64::jump_zircon_el2_or_lower(kernel, zbi_items) };
    }

    #[cfg(target_arch = "x86_64")]
    {
        const BUFFER_SIZE: usize = 32 * 1024 / 2;
        let mut mem_map_buf = [0u8; BUFFER_SIZE];
        let mut items = zbi::ZbiContainer::parse(&mut zbi_items[..])?;
        let efi_memory_attribute_table = crate::utils::get_efi_mem_attr(&efi_entry);
        if efi_memory_attribute_table.is_none() {
            efi_println!(
                efi_entry,
                "EFI_MEMORY_ATTRIBUTES_TABLE not found, synthesizing from memory map"
            );
        }

        // `exit_boot_service` returnes EFI memory map that is used to derive and append MEM_CONFIG
        // items.
        let efi_memory_map = efi::exit_boot_services(efi_entry, &mut mem_map_buf).unwrap();

        add_memory_items(&efi_memory_map, efi_memory_attribute_table.as_ref(), &mut items)?;

        // SAFETY: The kernel has passed libavb verification or device is unlocked, in which case we
        // assume the caller has addressed all safety and security concerns.
        unsafe { boot::x86::zbi_boot(kernel, zbi_items) };
    }

    #[cfg(target_arch = "riscv64")]
    {
        let _ = (efi_entry, kernel, zbi_items);
        Err(Error::Unsupported.into())
    }
}

// This function must not use allocation
#[allow(unused)]
fn add_memory_items<B>(
    efi_memory_map: &EfiMemoryMap,
    efi_memory_attribute_table: Option<&EfiMemoryAttributesTable>,
    zbi_items: &mut ZbiContainer<B>,
) -> EfiResult<()>
where
    B: SplitByteSliceMut + PartialEq,
{
    generate_efi_memory_attributes_table_item(
        efi_memory_map,
        efi_memory_attribute_table,
        zbi_items,
    )?;

    generate_mem_config_item(efi_memory_map, zbi_items)?;

    Ok(())
}

fn generate_efi_memory_attributes_table_item<'b, B>(
    efi_memory_map: &EfiMemoryMap<'b>,
    efi_memory_attribute_table: Option<&EfiMemoryAttributesTable>,
    zbi_items: &mut ZbiContainer<B>,
) -> EfiResult<()>
where
    B: SplitByteSliceMut + PartialEq,
{
    let payload = zbi_items.get_next_payload().map_err(|_| "Failed to get ZBI payload")?;
    let provided_payload_size = payload.len();
    let (mut header, mut tail) =
        Ref::<&mut [u8], EfiMemoryAttributesTableHeader>::new_from_prefix(payload)
            .ok_or(Error::BadBufferSize)?;

    for efi_memory_desc in efi_memory_map.into_iter() {
        if (efi_memory_desc.attributes & EFI_MEMORY_ATTRIBUTE_EMA_RUNTIME).0 == 0 {
            continue;
        }

        let mut base = efi_memory_desc.physical_start;
        let mut size: u64 = (SafeNum::from(efi_memory_desc.number_of_pages) * PAGE_SIZE)
            .try_into()
            .map_err(Error::from)?;

        // This EMAT entry is either a sub-region or a full copy of the memory map region, per
        // EFI 2.10 4.6.4: "Additionally, every memory region described by a Descriptor in
        // EFI_MEMORY_ATTRIBUTES_TABLE must be a sub-region of, or equal to, a descriptor in the
        // table produced by GetMemoryMap()."
        //
        // This means that we do not have to consider the case where the EMAT entry only overlaps
        // the end of the memory map entry.
        //
        // EMAT items are ordered by physical address, so once we go past |base| we can quit the
        // loop.
        for emat_item in efi_memory_attribute_table
            .into_iter()
            .flatten()
            .skip_while(move |item| item.physical_start < base)
            .take_while(move |item| item.physical_start < base + size)
        {
            if emat_item.physical_start > base {
                // Create a region for [base ... emat_item->PhysicalStart), because that region is
                // not covered by the EMAT.
                let mut generated_item;
                (generated_item, tail) = Ref::<_, EfiMemoryDescriptor>::new_from_prefix(tail)
                    .ok_or(BufferTooSmall(Some(size_of::<EfiMemoryDescriptor>())))?;

                generated_item.physical_start = base;
                generated_item.number_of_pages = (emat_item.physical_start - base) / PAGE_SIZE;
                generated_item.virtual_start = 0;
                generated_item.attributes = EFI_MEMORY_ATTRIBUTE_EMA_RUNTIME;
                generated_item.memory_type = efi_memory_desc.memory_type;

                // Adjust base and size forward.
                size -= emat_item.physical_start - base;
                base = emat_item.physical_start;
            }

            // emat_item.physical_start == base
            // Create a region for [base ... emat_item->NumberOfPages * PAGE_SIZE)
            let mut generated_item;
            (generated_item, tail) = Ref::<_, EfiMemoryDescriptor>::new_from_prefix(tail)
                .ok_or(BufferTooSmall(Some(size_of::<EfiMemoryDescriptor>())))?;
            *generated_item = *emat_item;

            // Adjust base and size forward.
            base += emat_item.number_of_pages * PAGE_SIZE;
            size -= emat_item.number_of_pages * PAGE_SIZE;
        }

        if size != 0 {
            let mut generated_item;
            (generated_item, tail) = Ref::<_, EfiMemoryDescriptor>::new_from_prefix(tail)
                .ok_or(BufferTooSmall(Some(size_of::<EfiMemoryDescriptor>())))?;

            generated_item.physical_start = base;
            generated_item.number_of_pages = size / PAGE_SIZE;
            generated_item.virtual_start = 0;
            generated_item.attributes = EFI_MEMORY_ATTRIBUTE_EMA_RUNTIME;
            generated_item.memory_type = efi_memory_desc.memory_type;
        }
    }

    let used_payload = provided_payload_size - tail.len();
    header.descriptor_size = size_of::<EfiMemoryDescriptor>().try_into().map_err(Error::from)?;
    header.number_of_entries =
        (used_payload / size_of::<EfiMemoryDescriptor>()).try_into().unwrap();
    header.reserved = 0;
    header.version = 1;

    zbi_items
        .create_entry(ZbiType::EfiMemoryAttributesTable, 0, ZbiFlags::default(), used_payload)
        .map_err(|_| "Failed to create EFI_MEMORY_ATTRIBUTES_TABLE ZBI entry")?;

    Ok(())
}

fn generate_mem_config_item<'b, B>(
    efi_memory_map: &EfiMemoryMap<'b>,
    zbi_items: &mut ZbiContainer<B>,
) -> EfiResult<()>
where
    B: SplitByteSliceMut + PartialEq,
{
    let mut tail = zbi_items.get_next_payload().map_err(|_| "Failed to get ZBI payload")?;
    let provided_payload_size = tail.len();

    for efi_desc in efi_memory_map.into_iter() {
        let mut zbi_mem_range: Ref<&mut [u8], zbi_mem_range_t>;
        (zbi_mem_range, tail) =
            Ref::new_from_prefix(tail).ok_or(BufferTooSmall(Some(size_of::<zbi_mem_range_t>())))?;
        zbi_mem_range.paddr = efi_desc.physical_start;
        zbi_mem_range.length = efi_desc.number_of_pages * PAGE_SIZE;
        zbi_mem_range.type_ = efi_to_zbi_mem_range_type(efi_desc.memory_type);
        zbi_mem_range.reserved = 0;
    }

    let used_payload = provided_payload_size - tail.len();
    zbi_items
        .create_entry(ZbiType::MemConfig, 0, ZbiFlags::default(), used_payload)
        .map_err(|_| "Failed to create MEM_CONFIG ZBI entry")?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use ::efi::EFI_MEMORY_ATTRIBUTES_GUID;
    use efi_types::{
        EfiConfigurationTable, EfiMemoryAttribute, EFI_MEMORY_ATTRIBUTE_EMA_XP,
        EFI_MEMORY_TYPE_CONVENTIONAL_MEMORY, EFI_MEMORY_TYPE_RUNTIME_SERVICES_CODE,
        EFI_MEMORY_TYPE_RUNTIME_SERVICES_DATA,
    };
    use zerocopy::{FromBytes, IntoBytes};

    #[test]
    fn test_add_memory_items_without_emat() {
        let mut descriptors = [
            EfiMemoryDescriptor {
                memory_type: EFI_MEMORY_TYPE_CONVENTIONAL_MEMORY,
                padding: 0,
                physical_start: 0x1000,
                virtual_start: 0,
                number_of_pages: 4,
                attributes: EfiMemoryAttribute(0),
            },
            EfiMemoryDescriptor {
                memory_type: EFI_MEMORY_TYPE_RUNTIME_SERVICES_CODE,
                padding: 0,
                physical_start: 0x5000,
                virtual_start: 0,
                number_of_pages: 2,
                attributes: EFI_MEMORY_ATTRIBUTE_EMA_RUNTIME,
            },
        ];
        let efi_memory_map =
            EfiMemoryMap::new(descriptors.as_mut_bytes(), 0, size_of::<EfiMemoryDescriptor>(), 1);

        let mut zbi_buf = [0u8; 1024];
        let mut container = ZbiContainer::new(&mut zbi_buf[..]).unwrap();

        add_memory_items(&efi_memory_map, None, &mut container).unwrap();

        let emat_item = container
            .iter()
            .find(|item| item.header.type_ == ZbiType::EfiMemoryAttributesTable as u32)
            .expect("Synthesized EfiMemoryAttributesTable ZBI item should be present");
        let (emat_header, emat_tail) =
            EfiMemoryAttributesTableHeader::ref_from_prefix(emat_item.payload.as_bytes()).unwrap();
        assert_eq!(emat_header.version, 1);
        assert_eq!(emat_header.number_of_entries, 1);
        assert_eq!(emat_header.descriptor_size, size_of::<EfiMemoryDescriptor>() as u32);
        let emat_entries = <[EfiMemoryDescriptor]>::ref_from_bytes(emat_tail).unwrap();
        assert_eq!(emat_entries.len(), 1);
        assert_eq!(emat_entries[0].physical_start, 0x5000);
        assert_eq!(emat_entries[0].number_of_pages, 2);
        assert_eq!(emat_entries[0].attributes, EFI_MEMORY_ATTRIBUTE_EMA_RUNTIME);
        assert_eq!(emat_entries[0].memory_type, EFI_MEMORY_TYPE_RUNTIME_SERVICES_CODE);

        let mem_config_item = container
            .iter()
            .find(|item| item.header.type_ == ZbiType::MemConfig as u32)
            .expect("MemConfig ZBI item should be present");
        let ranges =
            <[zbi_mem_range_t]>::ref_from_bytes(mem_config_item.payload.as_bytes()).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].paddr, 0x1000);
        assert_eq!(ranges[0].length, 4 * PAGE_SIZE);
        assert_eq!(ranges[1].paddr, 0x5000);
        assert_eq!(ranges[1].length, 2 * PAGE_SIZE);
    }

    #[test]
    fn test_add_memory_items_with_emat() {
        let mut descriptors = [EfiMemoryDescriptor {
            memory_type: EFI_MEMORY_TYPE_RUNTIME_SERVICES_CODE,
            padding: 0,
            physical_start: 0x1000,
            virtual_start: 0,
            number_of_pages: 4,
            attributes: EFI_MEMORY_ATTRIBUTE_EMA_RUNTIME,
        }];
        let efi_memory_map =
            EfiMemoryMap::new(descriptors.as_mut_bytes(), 0, size_of::<EfiMemoryDescriptor>(), 1);

        #[repr(C)]
        struct TestEmat {
            header: EfiMemoryAttributesTableHeader,
            entries: [EfiMemoryDescriptor; 1],
        }

        let raw_emat = TestEmat {
            header: EfiMemoryAttributesTableHeader {
                version: 1,
                number_of_entries: 1,
                descriptor_size: size_of::<EfiMemoryDescriptor>() as u32,
                reserved: 0,
            },
            entries: [EfiMemoryDescriptor {
                memory_type: EFI_MEMORY_TYPE_RUNTIME_SERVICES_CODE,
                padding: 0,
                physical_start: 0x1000,
                virtual_start: 0,
                number_of_pages: 2,
                attributes: EFI_MEMORY_ATTRIBUTE_EMA_RUNTIME,
            }],
        };
        // SAFETY: `raw_emat` begins with a valid `EfiMemoryAttributesTableHeader` followed by
        // `number_of_entries` valid `EfiMemoryDescriptor` items.
        let emat = unsafe {
            EfiMemoryAttributesTable::new(EfiConfigurationTable {
                vendor_guid: EFI_MEMORY_ATTRIBUTES_GUID,
                vendor_table: (&raw_emat as *const TestEmat) as *mut _,
            })
        }
        .unwrap();

        let mut zbi_buf = [0u8; 1024];
        let mut container = ZbiContainer::new(&mut zbi_buf[..]).unwrap();

        add_memory_items(&efi_memory_map, Some(&emat), &mut container).unwrap();

        let emat_item = container
            .iter()
            .find(|item| item.header.type_ == ZbiType::EfiMemoryAttributesTable as u32)
            .expect("EfiMemoryAttributesTable ZBI item should be present");
        let (emat_header, emat_tail) =
            EfiMemoryAttributesTableHeader::ref_from_prefix(emat_item.payload.as_bytes()).unwrap();
        assert_eq!(emat_header.number_of_entries, 2);
        let emat_entries = <[EfiMemoryDescriptor]>::ref_from_bytes(emat_tail).unwrap();
        assert_eq!(emat_entries.len(), 2);
        assert_eq!(emat_entries[0].physical_start, 0x1000);
        assert_eq!(emat_entries[0].number_of_pages, 2);
        assert_eq!(emat_entries[1].physical_start, 0x1000 + 2 * PAGE_SIZE);
        assert_eq!(emat_entries[1].number_of_pages, 2);
        assert!(container.iter().any(|item| item.header.type_ == ZbiType::MemConfig as u32));
    }

    #[test]
    fn test_add_memory_items_with_emat_starting_partway() {
        let mut descriptors = [EfiMemoryDescriptor {
            memory_type: EFI_MEMORY_TYPE_RUNTIME_SERVICES_CODE,
            padding: 0,
            physical_start: 0x1000,
            virtual_start: 0,
            number_of_pages: 4,
            attributes: EFI_MEMORY_ATTRIBUTE_EMA_RUNTIME,
        }];
        let efi_memory_map =
            EfiMemoryMap::new(descriptors.as_mut_bytes(), 0, size_of::<EfiMemoryDescriptor>(), 1);

        #[repr(C)]
        struct TestEmat {
            header: EfiMemoryAttributesTableHeader,
            entries: [EfiMemoryDescriptor; 1],
        }

        let emat_attrs =
            EfiMemoryAttribute(EFI_MEMORY_ATTRIBUTE_EMA_RUNTIME.0 | EFI_MEMORY_ATTRIBUTE_EMA_XP.0);
        let raw_emat = TestEmat {
            header: EfiMemoryAttributesTableHeader {
                version: 1,
                number_of_entries: 1,
                descriptor_size: size_of::<EfiMemoryDescriptor>() as u32,
                reserved: 0,
            },
            entries: [EfiMemoryDescriptor {
                memory_type: EFI_MEMORY_TYPE_RUNTIME_SERVICES_DATA,
                padding: 0,
                physical_start: 0x1000 + PAGE_SIZE,
                virtual_start: 0,
                number_of_pages: 1,
                attributes: emat_attrs,
            }],
        };
        // SAFETY: `raw_emat` begins with a valid `EfiMemoryAttributesTableHeader` followed by
        // `number_of_entries` valid `EfiMemoryDescriptor` items.
        let emat = unsafe {
            EfiMemoryAttributesTable::new(EfiConfigurationTable {
                vendor_guid: EFI_MEMORY_ATTRIBUTES_GUID,
                vendor_table: (&raw_emat as *const TestEmat) as *mut _,
            })
        }
        .unwrap();

        let mut zbi_buf = [0u8; 1024];
        let mut container = ZbiContainer::new(&mut zbi_buf[..]).unwrap();

        add_memory_items(&efi_memory_map, Some(&emat), &mut container).unwrap();

        let emat_item = container
            .iter()
            .find(|item| item.header.type_ == ZbiType::EfiMemoryAttributesTable as u32)
            .expect("EfiMemoryAttributesTable ZBI item should be present");
        let (emat_header, emat_tail) =
            EfiMemoryAttributesTableHeader::ref_from_prefix(emat_item.payload.as_bytes()).unwrap();
        assert_eq!(emat_header.number_of_entries, 3);
        let emat_entries = <[EfiMemoryDescriptor]>::ref_from_bytes(emat_tail).unwrap();
        assert_eq!(emat_entries.len(), 3);

        // Leading gap [0x1000, 0x2000) inherits memory_type from the outer descriptor.
        assert_eq!(emat_entries[0].physical_start, 0x1000);
        assert_eq!(emat_entries[0].number_of_pages, 1);
        assert_eq!(emat_entries[0].attributes, EFI_MEMORY_ATTRIBUTE_EMA_RUNTIME);
        assert_eq!(emat_entries[0].memory_type, EFI_MEMORY_TYPE_RUNTIME_SERVICES_CODE);

        // EMAT entry [0x2000, 0x3000) preserves its attributes and memory_type.
        assert_eq!(emat_entries[1].physical_start, 0x1000 + PAGE_SIZE);
        assert_eq!(emat_entries[1].number_of_pages, 1);
        assert_eq!(emat_entries[1].attributes, emat_attrs);
        assert_eq!(emat_entries[1].memory_type, EFI_MEMORY_TYPE_RUNTIME_SERVICES_DATA);

        // Trailing gap [0x3000, 0x5000) covers the remainder of the outer descriptor.
        assert_eq!(emat_entries[2].physical_start, 0x1000 + 2 * PAGE_SIZE);
        assert_eq!(emat_entries[2].number_of_pages, 2);
        assert_eq!(emat_entries[2].attributes, EFI_MEMORY_ATTRIBUTE_EMA_RUNTIME);
        assert_eq!(emat_entries[2].memory_type, EFI_MEMORY_TYPE_RUNTIME_SERVICES_CODE);
    }
}
