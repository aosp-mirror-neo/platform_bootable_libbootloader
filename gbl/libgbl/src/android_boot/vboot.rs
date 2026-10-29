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

//! Contains APIs for performaing android verified boot.

use crate::{
    gbl_avb::{
        ops::{GblAvbOps, PreloadBufferState, AVB_DIGEST_KEY},
        state::{BootStateColor, KeyValidationStatus, VerificationStatus},
        ArrayMaxParts, LoadPartition, Verification, MAX_PARTITIONS_TO_VERIFY,
    },
    gbl_println,
    ops::{PartitionBuffer, Slot},
    slots::Bootability,
    GblOps, IntegrationError, Result,
};
use abr::SlotIndex;
use avb::{
    slot_verify, HashtreeErrorMode, IoError, SlotVerifyData, SlotVerifyError, SlotVerifyFlags,
    SlotVerifyResult,
};
use bootparams::entry::CommandlineParser;
use core::{ffi::CStr, ops::DerefMut};
use liberror::Error;

/// A container holding partitions for libavb verification
pub struct PartitionsToVerify<'a> {
    partitions: ArrayMaxParts<LoadPartition<'a>>,
    preloaded: ArrayMaxParts<(&'a str, PreloadBufferState<'a>)>,
}

impl<'a> PartitionsToVerify<'a> {
    /// Appends a partition to verify
    pub fn try_push(&mut self, partition: LoadPartition<'a>) -> Result<()> {
        self.partitions
            .try_push(partition)
            .or(Err(Error::TooManyPartitions(MAX_PARTITIONS_TO_VERIFY)))?;
        Ok(())
    }

    /// Appends a preloaded partition buffer.
    pub fn try_push_preloaded(
        &mut self,
        partition: LoadPartition<'a>,
        buf: &'a mut PartitionBuffer<impl DerefMut<Target = [u8]>>,
    ) -> Result<()> {
        let buf = match buf {
            PartitionBuffer::Preloaded(v) => PreloadBufferState::Loaded(&v[..]),
            PartitionBuffer::Designated(v) => PreloadBufferState::ToLoad(&mut v[..]),
        };
        let err = Err(Error::TooManyPartitions(MAX_PARTITIONS_TO_VERIFY));
        self.partitions.try_push(partition).or(err)?;
        self.preloaded.try_push((partition.name_cstr().to_str().unwrap(), buf)).or(err)?;
        Ok(())
    }
}

impl<'a> Default for PartitionsToVerify<'a> {
    fn default() -> Self {
        Self { partitions: ArrayMaxParts::new(), preloaded: ArrayMaxParts::new() }
    }
}

/// Consumes a SlotVerifyResult and returns a SlotVerifyData
pub(crate) fn into_verify_data<'a>(
    res: SlotVerifyResult<'a, SlotVerifyData<'a>>,
) -> Option<SlotVerifyData<'a>> {
    match res {
        Ok(data) => Some(data),
        Err(SlotVerifyError::PublicKeyRejected(v)) => v,
        Err(SlotVerifyError::RollbackIndex(v)) => v,
        Err(SlotVerifyError::Verification(v)) => v,
        _ => None,
    }
}

/// Android verified boot flow.
///
/// All relevant images from disk must be preloaded and provided as `partitions`; in its final
/// state `ops` will provide the necessary callbacks for where the images should go in RAM and
/// which ones are preloaded.
///
/// # Arguments
/// * `ops`: [GblOps] providing device-specific backend.
/// * `slot`: Current slot.
/// * `partitions`: [PartitionsToVerify] providing pre-loaded partitions.
///
/// # Returns
///
/// * On success, returns a tuple of (verification result, BootStateColor, is_unlocked).
/// * Returns an error if verification process failed and boot cannot continue.
pub fn avb_verify_slot<'a, 'b: 'c, 'c>(
    ops: &mut impl GblOps<'a>,
    slot: Option<Slot>,
    partitions: &'c mut PartitionsToVerify<'b>,
) -> Result<(SlotVerifyData<'c>, VerificationStatus, bool)> {
    let slot_index = slot.map(|s| slot_to_index(ops, s)).transpose()?;

    let PartitionsToVerify { partitions, preloaded } = partitions;

    let mut avb_ops = GblAvbOps::new(ops, slot_index, preloaded, false);
    let status = avb_ops.avb_read_device_status()?;

    let mut flags = SlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_NONE;
    if status.is_unlocked {
        flags |= SlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR;
    }
    if status.is_dm_verity_error {
        flags |= SlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_RESTART_CAUSED_BY_HASHTREE_CORRUPTION;
    }

    let mut names: ArrayMaxParts<&'c CStr> = partitions.iter().map(|p| p.name_cstr()).collect();
    let verify_result = slot_verify(
        &mut avb_ops,
        &names,
        slot_index.map(|s| s.into()),
        flags,
        HashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_MANAGED_RESTART_AND_EIO,
    );
    let mut missed_partitions_error: Option<IntegrationError> = None;
    let (color, verify_data) = match verify_result {
        Ok(ref verify_data) => {
            // Reuse `names` to store missed required partitions.
            names.clear();
            // Look for not verified required partitions.
            names.extend(
                partitions
                    .iter()
                    .filter(|p| p.verification() == Verification::Required)
                    .map(|p| p.name_cstr())
                    .filter(|name| {
                        !verify_data.partition_data().iter().any(|v| v.partition_name() == *name)
                    }),
            );
            let have_missed_partitions = !names.is_empty();
            if have_missed_partitions {
                gbl_println!(
                    avb_ops.gbl_ops,
                    "AVB verification passed, but required partitions missed: {:?}.",
                    names
                );
            }

            let (color, data) = match (status.is_unlocked, have_missed_partitions) {
                // Unlocked.
                (true, _) => (BootStateColor::Orange, Some(verify_data)),
                // Have missed partitions.
                (false, true) => {
                    missed_partitions_error =
                        Some(IntegrationError::AvbIoError(IoError::NoSuchPartition));
                    (BootStateColor::Red, None)
                }
                // Locked, all partitions presented.
                (false, false) => {
                    let color = match avb_ops.key_validation_status()? {
                        KeyValidationStatus::ValidCustomKey => BootStateColor::Yellow,
                        _ => BootStateColor::Green,
                    };
                    (color, Some(verify_data))
                }
            };

            gbl_println!(
                avb_ops.gbl_ops,
                "AVB verification passed. Device is unlocked: {}. Missed partitions: {}. \
                Color: {color}.",
                status.is_unlocked,
                names.len(),
            );

            (color, data)
        }
        // Non-fatal error, can continue booting since verify_data is available.
        Err(ref e) if e.verification_data().is_some() && status.is_unlocked => {
            let color = BootStateColor::Orange;

            gbl_println!(
                avb_ops.gbl_ops,
                "AVB verification failed with {e}. Device is unlocked: {} Color: {color}. \
                Continue current boot attempt.",
                status.is_unlocked
            );

            (color, Some(e.verification_data().unwrap()))
        }
        // Fatal error. Cannot boot.
        Err(ref e) => {
            let color = BootStateColor::Red;

            gbl_println!(
                avb_ops.gbl_ops,
                "AVB verification failed with {e}. Device is unlocked: {}. Color: {color}. \
                Cannot continue boot.",
                status.is_unlocked
            );

            (color, None)
        }
    };

    let mut digest = None;
    let mut is_eio = false;
    if let Some(verify_data) = verify_data {
        assert!(
            verify_data.vbmeta_data().first().unwrap().partition_name() == c"vbmeta",
            "GBL requires the vbmeta partition as the top-level verification structure. Please \
            contact the GBL team if you encounter this error."
        );

        is_eio = verify_data.resolved_hashtree_error_mode()
            == HashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_EIO;

        // Take the last AVB digest on the commandline, which will be the one calculated by libavb.
        // There should only be one, but it's not guaranteed, e.g. if a chained vbmeta signing key
        // is compromised, an attacker could create a vbmeta which injects a fake digest as a
        // commandline property descriptor. libavb puts all descriptors first in the commandline
        // then appends its own calculated values last, so always use the last one.
        digest = CommandlineParser::new(verify_data.cmdline().to_str().unwrap())
            .filter_map(|v| v.ok().filter(|v| v.key == AVB_DIGEST_KEY))
            .last()
            .and_then(|v| v.value)
    }

    let verification_status = VerificationStatus { color, is_eio };
    // Allowes FW to handle verification result.
    avb_ops.handle_verification_result(verify_data, verification_status, digest)?;

    if let (Some(verify_data), Some(slot)) = (verify_data, slot) {
        // Update rollback indices if the slot has successfully booted following:
        // https://android.googlesource.com/platform/external/avb/+/android16-release/README.md#updating-stored-rollback-indexes
        if !status.is_unlocked && matches!(slot.bootability, Bootability::Successful(_)) {
            avb_ops.update_rollback_indexes(verify_data)?;
        }
    }

    match color {
        // Check both libavb and missed partitions errors for RED color.
        BootStateColor::Red => Err(verify_result
            .err()
            .map(|e| e.without_verify_data().into())
            .unwrap_or_else(|| missed_partitions_error.unwrap())),
        _ => {
            Ok((into_verify_data(verify_result).unwrap(), verification_status, status.is_unlocked))
        }
    }
}

/// Android fake verified boot flow.
///
/// Used only by the DEV GBL to boot the device even if a critical AVB error is encountered,
/// by using a custom precompiled vbmeta image to work around on-device issues.
#[cfg(feature = "gbl_dev")]
pub fn avb_fake_verify_slot<'a, 'b: 'c, 'c>(
    ops: &mut impl GblOps<'a>,
    slot: Option<Slot>,
    partitions: &'c mut PartitionsToVerify<'b>,
) -> Result<(SlotVerifyData<'c>, VerificationStatus, bool)> {
    use crate::gbl_avb::ops::custom_vbmeta::CustomVbmetaAvbOps;
    use crate::slots::slotted_part;

    let slot_index = slot.map(|s| slot_to_index(ops, s)).transpose()?;

    let PartitionsToVerify { partitions, preloaded } = partitions;

    let mut names: ArrayMaxParts<&'c CStr> = ArrayMaxParts::new();
    for partition in partitions.iter() {
        // `libavb` fails with IO if any partition is missed when verification is disabled,
        // so filter out missed partitions.
        if ops.partition_size(&slotted_part(partition.name(), slot.map(|s| s.suffix)))?.is_some() {
            names.push(partition.name_cstr());
        }
    }

    let mut avb_ops = GblAvbOps::new(ops, slot_index, preloaded, false);
    let status = avb_ops.avb_read_device_status()?;

    // Uses pre-compiled fake vbmeta image with disabled verification, so rely on libavb to
    // load the partitions only.
    let custom_vbmeta = include_bytes!("../../testdata/android/vbmeta_disabled.img");
    // Custom vbmeta partition has `0` rollback index value.
    let custom_vbmeta_rollbacks = [(0, 0)];
    let mut custom_avb_ops = CustomVbmetaAvbOps {
        ops: &mut avb_ops,
        vbmeta: custom_vbmeta,
        rollback_indexes: &custom_vbmeta_rollbacks,
    };
    match slot_verify(
        &mut custom_avb_ops,
        &names,
        slot_index.map(|s| s.into()),
        SlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
        HashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_RESTART,
    ) {
        // Fatal error. Cannot boot.
        Err(ref e) if e.verification_data().is_none() => {
            gbl_println!(
                avb_ops.gbl_ops,
                "Fake AVB verification failed with {e}. Color: {}. Cannot continue boot.",
                BootStateColor::Red,
            );
            Err(e.without_verify_data().into())
        }
        r => {
            let color = BootStateColor::Orange;
            gbl_println!(
                avb_ops.gbl_ops,
                "Fake AVB verification done. Color: {}. Continue current boot attempt.",
                color,
            );
            Ok((
                into_verify_data(r).unwrap(),
                VerificationStatus { color, is_eio: false },
                status.is_unlocked,
            ))
        }
    }
}

/// Helper to convert a `Slot` to a `SlotIndex`, logging and mapping errors.
fn slot_to_index<'a>(
    ops: &mut impl GblOps<'a>,
    slot: Slot,
) -> core::result::Result<SlotIndex, Error> {
    SlotIndex::try_from(slot.suffix.as_char())
        .inspect_err(|_| gbl_println!(ops, "AVB: Invalid slot: {}", slot.suffix.as_char()))
        .map_err(|_| Error::InvalidInput)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        android_boot::tests::{
            EXPECTED_AVB_PROPS, TEST_ROLLBACK_INDEX, TEST_ROLLBACK_INDEX_LOCATION,
        },
        gbl_avb::{
            AvbDeviceStatus, AvbPartition, AvbProperty, Critical, Fdr, SpecializedPartition,
        },
        ops::{
            test::{slot, slot_successful, FakeGblOps, FakeGblOpsStorage},
            Slot,
        },
        tests::{read_test_data, read_test_data_as_str},
        IntegrationError::AvbIoError,
    };
    use avb::{IoError, SlotVerifyError};
    use libutils::cstr_buffer;
    use std::{
        collections::{HashMap, HashSet},
        ffi::CStr,
        string::String,
    };

    /// FW rollback index before verification.
    const TEST_ROLLBACK_INDEX_BEFORE_VERIFY: u64 = TEST_ROLLBACK_INDEX - 1;

    /// Helper for testing avb_verify_slot
    fn test_avb_verify_slot<'a>(
        partitions: &[(&CStr, &str)],
        partitions_to_verify: &mut PartitionsToVerify<'a>,
        device_status: std::result::Result<AvbDeviceStatus, IoError>,
        key_validation_status: KeyValidationStatus,
        fw_rollback_result: std::result::Result<u64, IoError>,
        slot: Slot,
        expected_updated_fw_rollback: Option<u64>,
        expected_reported_status: Option<VerificationStatus>,
        expected_reported_partitions: Option<&[&str]>,
    ) -> Result<()> {
        let mut storage = FakeGblOpsStorage::default();
        for (part, file) in partitions {
            storage.add_raw_device(part, read_test_data(file));
        }
        let mut ops = FakeGblOps::new(&storage);
        match device_status {
            Ok(ref device_status) => *ops.avb_device_status = device_status.clone(),
            Err(ref e) => ops.avb_device_status.set_err(e.clone()),
        };
        ops.avb_ops.rollbacks = HashMap::from([(TEST_ROLLBACK_INDEX_LOCATION, fw_rollback_result)]);
        let mut out_status = None;
        let mut out_properties: Vec<(String, String)> = Vec::new();
        let mut out_partitions: HashSet<String> = HashSet::new();
        let mut handler = |status,
                           _: Option<&CStr>,
                           properties: Option<Vec<AvbProperty<'_>>>,
                           partitions: Option<Vec<AvbPartition<'_>>>| {
            out_status = Some(status);
            if let Some(properties) = properties {
                out_properties.extend(properties.iter().map(|p| {
                    (
                        p.key.to_str().unwrap().to_owned(),
                        CStr::from_bytes_with_nul(p.value_with_nul)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_owned(),
                    )
                }))
            }
            if let Some(partitions) = partitions {
                out_partitions
                    .extend(partitions.iter().map(|p| p.name.to_str().unwrap().to_owned()));
            }
            Ok(())
        };
        ops.avb_handle_verification_result = Some(&mut handler);
        ops.avb_key_validation_status = Some(Ok(key_validation_status));
        let res = avb_verify_slot(&mut ops, Some(slot), partitions_to_verify);
        if let Some(expected_updated_fw_rollback) = expected_updated_fw_rollback {
            let updated_rollback_index =
                ops.avb_ops.rollbacks.get(&TEST_ROLLBACK_INDEX_LOCATION).unwrap();
            assert_eq!(updated_rollback_index.as_ref().unwrap(), &expected_updated_fw_rollback);
        }
        assert_eq!(out_status, expected_reported_status);
        let (_, status, unlocked) = res?;
        if let Some(expected_reported_partitions) = expected_reported_partitions {
            assert_eq!(
                out_partitions,
                expected_reported_partitions.iter().map(|p| p.to_string()).collect()
            );
        }
        assert_eq!(
            out_properties.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect::<Vec<_>>(),
            EXPECTED_AVB_PROPS
        );
        assert_eq!(out_status.unwrap(), status);
        if let Ok(device_status) = device_status {
            assert_eq!(unlocked, device_status.is_unlocked);
        }
        Ok(())
    }

    #[test]
    fn test_avb_verify_slot_success() {
        let fw = SpecializedPartition {
            name_buffer: cstr_buffer("fw"),
            verification: Some(Verification::Required),
            fdr: Fdr::No,
            critical: Critical::No,
        };
        let mut partitions_to_verify = PartitionsToVerify::default();
        partitions_to_verify.try_push(LoadPartition::Boot).unwrap();
        partitions_to_verify.try_push(LoadPartition::InitBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::VendorBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::PlatformSpecific(&fw)).unwrap();
        let partitions_data = [
            (c"boot_a", "android/boot_no_ramdisk_v4_a.img"),
            (c"init_boot_a", "android/init_boot_a.img"),
            (c"vendor_boot_a", "android/vendor_boot_v4_a.img"),
            (c"fw_a", "android/fw_a.img"),
            (c"vbmeta_a", "android/vbmeta_v4_v4_init_boot_a.img"),
        ];

        assert_eq!(
            test_avb_verify_slot(
                &partitions_data,
                &mut partitions_to_verify,
                Ok(AvbDeviceStatus {
                    is_unlocked: false,
                    is_unlocked_critical: false,
                    is_dm_verity_error: false,
                    is_unlockable: false
                }),
                KeyValidationStatus::Valid,
                // FW rollback index result.
                Ok(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                // Slot has been already successfully booted before.
                slot_successful('a'),
                // Rollback index is expected to be updated.
                Some(TEST_ROLLBACK_INDEX),
                Some(VerificationStatus { color: BootStateColor::Green, is_eio: false }),
                Some(&["boot", "init_boot", "vendor_boot", "fw"])
            ),
            Ok(()),
        );
    }

    #[test]
    fn test_avb_verify_slot_success_required_partition_missed() {
        let not_presented = SpecializedPartition {
            name_buffer: cstr_buffer("not_presented"),
            verification: Some(Verification::Required),
            fdr: Fdr::No,
            critical: Critical::No,
        };
        let mut partitions_to_verify = PartitionsToVerify::default();
        partitions_to_verify.try_push(LoadPartition::Boot).unwrap();
        partitions_to_verify.try_push(LoadPartition::InitBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::VendorBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::PlatformSpecific(&not_presented)).unwrap();
        let partitions_data = [
            (c"boot_a", "android/boot_no_ramdisk_v4_a.img"),
            (c"init_boot_a", "android/init_boot_a.img"),
            (c"vendor_boot_a", "android/vendor_boot_v4_a.img"),
            (c"vbmeta_a", "android/vbmeta_v4_v4_init_boot_a.img"),
        ];
        assert_eq!(
            test_avb_verify_slot(
                &partitions_data,
                &mut partitions_to_verify,
                Ok(AvbDeviceStatus {
                    is_unlocked: false,
                    is_unlocked_critical: false,
                    is_dm_verity_error: false,
                    is_unlockable: false
                }),
                KeyValidationStatus::Valid,
                // FW rollback index result.
                Ok(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                // Slot has been already successfully booted before.
                slot_successful('a'),
                // Partition isn't found, slot cannot be booted. Index hasn't been updated.
                Some(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                Some(VerificationStatus { color: BootStateColor::Red, is_eio: false }),
                None,
            ),
            Err(IoError::NoSuchPartition.into()),
        );
    }

    #[test]
    fn test_avb_verify_slot_success_optional_partition_missed() {
        let not_presented = SpecializedPartition {
            name_buffer: cstr_buffer("not_presented"),
            verification: Some(Verification::IfExists),
            fdr: Fdr::No,
            critical: Critical::No,
        };
        let mut partitions_to_verify = PartitionsToVerify::default();
        partitions_to_verify.try_push(LoadPartition::Boot).unwrap();
        partitions_to_verify.try_push(LoadPartition::InitBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::VendorBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::PlatformSpecific(&not_presented)).unwrap();
        let partitions_data = [
            (c"boot_a", "android/boot_no_ramdisk_v4_a.img"),
            (c"init_boot_a", "android/init_boot_a.img"),
            (c"vendor_boot_a", "android/vendor_boot_v4_a.img"),
            (c"vbmeta_a", "android/vbmeta_v4_v4_init_boot_a.img"),
        ];
        assert_eq!(
            test_avb_verify_slot(
                &partitions_data,
                &mut partitions_to_verify,
                Ok(AvbDeviceStatus {
                    is_unlocked: false,
                    is_unlocked_critical: false,
                    is_dm_verity_error: false,
                    is_unlockable: false
                }),
                KeyValidationStatus::Valid,
                // FW rollback index result.
                Ok(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                // Slot has been already successfully booted before.
                slot_successful('a'),
                // Rollback index is expected to be updated.
                Some(TEST_ROLLBACK_INDEX),
                Some(VerificationStatus { color: BootStateColor::Green, is_eio: false }),
                Some(&["boot", "init_boot", "vendor_boot"])
            ),
            Ok(()),
        );
    }

    #[test]
    fn test_avb_verify_slot_success_custom_key() {
        let mut partitions_to_verify = PartitionsToVerify::default();
        partitions_to_verify.try_push(LoadPartition::Boot).unwrap();
        partitions_to_verify.try_push(LoadPartition::InitBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::VendorBoot).unwrap();
        let partitions_data = [
            (c"boot_a", "android/boot_no_ramdisk_v4_a.img"),
            (c"init_boot_a", "android/init_boot_a.img"),
            (c"vendor_boot_a", "android/vendor_boot_v4_a.img"),
            (c"vbmeta_a", "android/vbmeta_v4_v4_init_boot_a.img"),
        ];

        assert_eq!(
            test_avb_verify_slot(
                &partitions_data,
                &mut partitions_to_verify,
                Ok(AvbDeviceStatus {
                    is_unlocked: false,
                    is_unlocked_critical: false,
                    is_dm_verity_error: false,
                    is_unlockable: false
                }),
                KeyValidationStatus::ValidCustomKey,
                // FW rollback index result.
                Ok(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                // Slot has been already successfully booted before.
                slot_successful('a'),
                // Rollback index is expected to be updated.
                Some(TEST_ROLLBACK_INDEX),
                Some(VerificationStatus { color: BootStateColor::Yellow, is_eio: false }),
                None,
            ),
            Ok(()),
        );
    }

    #[test]
    fn test_avb_verify_slot_from_preloaded_success() {
        let mut boot = read_test_data("android/boot_no_ramdisk_v4_a.img");
        let mut init_boot = read_test_data("android/init_boot_a.img");
        let mut vendor_boot = read_test_data("android/vendor_boot_v4_a.img");

        let mut preloaded = [
            (LoadPartition::Boot, PartitionBuffer::Preloaded(&mut boot[..])),
            (LoadPartition::InitBoot, PartitionBuffer::Preloaded(&mut init_boot[..])),
            (LoadPartition::VendorBoot, PartitionBuffer::Preloaded(&mut vendor_boot[..])),
        ];
        let mut partitions_to_verify = PartitionsToVerify::default();
        for (p, v) in &mut preloaded {
            partitions_to_verify.try_push_preloaded(*p, v).unwrap();
        }
        let partitions_data = [
            // Required images aren't presented. Have to rely on preloaded.
            (c"vbmeta_a", "android/vbmeta_v4_v4_init_boot_a.img"),
        ];
        assert_eq!(
            test_avb_verify_slot(
                &partitions_data,
                &mut partitions_to_verify,
                Ok(AvbDeviceStatus {
                    is_unlocked: false,
                    is_unlocked_critical: false,
                    is_dm_verity_error: false,
                    is_unlockable: false
                }),
                KeyValidationStatus::Valid,
                // FW rollback index result.
                Ok(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                slot('a'),
                // First boot for slot. Index hasn't been updated.
                Some(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                Some(VerificationStatus { color: BootStateColor::Green, is_eio: false }),
                None,
            ),
            Ok(()),
        );
    }

    #[test]
    fn test_avb_verify_slot_success_unlocked() {
        let fw = SpecializedPartition {
            name_buffer: cstr_buffer("fw"),
            verification: Some(Verification::Required),
            fdr: Fdr::No,
            critical: Critical::No,
        };
        let mut partitions_to_verify = PartitionsToVerify::default();
        partitions_to_verify.try_push(LoadPartition::Boot).unwrap();
        partitions_to_verify.try_push(LoadPartition::InitBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::VendorBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::PlatformSpecific(&fw)).unwrap();
        let partitions_data = [
            (c"boot_a", "android/boot_no_ramdisk_v4_a.img"),
            (c"init_boot_a", "android/init_boot_a.img"),
            (c"vendor_boot_a", "android/vendor_boot_v4_a.img"),
            (c"fw_a", "android/fw_a.img"),
            (c"vbmeta_a", "android/vbmeta_v4_v4_init_boot_a.img"),
        ];
        assert_eq!(
            test_avb_verify_slot(
                &partitions_data,
                &mut partitions_to_verify,
                Ok(AvbDeviceStatus {
                    is_unlocked: true,
                    is_unlocked_critical: true,
                    is_dm_verity_error: false,
                    is_unlockable: true
                }),
                KeyValidationStatus::Valid,
                // FW rollback index result.
                Ok(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                slot_successful('a'),
                // Device is unlocked. Index hasn't been updated.
                Some(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                Some(VerificationStatus { color: BootStateColor::Orange, is_eio: false }),
                Some(&["boot", "init_boot", "vendor_boot", "fw"]),
            ),
            Ok(()),
        );
    }

    #[test]
    fn test_avb_verify_slot_success_unlocked_required_partition_missed() {
        let fw = SpecializedPartition {
            name_buffer: cstr_buffer("fw"),
            verification: Some(Verification::Required),
            fdr: Fdr::No,
            critical: Critical::No,
        };
        let not_presented = SpecializedPartition {
            name_buffer: cstr_buffer("not_presented"),
            verification: Some(Verification::Required),
            fdr: Fdr::No,
            critical: Critical::No,
        };
        let mut partitions_to_verify = PartitionsToVerify::default();
        partitions_to_verify.try_push(LoadPartition::Boot).unwrap();
        partitions_to_verify.try_push(LoadPartition::InitBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::VendorBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::PlatformSpecific(&fw)).unwrap();
        partitions_to_verify.try_push(LoadPartition::PlatformSpecific(&not_presented)).unwrap();
        let partitions_data = [
            (c"boot_a", "android/boot_no_ramdisk_v4_a.img"),
            (c"init_boot_a", "android/init_boot_a.img"),
            (c"vendor_boot_a", "android/vendor_boot_v4_a.img"),
            (c"fw_a", "android/fw_a.img"),
            (c"vbmeta_a", "android/vbmeta_v4_v4_init_boot_a.img"),
        ];
        assert_eq!(
            test_avb_verify_slot(
                &partitions_data,
                &mut partitions_to_verify,
                Ok(AvbDeviceStatus {
                    is_unlocked: true,
                    is_unlocked_critical: true,
                    is_dm_verity_error: false,
                    is_unlockable: true
                }),
                KeyValidationStatus::Valid,
                // FW rollback index result.
                Ok(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                slot_successful('a'),
                // Device is unlocked. Index hasn't been updated.
                Some(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                Some(VerificationStatus { color: BootStateColor::Orange, is_eio: false }),
                Some(&["boot", "init_boot", "vendor_boot", "fw"]),
            ),
            Ok(()),
        );
    }

    #[test]
    fn test_avb_verify_slot_verification_failed_unlocked() {
        let mut partitions_to_verify = PartitionsToVerify::default();
        partitions_to_verify.try_push(LoadPartition::Boot).unwrap();
        partitions_to_verify.try_push(LoadPartition::InitBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::VendorBoot).unwrap();
        let partitions_data = [
            // Wrong boot image, expect verification to fail.
            (c"boot_a", "android/boot_v0_a.img"),
            (c"init_boot_a", "android/init_boot_a.img"),
            (c"vendor_boot_a", "android/vendor_boot_v4_a.img"),
            (c"vbmeta_a", "android/vbmeta_v4_v4_init_boot_a.img"),
        ];
        assert_eq!(
            test_avb_verify_slot(
                &partitions_data,
                &mut partitions_to_verify,
                Ok(AvbDeviceStatus {
                    is_unlocked: true,
                    is_unlocked_critical: true,
                    is_dm_verity_error: false,
                    is_unlockable: false
                }),
                KeyValidationStatus::Valid,
                // FW rollback index result.
                Ok(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                slot_successful('a'),
                // Device is unlocked. Index hasn't been updated.
                Some(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                Some(VerificationStatus { color: BootStateColor::Orange, is_eio: false }),
                None,
            ),
            // Device is unlocked, so can continue boot.
            Ok(()),
        );
    }

    #[test]
    fn test_avb_verify_slot_verification_fatal_failed_unlocked() {
        let mut partitions_to_verify = PartitionsToVerify::default();
        partitions_to_verify.try_push(LoadPartition::Boot).unwrap();
        partitions_to_verify.try_push(LoadPartition::InitBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::VendorBoot).unwrap();
        let partitions_data = [
            (c"boot_a", "android/boot_no_ramdisk_v4_a.img"),
            (c"init_boot_a", "android/init_boot_a.img"),
            (c"vendor_boot_a", "android/vendor_boot_v4_a.img"),
            (c"vbmeta_a", "android/vbmeta_v4_v4_init_boot_a.img"),
        ];
        assert_eq!(
            test_avb_verify_slot(
                &partitions_data,
                &mut partitions_to_verify,
                Ok(AvbDeviceStatus {
                    is_unlocked: true,
                    is_unlocked_critical: true,
                    is_dm_verity_error: false,
                    is_unlockable: false
                }),
                KeyValidationStatus::Valid,
                // FW rollback index result.
                Err(IoError::NoSuchValue),
                slot_successful('a'),
                // Getting FW rollback index is failed. Index cannot be updated and checked.
                None,
                Some(VerificationStatus { color: BootStateColor::Red, is_eio: false }),
                None,
            ),
            Err(SlotVerifyError::Io.into())
        )
    }

    #[test]
    fn test_avb_verify_slot_verification_failed_locked() {
        let mut partitions_to_verify = PartitionsToVerify::default();
        partitions_to_verify.try_push(LoadPartition::Boot).unwrap();
        partitions_to_verify.try_push(LoadPartition::InitBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::VendorBoot).unwrap();
        let partitions_data = [
            // Wrong boot image, expect verification to fail.
            (c"boot_a", "android/boot_v0_a.img"),
            (c"init_boot_a", "android/init_boot_a.img"),
            (c"vendor_boot_a", "android/vendor_boot_v4_a.img"),
            (c"vbmeta_a", "android/vbmeta_v4_v4_init_boot_a.img"),
        ];

        assert_eq!(
            test_avb_verify_slot(
                &partitions_data,
                &mut partitions_to_verify,
                Ok(AvbDeviceStatus {
                    is_unlocked: false,
                    is_unlocked_critical: false,
                    is_dm_verity_error: false,
                    is_unlockable: false
                }),
                KeyValidationStatus::Valid,
                // FW rollback index result.
                Ok(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                slot_successful('a'),
                // Verification failed. Index hasn't been updated.
                Some(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                Some(VerificationStatus { color: BootStateColor::Red, is_eio: false }),
                None,
            ),
            // Cannot continue boot.
            Err(SlotVerifyError::Verification(None).into()),
        );
    }

    #[test]
    fn test_avb_verify_slot_success_eio_mode() {
        let mut partitions_to_verify = PartitionsToVerify::default();
        partitions_to_verify.try_push(LoadPartition::Boot).unwrap();
        partitions_to_verify.try_push(LoadPartition::InitBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::VendorBoot).unwrap();
        let partitions_data = [
            (c"boot_a", "android/boot_no_ramdisk_v4_a.img"),
            (c"init_boot_a", "android/init_boot_a.img"),
            (c"vendor_boot_a", "android/vendor_boot_v4_a.img"),
            (c"vbmeta_a", "android/vbmeta_v4_v4_init_boot_a.img"),
        ];

        assert_eq!(
            test_avb_verify_slot(
                &partitions_data,
                &mut partitions_to_verify,
                Ok(AvbDeviceStatus {
                    is_unlocked: false,
                    is_unlocked_critical: false,
                    is_dm_verity_error: true,
                    is_unlockable: false
                }),
                KeyValidationStatus::Valid,
                // FW rollback index result.
                Ok(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                slot_successful('a'),
                // Rollback index is expected to be updated.
                Some(TEST_ROLLBACK_INDEX),
                // Expected verification status.
                Some(VerificationStatus { color: BootStateColor::Green, is_eio: true }),
                None,
            ),
            Ok(()),
        );
    }

    #[test]
    fn test_avb_verify_slot_verification_failed_obtain_device_status() {
        let mut partitions_to_verify = PartitionsToVerify::default();

        assert_eq!(
            test_avb_verify_slot(
                &[],
                &mut partitions_to_verify,
                // Device status
                Err(IoError::NoSuchValue),
                KeyValidationStatus::Valid,
                // FW rollback index result.
                Ok(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                slot_successful('a'),
                // Verification isn't started. Index hasn't been updated.
                Some(TEST_ROLLBACK_INDEX_BEFORE_VERIFY),
                // Expected verification status.
                None,
                None,
            ),
            // Cannot continue boot.
            Err(AvbIoError(IoError::NoSuchValue)),
        );
    }

    #[cfg(feature = "gbl_dev")]
    #[test]
    fn test_avb_verify_slot_avb_not_implemented_dev_gbl() {
        let mut partitions_to_verify = PartitionsToVerify::default();
        partitions_to_verify.try_push(LoadPartition::Boot).unwrap();
        partitions_to_verify.try_push(LoadPartition::InitBoot).unwrap();
        partitions_to_verify.try_push(LoadPartition::VendorBoot).unwrap();
        let partitions_data = [
            (c"boot_a", "android/boot_no_ramdisk_v4_a.img"),
            (c"init_boot_a", "android/init_boot_a.img"),
            (c"vendor_boot_a", "android/vendor_boot_v4_a.img"),
            (c"vbmeta_a", "android/vbmeta_v4_v4_init_boot_a.img"),
        ];
        assert_eq!(
            test_avb_verify_slot(
                &partitions_data,
                &mut partitions_to_verify,
                // Get device status isn't implemented.
                Err(IoError::NotImplemented),
                KeyValidationStatus::Valid,
                // Read FW rollback index isn't implemented.
                Err(IoError::NotImplemented),
                slot_successful('a'),
                // Getting FW rollback index is failed. Index cannot be updated and checked.
                None,
                Some(VerificationStatus { color: BootStateColor::Orange, is_eio: false }),
                None,
            ),
            Ok(()),
        );
    }

    /// This test uses a "malicious" vbmeta which tries to inject a fake vbmeta digest to the
    /// commandline, and ensures that we ignore it and use the real digest.
    #[test]
    fn test_avb_verify_slot_success_spoof_digest() {
        let mut partitions_to_verify = PartitionsToVerify::default();
        let partitions_data = [(c"vbmeta_a", "android/vbmeta_spoof_a.img")];
        let real_vbmeta_digest = read_test_data_as_str("android/vbmeta_spoof_a.digest.txt");

        let mut storage = FakeGblOpsStorage::default();
        for (part, file) in &partitions_data {
            storage.add_raw_device(part, read_test_data(file));
        }
        let mut ops = FakeGblOps::new(&storage);
        ops.avb_ops.rollbacks =
            HashMap::from([(TEST_ROLLBACK_INDEX_LOCATION, Ok(TEST_ROLLBACK_INDEX_BEFORE_VERIFY))]);

        // Set up a `handle_verification_result()` handler to save the state for analysis.
        let mut out_status = None;
        let mut out_digest = None;
        let mut handler = |status,
                           digest: Option<&CStr>,
                           _: Option<Vec<AvbProperty<'_>>>,
                           _: Option<Vec<AvbPartition<'_>>>| {
            out_status = Some(status);
            out_digest = digest.map(|d| d.to_str().unwrap().to_owned());
            Ok(())
        };
        ops.avb_handle_verification_result = Some(&mut handler);
        ops.avb_key_validation_status = Some(Ok(KeyValidationStatus::Valid));

        let res = avb_verify_slot(&mut ops, Some(slot_successful('a')), &mut partitions_to_verify);
        assert!(res.is_ok());

        assert_eq!(
            out_status,
            Some(VerificationStatus { color: BootStateColor::Green, is_eio: false })
        );

        // Verify that both digests are present in the command line, the spoofed one we injected
        // from vbmeta and the real one calculated by libavb.
        //
        // It's possible in the future we might want to change behavior e.g. to error out if we
        // detect duplicate vbmeta digests in the commandline, but for now we allow it.
        let (verify_data, _, _) = res.unwrap();
        let cmdline = verify_data.cmdline().to_str().unwrap();
        assert!(cmdline.contains("androidboot.vbmeta.digest=spoofed_digest"));
        assert!(cmdline.contains(&format!("androidboot.vbmeta.digest={}", real_vbmeta_digest)));

        // The digest passed to `handle_verification_result()` should be the real one.
        assert_eq!(out_digest, Some(real_vbmeta_digest.to_owned()));
    }
}
