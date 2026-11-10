// Copyright 2025, The Android Open Source Project
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

//! Helpers for manipulating the bootloader_message (BCB), Virtual A/B and GSI messages in `misc`.

use crate::{partition::check_part_unique, GblOps};
use gbl_async::yield_now;
use liberror::{Error, Result};
use zerocopy::{error::SizeError, FromBytes, FromZeros, IntoBytes};

pub use misc::{
    AndroidBootMode, BootloaderMessage, MergeStatus, MiscGsiMessage, MiscGsiStatus,
    MiscVirtualAbMessage, SYSTEM_SPACE_OFFSET_IN_MISC,
};

/// The partition that contains the bootloader_message (BCB), Virtual A/B and GSI messages.
pub(crate) const MISC_PARTITION: &str = "misc";

/// Reads the bootloader_message (BCB) from `misc` partition into a buffer.
///
/// # Returns
/// * Ok(&mut BootloaderMessage) a mutable reference to the BootloaderMessage instance.
/// * Err(BufferTooSmall(_)) if buffer is too small.
/// * Err(_) if IO error.
pub fn read_bootloader_message_to<'a, 'b>(
    ops: &mut impl GblOps<'a>,
    buffer: &'b mut [u8],
) -> Result<&'b mut BootloaderMessage> {
    let (bcb, _) = BootloaderMessage::mut_from_prefix(buffer).map_err(|e| {
        // Converting to `SizeError` statically ensures that no other error is possible.
        let SizeError { .. } = e.into();
        Error::BufferTooSmall(Some(BootloaderMessage::SIZE_BYTES))
    })?;
    bcb.zero();
    ops.read_from_partition_sync(MISC_PARTITION, 0, bcb.as_mut_bytes())?;
    Ok(bcb)
}

/// Writes the bootloader_message (BCB) to `misc` partition.
pub fn write_bootloader_message<'a>(
    ops: &mut impl GblOps<'a>,
    bcb: &mut BootloaderMessage,
) -> Result<()> {
    ops.write_to_partition_sync(MISC_PARTITION, 0, bcb.as_mut_bytes())
}

/// Reads and validates the `MiscVirtualAbMessage` from the `misc` partition.
///
/// # Returns
///
/// * `Ok(MiscVirtualAbMessage)` if a valid Virtual A/B message is present in `misc`.
/// * `Err(Error::Unsupported)` if the target OS is Fuchsia.
/// * `Err(Error::PartitionNotFound)` if the `misc` partition does not exist.
/// * `Err(Error::OutOfRange)` if the `misc` partition is too small to hold system space.
/// * `Err(Error::InvalidInput)` if the Virtual A/B message header is uninitialized or invalid.
pub async fn read_virtual_ab_message<'a>(
    ops: &mut impl GblOps<'a>,
) -> Result<MiscVirtualAbMessage> {
    #[cfg(feature = "fuchsia")]
    if ops.expected_os_is_fuchsia()? {
        return Err(Error::Unsupported);
    }
    let devs = ops.disks();
    let (blk_idx, _) = check_part_unique(devs, MISC_PARTITION)?;
    let io = loop {
        match devs[blk_idx].partition_io(Some(MISC_PARTITION)) {
            Err(Error::NotReady) => yield_now().await,
            res => break res?,
        }
    };
    let mut buf = [0u8; MiscVirtualAbMessage::SIZE_BYTES];
    let offset = u64::try_from(SYSTEM_SPACE_OFFSET_IN_MISC)?;
    io.read(offset, &mut buf[..]).await?;
    MiscVirtualAbMessage::try_from(&buf[..])
}

/// Writes a `MiscVirtualAbMessage` to the `misc` partition.
pub async fn write_virtual_ab_message<'a>(
    ops: &mut impl GblOps<'a>,
    msg: MiscVirtualAbMessage,
) -> Result<()> {
    #[cfg(feature = "fuchsia")]
    if ops.expected_os_is_fuchsia()? {
        return Err(Error::Unsupported);
    }
    let devs = ops.disks();
    let (blk_idx, _) = check_part_unique(devs, MISC_PARTITION)?;
    let io = loop {
        match devs[blk_idx].partition_io(Some(MISC_PARTITION)) {
            Err(Error::NotReady) => yield_now().await,
            res => break res?,
        }
    };
    let mut buf: [u8; MiscVirtualAbMessage::SIZE_BYTES] = msg.into();
    let offset = u64::try_from(SYSTEM_SPACE_OFFSET_IN_MISC)?;
    io.write(offset, &mut buf[..]).await?;
    io.flush().await
}

/// Reads and validates the `misc_gsi_message` from the `misc` partition.
///
/// Note: This performs synchronous partition I/O (`block_on`). Callers in async contexts (such as
/// fastboot) must ensure any background disk tasks are synced first to avoid blocking on busy disk
/// resources.
///
/// # Returns
///
/// * `Ok(MiscGsiMessage)` if a valid GSI message is present in `misc`.
/// * `Err(Error::BadMagic)` or `Err(Error::UnsupportedVersion)` if the GSI message header is
///   uninitialized or invalid.
/// * `Err(_)` on I/O error, e.g. `Err(Error::PartitionNotFound)` if the `misc` partition does not
///   exist.
pub fn read_misc_gsi_message<'a>(ops: &mut impl GblOps<'a>) -> Result<MiscGsiMessage> {
    let mut buf = [0u8; MiscGsiMessage::SIZE_BYTES];
    ops.read_from_partition_sync(MISC_PARTITION, MiscGsiMessage::OFFSET_IN_MISC, &mut buf[..])?;
    MiscGsiMessage::try_from(&buf[..])
}

/// Writes the `misc_gsi_message` to the `misc` partition.
///
/// Note: This performs synchronous partition I/O (`block_on`). Callers in async contexts (such as
/// fastboot) must ensure any background disk tasks are synced first to avoid blocking on busy disk
/// resources.
pub fn write_misc_gsi_message<'a>(ops: &mut impl GblOps<'a>, gsi: MiscGsiMessage) -> Result<()> {
    let mut buf: [u8; MiscGsiMessage::SIZE_BYTES] = gsi.into();
    ops.write_to_partition_sync(MISC_PARTITION, MiscGsiMessage::OFFSET_IN_MISC, &mut buf[..])
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::{
        constants::KiB,
        ops::test::{FakeGblOps, FakeGblOpsStorage},
    };
    use gbl_async::block_on;

    pub(crate) use misc::test_utils::RawMiscGsiMessage;

    /// Reads the bootloader_message (BCB) from `misc` partition.
    pub(crate) fn read_bootloader_message<'a>(
        ops: &mut impl GblOps<'a>,
    ) -> Result<BootloaderMessage> {
        let mut bcb = BootloaderMessage::new_zeroed();
        read_bootloader_message_to(ops, bcb.as_mut_bytes())?;
        Ok(bcb)
    }

    #[test]
    fn test_read_bootloader_message_to() {
        let mut storage = FakeGblOpsStorage::default();
        storage.add_raw_device(c"misc", [0u8; KiB!(4)]);
        let mut ops = FakeGblOps::new(&storage);
        ops.write_to_partition_sync(MISC_PARTITION, 0, &mut b"bootonce-bootloader".to_vec())
            .unwrap();

        let bcb = read_bootloader_message(&mut ops).unwrap();

        assert_eq!(bcb.boot_mode(), Ok(AndroidBootMode::BootloaderBootOnce));
    }

    #[test]
    fn test_write_bootloader_message() {
        let mut storage = FakeGblOpsStorage::default();
        storage.add_raw_device(c"misc", [0u8; KiB!(4)]);
        let mut ops = FakeGblOps::new(&storage);

        let mut bcb = BootloaderMessage::new_zeroed();
        bcb.update_boot_command(AndroidBootMode::BootloaderBootOnce);
        write_bootloader_message(&mut ops, &mut bcb).unwrap();

        let bcb = read_bootloader_message(&mut ops).unwrap();
        assert_eq!(bcb.boot_mode(), Ok(AndroidBootMode::BootloaderBootOnce));
    }

    #[test]
    fn test_read_write_virtual_ab_message() {
        // Missing misc partition returns NotFound.
        let empty_storage = FakeGblOpsStorage::default();
        let mut empty_ops = FakeGblOps::new(&empty_storage);
        assert_eq!(
            block_on(read_virtual_ab_message(&mut empty_ops)),
            Err(Error::PartitionNotFound)
        );

        // Too-small misc partition returns OutOfRange.
        let mut small_storage = FakeGblOpsStorage::default();
        small_storage.add_raw_device(c"misc", [0u8; KiB!(4)]);
        let mut small_ops = FakeGblOps::new(&small_storage);
        assert_eq!(block_on(read_virtual_ab_message(&mut small_ops)), Err(Error::OutOfRange));

        // Uninitialized misc partition returns InvalidInput.
        let mut storage = FakeGblOpsStorage::default();
        storage.add_raw_device(c"misc", [0u8; KiB!(64)]);
        let mut ops = FakeGblOps::new(&storage);
        assert_eq!(block_on(read_virtual_ab_message(&mut ops)), Err(Error::InvalidInput));

        // Write Snapshotted status and read back.
        let mut msg = MiscVirtualAbMessage::default();
        msg.set_merge_status(MergeStatus::Snapshotted);
        block_on(write_virtual_ab_message(&mut ops, msg)).unwrap();

        let read_msg = block_on(read_virtual_ab_message(&mut ops)).unwrap();
        assert_eq!(read_msg.merge_status(), MergeStatus::Snapshotted);

        #[cfg(feature = "fuchsia")]
        {
            ops.os = Some(crate::Os::Fuchsia);
            assert_eq!(block_on(read_virtual_ab_message(&mut ops)), Err(Error::Unsupported));
            assert_eq!(
                block_on(write_virtual_ab_message(&mut ops, MiscVirtualAbMessage::default())),
                Err(Error::Unsupported)
            );
        }
    }

    #[test]
    fn test_read_misc_gsi_message() {
        let mut storage = FakeGblOpsStorage::default();
        storage.add_raw_device(c"misc", [0u8; KiB!(64)]);
        let mut ops = FakeGblOps::new(&storage);

        // Uninitialized misc partition has no valid GSI message.
        assert_eq!(read_misc_gsi_message(&mut ops), Err(Error::BadMagic));

        let mut expected = MiscGsiMessage::default();
        expected.set_status(MiscGsiStatus::BootAttempt(2));
        expected.set_active_slot("gsi").unwrap();
        ops.write_to_partition_sync(
            MISC_PARTITION,
            MiscGsiMessage::OFFSET_IN_MISC,
            &mut expected.as_bytes().to_vec(),
        )
        .unwrap();

        let gsi = read_misc_gsi_message(&mut ops).unwrap();
        assert_eq!(gsi, expected);
        assert_eq!(gsi.status(), Ok(Some(MiscGsiStatus::BootAttempt(2))));
        assert!(gsi.is_dirty());
        assert_eq!(gsi.active_slot(), Ok("gsi"));
    }

    #[test]
    fn test_write_misc_gsi_message() {
        let mut storage = FakeGblOpsStorage::default();
        storage.add_raw_device(c"misc", [0u8; KiB!(64)]);
        let mut ops = FakeGblOps::new(&storage);

        let prev_slot_offset = MiscGsiMessage::OFFSET_IN_MISC - (MiscGsiMessage::SIZE_BYTES as u64);
        let next_slot_offset = MiscGsiMessage::OFFSET_IN_MISC + (MiscGsiMessage::SIZE_BYTES as u64);

        // Populate BCB and adjacent system-space slots to verify write does not clobber them.
        let mut bcb = BootloaderMessage::new_zeroed();
        bcb.update_boot_command(AndroidBootMode::Recovery);
        write_bootloader_message(&mut ops, &mut bcb).unwrap();
        ops.write_to_partition_sync(MISC_PARTITION, prev_slot_offset, &mut [0xaau8; 64]).unwrap();
        ops.write_to_partition_sync(MISC_PARTITION, next_slot_offset, &mut [0xbbu8; 64]).unwrap();

        let mut gsi = MiscGsiMessage::default();
        gsi.set_status(MiscGsiStatus::BootAttempt(1));
        gsi.set_active_slot("dsu").unwrap();
        write_misc_gsi_message(&mut ops, gsi).unwrap();

        let mut raw = [0u8; MiscGsiMessage::SIZE_BYTES];
        ops.read_from_partition_sync(MISC_PARTITION, MiscGsiMessage::OFFSET_IN_MISC, &mut raw[..])
            .unwrap();
        assert_eq!(&raw[..], gsi.as_bytes());

        let read_back = read_misc_gsi_message(&mut ops).unwrap();
        assert_eq!(read_back, gsi);

        // Verify BCB and neighboring system-space slots are intact.
        assert_eq!(
            read_bootloader_message(&mut ops).unwrap().boot_mode(),
            Ok(AndroidBootMode::Recovery)
        );
        let mut prev_slot = [0u8; 64];
        let mut next_slot = [0u8; 64];
        ops.read_from_partition_sync(MISC_PARTITION, prev_slot_offset, &mut prev_slot[..]).unwrap();
        ops.read_from_partition_sync(MISC_PARTITION, next_slot_offset, &mut next_slot[..]).unwrap();
        assert_eq!(prev_slot, [0xaau8; 64]);
        assert_eq!(next_slot, [0xbbu8; 64]);
    }

    #[test]
    fn test_read_write_misc_gsi_message_missing_partition() {
        let storage = FakeGblOpsStorage::default();
        let mut ops = FakeGblOps::new(&storage);

        assert_eq!(read_misc_gsi_message(&mut ops), Err(Error::PartitionNotFound));
        assert_eq!(
            write_misc_gsi_message(&mut ops, MiscGsiMessage::default()),
            Err(Error::PartitionNotFound)
        );
    }

    #[test]
    fn test_read_write_misc_gsi_message_partition_too_small() {
        let mut storage = FakeGblOpsStorage::default();
        storage.add_raw_device(c"misc", [0u8; KiB!(4)]);
        let mut ops = FakeGblOps::new(&storage);

        assert!(read_misc_gsi_message(&mut ops).is_err());
        assert!(write_misc_gsi_message(&mut ops, MiscGsiMessage::default()).is_err());
    }
}
