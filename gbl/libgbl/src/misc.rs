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

//! Helpers for manipulating the bootloader_message (BCB) and Virtual A/B metadata in `misc`.

use crate::{partition::check_part_unique, GblOps};
use gbl_async::yield_now;
use liberror::{Error, Result};
use zerocopy::{error::SizeError, FromBytes, FromZeros, IntoBytes};

pub use misc::{
    AndroidBootMode, BootloaderMessage, MergeStatus, MiscVirtualAbMessage,
    SYSTEM_SPACE_OFFSET_IN_MISC,
};

/// The partition that contains the bootloader_message (BCB) and Virtual A/B metadata.
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
/// * `Err(Error::NotFound)` if the `misc` partition does not exist.
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

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::{
        constants::KiB,
        ops::test::{FakeGblOps, FakeGblOpsStorage},
    };
    use gbl_async::block_on;

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
        assert_eq!(block_on(read_virtual_ab_message(&mut empty_ops)), Err(Error::NotFound));

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
}
