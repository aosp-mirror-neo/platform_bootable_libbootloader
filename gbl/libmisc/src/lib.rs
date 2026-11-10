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

//! This library provides APIs to work with data structures inside Android misc partition.
//!
//! Reference code:
//! - https://cs.android.com/android/platform/superproject/main/+/main:bootable/recovery/bootloader_message/include/bootloader_message/bootloader_message.h
//! - https://cs.android.com/android/platform/superproject/main/+/main:bootable/recovery/bootloader_message/include/bootloader_message/bootloader_message_core.h

#![cfg_attr(not(test), no_std)]

use core::{
    ffi::CStr,
    fmt,
    mem::{offset_of, size_of},
};
use liberror::{Error, Result};
use static_assertions::{const_assert, const_assert_eq};
use zerocopy::{
    error::SizeError, FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Ref, Unaligned,
};

/// Android boot modes type
/// Usually obtained from BCB block of misc partition
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AndroidBootMode {
    /// Boot normally using A/B slots.
    Normal = 0,
    /// Stop in bootloader fastboot mode.
    BootloaderBootOnce,
    /// Boot into recovery mode using A/B slots.
    Recovery,
    /// Boot into userspace fastboot.
    Fastboot,
    /// Boot into rescue mode.
    Rescue,
}

const ANDROID_BOOT_MODE_CMD_NORMAL: &[u8] = b"";
const ANDROID_BOOT_MODE_CMD_BOOTLOADER: &[u8] = b"bootonce-bootloader";
const ANDROID_BOOT_MODE_CMD_RECOVERY: &[u8] = b"boot-recovery";
const ANDROID_BOOT_MODE_CMD_FASTBOOT: &[u8] = b"boot-fastboot";
const ANDROID_BOOT_MODE_CMD_RESCUE: &[u8] = b"boot-rescue";

impl TryFrom<&[u8]> for AndroidBootMode {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        match bytes {
            ANDROID_BOOT_MODE_CMD_NORMAL => Ok(AndroidBootMode::Normal),
            ANDROID_BOOT_MODE_CMD_BOOTLOADER => Ok(AndroidBootMode::BootloaderBootOnce),
            ANDROID_BOOT_MODE_CMD_RECOVERY => Ok(AndroidBootMode::Recovery),
            ANDROID_BOOT_MODE_CMD_FASTBOOT => Ok(AndroidBootMode::Fastboot),
            ANDROID_BOOT_MODE_CMD_RESCUE => Ok(AndroidBootMode::Rescue),
            _ => Err(Error::Other(Some("Invalid BCB command"))),
        }
    }
}

impl From<AndroidBootMode> for &'static [u8] {
    fn from(mode: AndroidBootMode) -> Self {
        match mode {
            AndroidBootMode::Normal => ANDROID_BOOT_MODE_CMD_NORMAL,
            AndroidBootMode::BootloaderBootOnce => ANDROID_BOOT_MODE_CMD_BOOTLOADER,
            AndroidBootMode::Recovery => ANDROID_BOOT_MODE_CMD_RECOVERY,
            AndroidBootMode::Fastboot => ANDROID_BOOT_MODE_CMD_FASTBOOT,
            AndroidBootMode::Rescue => ANDROID_BOOT_MODE_CMD_RESCUE,
        }
    }
}

impl AndroidBootMode {
    /// Whether the boot mode should be handled in recovery.
    pub const fn should_enter_recovery(&self) -> bool {
        match self {
            AndroidBootMode::Recovery | AndroidBootMode::Fastboot | AndroidBootMode::Rescue => true,
            AndroidBootMode::Normal | AndroidBootMode::BootloaderBootOnce => false,
        }
    }
}

/// BCB command field size in bytes.
const COMMAND_FIELD_SIZE: usize = 32;

/// Android bootloader message structure that usually placed in the first block of misc partition
///
/// Reference code:
/// https://cs.android.com/android/platform/superproject/main/+/95ec3cc1d879b92dd9db3bb4c4345c5fc812cdaa:bootable/recovery/bootloader_message/include/bootloader_message/bootloader_message.h;l=67
#[repr(C, packed)]
#[derive(Clone, Debug, PartialEq, Eq, Immutable, FromBytes, IntoBytes, KnownLayout, Unaligned)]
pub struct BootloaderMessage {
    command: [u8; COMMAND_FIELD_SIZE],
    status: [u8; 32],
    recovery: [u8; 768],
    stage: [u8; 32],
    reserved: [u8; 1184],
}

impl BootloaderMessage {
    /// BCB size in bytes
    pub const SIZE_BYTES: usize = 2048;

    /// Extract BootloaderMessage reference from bytes
    pub fn from_bytes_ref(buffer: &[u8]) -> Result<&BootloaderMessage> {
        Ok(Ref::into_ref(
            Ref::<_, BootloaderMessage>::new_from_prefix(buffer)
                .ok_or(Error::BufferTooSmall(Some(core::mem::size_of::<BootloaderMessage>())))?
                .0,
        ))
    }

    fn command_cstr(&self) -> Result<&CStr> {
        CStr::from_bytes_until_nul(&self.command)
            .map_err(|_| Error::Other(Some("Cannot read BCB command")))
    }

    /// Extract AndroidBootMode from BCB command field
    pub fn boot_mode(&self) -> Result<AndroidBootMode> {
        self.command_cstr()?.to_bytes().try_into()
    }

    /// Get the BCB command as str.
    pub fn boot_command(&self) -> Result<&str> {
        Ok(self.command_cstr()?.to_str()?)
    }

    /// Update the BCB boot command with AndroidBootMode.
    pub fn update_boot_command(&mut self, mode: AndroidBootMode) {
        let boot_cmd: &[u8] = mode.into();
        self.command.fill(0);
        self.command[..boot_cmd.len()].copy_from_slice(boot_cmd);
    }
}

const_assert!(BootloaderMessage::SIZE_BYTES == size_of::<BootloaderMessage>());

/// Offset in `misc` partition where system space starts (`misc_virtual_ab_message` resides at the
/// beginning of system space).
///
/// Reference code:
/// https://cs.android.com/search?q=symbol:SYSTEM_SPACE_OFFSET_IN_MISC&ss=android%2Fplatform%2Fsuperproject%2Fmain
pub const SYSTEM_SPACE_OFFSET_IN_MISC: usize = 32 * 1024;

/// Version of `MiscVirtualAbMessage`.
pub const MISC_VIRTUAL_AB_MESSAGE_VERSION: u8 = 2;

/// Magic header for `MiscVirtualAbMessage`.
pub const MISC_VIRTUAL_AB_MAGIC_HEADER: u32 = 0x56740AB0;

/// Virtual A/B snapshot merge status stored in `MiscVirtualAbMessage`.
///
/// Reference:
/// https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/boot/aidl/android/hardware/boot/MergeStatus.aidl
#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum MergeStatus {
    /// No snapshot or merge is in progress.
    #[default]
    None = 0,
    /// Merge status could not be determined.
    Unknown = 1,
    /// Partitions are snapshotted, but no merge has been started.
    Snapshotted = 2,
    /// At least one partition has merge in progress.
    Merging = 3,
    /// A merge was in progress, but it was canceled by the bootloader.
    Cancelled = 4,
}

impl From<u8> for MergeStatus {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::None,
            1 => Self::Unknown,
            2 => Self::Snapshotted,
            3 => Self::Merging,
            4 => Self::Cancelled,
            _ => Self::Unknown,
        }
    }
}

impl From<MergeStatus> for u8 {
    fn from(status: MergeStatus) -> Self {
        status as u8
    }
}

impl From<MergeStatus> for &'static str {
    /// Returns the fastboot string representation of the merge status.
    ///
    /// Matches AOSP `SnapshotUpdateMergeStatus`: only `Snapshotted` and `Merging` report their
    /// active state; `None`, `Unknown`, and `Cancelled` all report `"none"`.
    fn from(status: MergeStatus) -> Self {
        match status {
            MergeStatus::Snapshotted => "snapshotted",
            MergeStatus::Merging => "merging",
            MergeStatus::None | MergeStatus::Unknown | MergeStatus::Cancelled => "none",
        }
    }
}

impl fmt::Display for MergeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).into())
    }
}

#[repr(C, packed)]
#[derive(Clone, Debug, PartialEq, Eq, Immutable, FromBytes, IntoBytes, KnownLayout, Unaligned)]
struct RawMiscVirtualAbMessage {
    version: u8,
    magic: u32,
    merge_status: u8,
    source_slot: u8,
    reserved: [u8; 57],
}

/// Holds Virtual A/B message in the `misc` partition.
///
/// Instances of `MiscVirtualAbMessage` are guaranteed to carry a valid version and magic header.
///
/// Reference code:
/// https://cs.android.com/search?q=symbol:misc_virtual_ab_message&ss=android%2Fplatform%2Fsuperproject%2Fmain
#[repr(transparent)]
#[derive(Clone, Debug, PartialEq, Eq, Immutable, IntoBytes, KnownLayout, Unaligned)]
pub struct MiscVirtualAbMessage(RawMiscVirtualAbMessage);

impl Default for MiscVirtualAbMessage {
    fn default() -> Self {
        Self(RawMiscVirtualAbMessage {
            version: MISC_VIRTUAL_AB_MESSAGE_VERSION,
            magic: MISC_VIRTUAL_AB_MAGIC_HEADER,
            merge_status: MergeStatus::None.into(),
            source_slot: 0,
            reserved: [0; 57],
        })
    }
}

impl From<MiscVirtualAbMessage> for [u8; MiscVirtualAbMessage::SIZE_BYTES] {
    fn from(msg: MiscVirtualAbMessage) -> Self {
        zerocopy::transmute!(msg)
    }
}

impl TryFrom<RawMiscVirtualAbMessage> for MiscVirtualAbMessage {
    type Error = Error;

    fn try_from(raw: RawMiscVirtualAbMessage) -> Result<Self> {
        let magic = raw.magic;
        if raw.version != MISC_VIRTUAL_AB_MESSAGE_VERSION || magic != MISC_VIRTUAL_AB_MAGIC_HEADER {
            return Err(Error::InvalidInput);
        }
        Ok(Self(raw))
    }
}

impl TryFrom<&[u8]> for MiscVirtualAbMessage {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let (raw, _) = RawMiscVirtualAbMessage::read_from_prefix(bytes).map_err(|e| {
            // Destructuring `SizeError` statically ensures that no other error is possible.
            let SizeError { .. } = e;
            Error::BufferTooSmall(Some(Self::SIZE_BYTES))
        })?;
        Self::try_from(raw)
    }
}

impl MiscVirtualAbMessage {
    /// Size of `MiscVirtualAbMessage` in bytes.
    pub const SIZE_BYTES: usize = 64;

    /// Returns the `MergeStatus` represented by this message.
    pub fn merge_status(&self) -> MergeStatus {
        MergeStatus::from(self.0.merge_status)
    }

    /// Updates the `MergeStatus` in this message.
    pub fn set_merge_status(&mut self, status: MergeStatus) {
        self.0.merge_status = status.into();
    }
}

const_assert!(MiscVirtualAbMessage::SIZE_BYTES == size_of::<MiscVirtualAbMessage>());

/// GSI message `active_slot` field size in bytes (including NUL terminator).
const GSI_ACTIVE_SLOT_FIELD_SIZE: usize = 33;

/// GSI install status stored in [`MiscGsiMessage`].
///
/// Mirrors the install status used by `libgsi` (`/metadata/gsi/dsu/install_status`). A message
/// with no status set (`MISC_GSI_STATUS_UNDEFINED`) is reported as `None` by
/// [`MiscGsiMessage::status`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MiscGsiStatus {
    /// GSI booted successfully (`MISC_GSI_STATUS_BOOT_SUCCESS`, install status `"ok"`).
    BootSuccess,
    /// GSI boot attempted, with the number of attempts so far (`MISC_GSI_STATUS_BOOT_ATTEMPT`,
    /// install status `"<attempts>"`).
    BootAttempt(u8),
    /// GSI is disabled (`MISC_GSI_STATUS_DISABLED`, install status `"disabled"`).
    Disabled,
    /// GSI wipe requested (`MISC_GSI_STATUS_WIPE`, install status `"wipe"`).
    Wipe,
}

#[repr(C, packed)]
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Immutable, FromBytes, IntoBytes, KnownLayout, Unaligned,
)]
struct RawMiscGsiMessage {
    version: u8,
    magic: u32,
    status: u8,
    attempt: u8,
    flags: u32,
    active_slot: [u8; GSI_ACTIVE_SLOT_FIELD_SIZE],
    reserved: [u8; 20],
}

/// Android GSI message (`misc_gsi_message`) placed in the system space of the `misc` partition.
///
/// Instances of `MiscGsiMessage` are guaranteed to carry a valid version and magic header. Parsing
/// with `MiscGsiMessage::try_from(&[u8])` returns [`Error::BadMagic`] or
/// [`Error::UnsupportedVersion`] if the header is invalid (e.g. the message was never written).
///
/// Reference code:
/// https://cs.android.com/android/platform/superproject/main/+/main:bootable/recovery/bootloader_message/include/bootloader_message/bootloader_message_core.h
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Immutable, IntoBytes, KnownLayout, Unaligned)]
pub struct MiscGsiMessage(RawMiscGsiMessage);

impl MiscGsiMessage {
    /// `misc_gsi_message` size in bytes.
    pub const SIZE_BYTES: usize = 64;

    /// Offset in bytes of `misc_gsi_message` within the `misc` system space (`4 * 64` bytes,
    /// following `virtual_ab_message`, `memtag_message`, `kcmdline_message`, and `control_message`
    /// in `misc_system_space_layout`).
    const OFFSET_IN_SYSTEM_SPACE: u64 = 4 * 64;

    /// Offset in bytes of `misc_gsi_message` within the `misc` partition (32 KiB + 256 bytes).
    pub const OFFSET_IN_MISC: u64 = {
        let system_space_offset: u64 = libutils::const_cast!(SYSTEM_SPACE_OFFSET_IN_MISC);
        system_space_offset + Self::OFFSET_IN_SYSTEM_SPACE
    };

    /// Structure version (`MISC_GSI_MESSAGE_VERSION`).
    const VERSION: u8 = 1;

    /// Magic signature (`MISC_GSI_MAGIC_HEADER`, `"mgsi"`).
    const MAGIC: u32 = 0x6d677369;

    /// Dirty flag (`MISC_GSI_FLAGS_DIRTY`), indicating `/misc` status is out of sync with
    /// `/metadata/gsi/dsu/install_status`.
    pub const FLAGS_DIRTY: u32 = 0x1;

    // Raw `status` values (`MISC_GSI_STATUS_*`).
    const STATUS_UNDEFINED: u8 = 0;
    const STATUS_BOOT_SUCCESS: u8 = 1;
    const STATUS_BOOT_ATTEMPT: u8 = 2;
    const STATUS_DISABLED: u8 = 3;
    const STATUS_WIPE: u8 = 4;

    /// Gets the [`MiscGsiStatus`].
    ///
    /// Returns `Ok(None)` if no status is set (`MISC_GSI_STATUS_UNDEFINED`), and
    /// [`Error::InvalidInput`] for an unknown status value. Like `libgsi`, the `attempt` field is
    /// only read for [`MiscGsiStatus::BootAttempt`].
    pub const fn status(&self) -> Result<Option<MiscGsiStatus>> {
        Ok(match self.0.status {
            Self::STATUS_UNDEFINED => None,
            Self::STATUS_BOOT_SUCCESS => Some(MiscGsiStatus::BootSuccess),
            Self::STATUS_BOOT_ATTEMPT => Some(MiscGsiStatus::BootAttempt(self.0.attempt)),
            Self::STATUS_DISABLED => Some(MiscGsiStatus::Disabled),
            Self::STATUS_WIPE => Some(MiscGsiStatus::Wipe),
            _ => return Err(Error::InvalidInput),
        })
    }

    /// Sets the [`MiscGsiStatus`] and marks the message dirty.
    ///
    /// Like `libgsi`, the `attempt` field is set to the attempt count for
    /// [`MiscGsiStatus::BootAttempt`] and cleared for all other statuses.
    ///
    /// [`Self::FLAGS_DIRTY`] is set because the bootloader cannot update
    /// `/metadata/gsi/dsu/install_status`. It tells `libgsi` to sync the new status from `misc` on
    /// the next boot (currently done only for [`MiscGsiStatus::Disabled`] and
    /// [`MiscGsiStatus::Wipe`]).
    pub const fn set_status(&mut self, status: MiscGsiStatus) {
        (self.0.status, self.0.attempt) = match status {
            MiscGsiStatus::BootSuccess => (Self::STATUS_BOOT_SUCCESS, 0),
            MiscGsiStatus::BootAttempt(attempt) => (Self::STATUS_BOOT_ATTEMPT, attempt),
            MiscGsiStatus::Disabled => (Self::STATUS_DISABLED, 0),
            MiscGsiStatus::Wipe => (Self::STATUS_WIPE, 0),
        };
        self.set_dirty(true);
    }

    /// Gets the raw GSI flags.
    pub const fn flags(&self) -> u32 {
        self.0.flags
    }

    /// Returns whether [`Self::FLAGS_DIRTY`] is set in `flags`.
    pub const fn is_dirty(&self) -> bool {
        (self.0.flags & Self::FLAGS_DIRTY) != 0
    }

    /// Sets or clears [`Self::FLAGS_DIRTY`] in `flags`.
    pub const fn set_dirty(&mut self, dirty: bool) {
        if dirty {
            self.0.flags |= Self::FLAGS_DIRTY;
        } else {
            self.0.flags &= !Self::FLAGS_DIRTY;
        }
    }

    /// Gets the `active_slot` field as a `&str`.
    pub fn active_slot(&self) -> Result<&str> {
        Ok(CStr::from_bytes_until_nul(&self.0.active_slot)?.to_str()?)
    }

    /// Updates the `active_slot` field with a NUL-terminated string.
    ///
    /// Returns [`Error::InvalidInput`] if `slot` exceeds `GSI_ACTIVE_SLOT_FIELD_SIZE - 1` (32)
    /// bytes or contains an interior NUL byte.
    pub fn set_active_slot(&mut self, slot: &str) -> Result<()> {
        if slot.len() >= GSI_ACTIVE_SLOT_FIELD_SIZE || slot.as_bytes().contains(&0) {
            return Err(Error::InvalidInput);
        }
        self.0.active_slot.fill(0);
        self.0.active_slot[..slot.len()].copy_from_slice(slot.as_bytes());
        Ok(())
    }

    /// Returns whether the active DSU slot is locked (slot name ends with `".lock"`).
    ///
    /// Returns [`Error::InvalidInput`] if `active_slot` is not a valid NUL-terminated UTF-8 string.
    pub fn is_locked_dsu(&self) -> Result<bool> {
        Ok(self.active_slot()?.ends_with(".lock"))
    }
}

impl Default for MiscGsiMessage {
    fn default() -> Self {
        Self(RawMiscGsiMessage {
            version: Self::VERSION,
            magic: Self::MAGIC,
            ..RawMiscGsiMessage::new_zeroed()
        })
    }
}

impl From<MiscGsiMessage> for [u8; MiscGsiMessage::SIZE_BYTES] {
    fn from(msg: MiscGsiMessage) -> Self {
        zerocopy::transmute!(msg)
    }
}

impl TryFrom<RawMiscGsiMessage> for MiscGsiMessage {
    type Error = Error;

    fn try_from(raw: RawMiscGsiMessage) -> Result<Self> {
        let magic = raw.magic;
        if magic != Self::MAGIC {
            return Err(Error::BadMagic);
        }
        if raw.version != Self::VERSION {
            return Err(Error::UnsupportedVersion);
        }
        Ok(Self(raw))
    }
}

impl TryFrom<&[u8]> for MiscGsiMessage {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let (raw, _) = RawMiscGsiMessage::read_from_prefix(bytes).map_err(|e| {
            // Destructuring `SizeError` statically ensures that no other error is possible.
            let SizeError { .. } = e;
            Error::BufferTooSmall(Some(Self::SIZE_BYTES))
        })?;
        Self::try_from(raw)
    }
}

const_assert_eq!(offset_of!(RawMiscGsiMessage, version), 0);
const_assert_eq!(offset_of!(RawMiscGsiMessage, magic), 1);
const_assert_eq!(offset_of!(RawMiscGsiMessage, status), 5);
const_assert_eq!(offset_of!(RawMiscGsiMessage, attempt), 6);
const_assert_eq!(offset_of!(RawMiscGsiMessage, flags), 7);
const_assert_eq!(offset_of!(RawMiscGsiMessage, active_slot), 11);
const_assert_eq!(offset_of!(RawMiscGsiMessage, reserved), 44);
const_assert_eq!(MiscGsiMessage::SIZE_BYTES, size_of::<MiscGsiMessage>());

#[cfg(test)]
mod test {
    use super::*;

    fn test_parse_bcb(command: &[u8], expected_mode: Result<AndroidBootMode>) {
        let mut bcb = BootloaderMessage::new_zeroed();
        bcb.command[..command.len()].copy_from_slice(command);
        assert_eq!(
            BootloaderMessage::from_bytes_ref(bcb.as_bytes()).unwrap().boot_mode(),
            expected_mode
        );
    }

    #[test]
    fn test_bcb_empty_parsed_as_normal() {
        test_parse_bcb(b"", Ok(AndroidBootMode::Normal));
    }

    #[test]
    fn test_bcb_with_wrong_command_failed() {
        test_parse_bcb(b"boot-wrong", Err(Error::Other(Some("Invalid BCB command"))));
    }

    #[test]
    fn test_bcb_to_recovery_parsed() {
        test_parse_bcb(ANDROID_BOOT_MODE_CMD_RECOVERY, Ok(AndroidBootMode::Recovery));
    }

    #[test]
    fn test_bcb_to_fastboot_parsed() {
        test_parse_bcb(ANDROID_BOOT_MODE_CMD_FASTBOOT, Ok(AndroidBootMode::Fastboot));
    }

    #[test]
    fn test_bcb_to_bootloader_once_parsed() {
        test_parse_bcb(ANDROID_BOOT_MODE_CMD_BOOTLOADER, Ok(AndroidBootMode::BootloaderBootOnce));
    }

    #[test]
    fn test_bcb_update_boot_command() {
        macro_rules! assert_bcb_update_boot_command {
            ($mode:expr) => {
                let mut bcb = BootloaderMessage::new_zeroed();
                bcb.update_boot_command($mode);
                assert_eq!(bcb.boot_mode(), Ok($mode));
            };
        }

        assert_bcb_update_boot_command!(AndroidBootMode::Normal);
        assert_bcb_update_boot_command!(AndroidBootMode::BootloaderBootOnce);
        assert_bcb_update_boot_command!(AndroidBootMode::Recovery);
        assert_bcb_update_boot_command!(AndroidBootMode::Fastboot);
        assert_bcb_update_boot_command!(AndroidBootMode::Rescue);
    }

    #[test]
    fn test_android_boot_mode_into_from_bytes() {
        macro_rules! assert_android_boot_mode {
            ($mode:expr) => {
                let boot_cmd: &[u8] = $mode.into();
                assert!(boot_cmd.len() < COMMAND_FIELD_SIZE);
                assert_eq!(boot_cmd.try_into(), Ok($mode));
            };
        }

        assert_android_boot_mode!(AndroidBootMode::Normal);
        assert_android_boot_mode!(AndroidBootMode::BootloaderBootOnce);
        assert_android_boot_mode!(AndroidBootMode::Recovery);
        assert_android_boot_mode!(AndroidBootMode::Fastboot);
        assert_android_boot_mode!(AndroidBootMode::Normal);
    }

    #[test]
    fn test_virtual_ab_message_try_from_buffer_too_small() {
        let buf = [0u8; MiscVirtualAbMessage::SIZE_BYTES - 1];
        assert_eq!(
            MiscVirtualAbMessage::try_from(&buf[..]),
            Err(Error::BufferTooSmall(Some(MiscVirtualAbMessage::SIZE_BYTES)))
        );
    }

    #[test]
    fn test_virtual_ab_message_try_from_uninitialized_fails() {
        let buf = [0u8; MiscVirtualAbMessage::SIZE_BYTES];
        assert_eq!(MiscVirtualAbMessage::try_from(&buf[..]), Err(Error::InvalidInput));
    }

    #[test]
    fn test_virtual_ab_message_default_is_valid() {
        let msg = MiscVirtualAbMessage::default();
        assert_eq!(MiscVirtualAbMessage::try_from(msg.as_bytes()), Ok(msg.clone()));
        assert_eq!(msg.merge_status(), MergeStatus::None);
        assert_eq!(<&str>::from(msg.merge_status()), "none");
        assert_eq!(format!("{}", msg.merge_status()), "none");
        let bytes: [u8; MiscVirtualAbMessage::SIZE_BYTES] = msg.clone().into();
        assert_eq!(MiscVirtualAbMessage::try_from(&bytes[..]), Ok(msg));
    }

    #[test]
    fn test_virtual_ab_message_invalid_magic_or_version_fails() {
        let mut msg = MiscVirtualAbMessage::default();
        msg.set_merge_status(MergeStatus::Snapshotted);
        assert_eq!(MiscVirtualAbMessage::try_from(msg.as_bytes()), Ok(msg.clone()));
        assert_eq!(MiscVirtualAbMessage::try_from(msg.0.clone()), Ok(msg.clone()));

        let mut bad_version = msg.0.clone();
        bad_version.version = 1;
        assert_eq!(
            MiscVirtualAbMessage::try_from(bad_version.as_bytes()),
            Err(Error::InvalidInput)
        );
        assert_eq!(MiscVirtualAbMessage::try_from(bad_version), Err(Error::InvalidInput));

        let mut bad_magic = msg.0;
        bad_magic.magic = 0x12345678;
        assert_eq!(MiscVirtualAbMessage::try_from(bad_magic.as_bytes()), Err(Error::InvalidInput));
        assert_eq!(MiscVirtualAbMessage::try_from(bad_magic), Err(Error::InvalidInput));
    }

    #[test]
    fn test_virtual_ab_message_set_and_get_merge_status() {
        let mut msg = MiscVirtualAbMessage::default();
        for (status, expected_str) in [
            (MergeStatus::None, "none"),
            (MergeStatus::Unknown, "none"),
            (MergeStatus::Snapshotted, "snapshotted"),
            (MergeStatus::Merging, "merging"),
            (MergeStatus::Cancelled, "none"),
        ] {
            msg.set_merge_status(status);
            let parsed = MiscVirtualAbMessage::try_from(msg.as_bytes()).unwrap();
            assert_eq!(parsed.merge_status(), status);
            assert_eq!(<&str>::from(parsed.merge_status()), expected_str);
            assert_eq!(format!("{}", parsed.merge_status()), expected_str);
        }
    }

    #[test]
    fn test_virtual_ab_message_preserves_source_slot_and_prefix_read() {
        let mut raw_msg = MiscVirtualAbMessage::default().0;
        raw_msg.merge_status = MergeStatus::Merging.into();
        raw_msg.source_slot = 1;
        raw_msg.reserved[0] = 0x5a;

        let mut buf = [0u8; MiscVirtualAbMessage::SIZE_BYTES + 16];
        buf[..MiscVirtualAbMessage::SIZE_BYTES].copy_from_slice(raw_msg.as_bytes());

        let mut msg = MiscVirtualAbMessage::try_from(&buf[..]).unwrap();
        assert_eq!(msg.merge_status(), MergeStatus::Merging);
        msg.set_merge_status(MergeStatus::Cancelled);
        assert_eq!(msg.merge_status(), MergeStatus::Cancelled);
        assert_eq!(msg.0.source_slot, 1);
        assert_eq!(msg.0.reserved[0], 0x5a);
    }

    #[test]
    fn test_misc_gsi_message_default_is_valid() {
        let gsi = MiscGsiMessage::default();
        assert_eq!(gsi.status(), Ok(None));
        assert_eq!(gsi.flags(), 0);
        assert!(!gsi.is_dirty());
        assert_eq!(gsi.active_slot(), Ok(""));
        assert_eq!(MiscGsiMessage::try_from(gsi.as_bytes()), Ok(gsi));
        let bytes: [u8; MiscGsiMessage::SIZE_BYTES] = gsi.into();
        assert_eq!(MiscGsiMessage::try_from(&bytes[..]), Ok(gsi));
    }

    #[test]
    fn test_misc_gsi_message_try_from_invalid() {
        let buf = [0u8; MiscGsiMessage::SIZE_BYTES - 1];
        assert_eq!(
            MiscGsiMessage::try_from(&buf[..]),
            Err(Error::BufferTooSmall(Some(MiscGsiMessage::SIZE_BYTES)))
        );

        // An uninitialized (zeroed) message has no valid header.
        let buf = [0u8; MiscGsiMessage::SIZE_BYTES];
        assert_eq!(MiscGsiMessage::try_from(&buf[..]), Err(Error::BadMagic));

        let mut bad_magic = MiscGsiMessage::default().0;
        bad_magic.magic = !MiscGsiMessage::MAGIC;
        assert_eq!(MiscGsiMessage::try_from(bad_magic.as_bytes()), Err(Error::BadMagic));
        assert_eq!(MiscGsiMessage::try_from(bad_magic), Err(Error::BadMagic));

        let mut bad_version = MiscGsiMessage::default().0;
        bad_version.version = 2;
        assert_eq!(
            MiscGsiMessage::try_from(bad_version.as_bytes()),
            Err(Error::UnsupportedVersion)
        );
        assert_eq!(MiscGsiMessage::try_from(bad_version), Err(Error::UnsupportedVersion));
    }

    #[test]
    fn test_misc_gsi_message_binary_layout() {
        let mut gsi = MiscGsiMessage::default();
        gsi.set_status(MiscGsiStatus::BootAttempt(3));
        gsi.set_active_slot("gsi").unwrap();

        let bytes = gsi.as_bytes();
        assert_eq!(bytes[0], MiscGsiMessage::VERSION);
        assert_eq!(&bytes[1..5], &MiscGsiMessage::MAGIC.to_le_bytes());
        assert_eq!(bytes[5], MiscGsiMessage::STATUS_BOOT_ATTEMPT);
        assert_eq!(bytes[6], 3);
        assert_eq!(&bytes[7..11], &MiscGsiMessage::FLAGS_DIRTY.to_le_bytes());
        assert_eq!(&bytes[11..15], b"gsi\0");
        assert_eq!(&bytes[15..44], &[0u8; 29]);
        assert_eq!(&bytes[44..64], &[0u8; 20]);
        assert_eq!(MiscGsiMessage::try_from(bytes), Ok(gsi));
    }

    #[test]
    fn test_misc_gsi_message_preserves_reserved_and_prefix_read() {
        let mut raw = MiscGsiMessage::default().0;
        raw.reserved[0] = 0x5a;

        // Parsing only consumes the first `SIZE_BYTES` bytes.
        let mut buf = [0xffu8; MiscGsiMessage::SIZE_BYTES + 16];
        buf[..MiscGsiMessage::SIZE_BYTES].copy_from_slice(raw.as_bytes());

        let mut gsi = MiscGsiMessage::try_from(&buf[..]).unwrap();
        gsi.set_status(MiscGsiStatus::Wipe);
        assert_eq!(gsi.0.reserved[0], 0x5a);
    }

    #[test]
    fn test_misc_gsi_status_encoding() {
        for (status, raw_status, raw_attempt) in [
            (MiscGsiStatus::BootSuccess, 1, 0),
            (MiscGsiStatus::BootAttempt(0), 2, 0),
            (MiscGsiStatus::BootAttempt(u8::MAX), 2, u8::MAX),
            (MiscGsiStatus::Disabled, 3, 0),
            (MiscGsiStatus::Wipe, 4, 0),
        ] {
            // Start from a non-zero attempt count and an unrelated flag bit (0x10) to check that
            // `set_status()` overwrites the attempt count, preserves other flags, and sets dirty.
            let mut gsi = MiscGsiMessage::default();
            (gsi.0.attempt, gsi.0.flags) = (7, 0x10);
            gsi.set_status(status);
            assert_eq!((gsi.0.status, gsi.0.attempt), (raw_status, raw_attempt));
            assert_eq!(gsi.status(), Ok(Some(status)));
            assert_eq!(gsi.flags(), 0x10 | MiscGsiMessage::FLAGS_DIRTY);
        }
    }

    #[test]
    fn test_misc_gsi_status_decoding() {
        // No status set.
        assert_eq!(MiscGsiMessage::default().status(), Ok(None));

        // `attempt` is ignored for statuses other than `BootAttempt`.
        let mut gsi = MiscGsiMessage::default();
        (gsi.0.status, gsi.0.attempt) = (3, 5);
        assert_eq!(gsi.status(), Ok(Some(MiscGsiStatus::Disabled)));

        // Unknown status values are rejected.
        for raw_status in [5, u8::MAX] {
            gsi.0.status = raw_status;
            assert_eq!(gsi.status(), Err(Error::InvalidInput));
        }
    }

    #[test]
    fn test_misc_gsi_message_dirty_flag() {
        let mut gsi = MiscGsiMessage::default();
        gsi.0.flags = 0x10;
        assert!(!gsi.is_dirty());

        gsi.set_dirty(true);
        assert!(gsi.is_dirty());
        assert_eq!(gsi.flags(), 0x10 | MiscGsiMessage::FLAGS_DIRTY);

        gsi.set_dirty(false);
        assert!(!gsi.is_dirty());
        assert_eq!(gsi.flags(), 0x10);
    }

    #[test]
    fn test_misc_gsi_message_active_slot() {
        let mut gsi = MiscGsiMessage::default();

        // Overwriting a longer slot name with a shorter one clears trailing bytes.
        gsi.set_active_slot("dsu_longer_name").unwrap();
        assert_eq!(gsi.active_slot(), Ok("dsu_longer_name"));
        gsi.set_active_slot("dsu").unwrap();
        assert_eq!(gsi.active_slot(), Ok("dsu"));

        // Maximum allowed length (32 bytes + 1 NUL terminator).
        let max_slot = "a".repeat(GSI_ACTIVE_SLOT_FIELD_SIZE - 1);
        assert_eq!(gsi.set_active_slot(&max_slot), Ok(()));
        assert_eq!(gsi.active_slot(), Ok(max_slot.as_str()));

        // 33 bytes (leaves no space for NUL terminator) is rejected.
        let too_long_slot = "a".repeat(GSI_ACTIVE_SLOT_FIELD_SIZE);
        assert_eq!(gsi.set_active_slot(&too_long_slot), Err(Error::InvalidInput));

        // Interior NUL byte is rejected.
        assert_eq!(gsi.set_active_slot("dsu\0slot"), Err(Error::InvalidInput));

        // Missing NUL terminator in raw bytes is rejected on read.
        gsi.0.active_slot = [b'x'; GSI_ACTIVE_SLOT_FIELD_SIZE];
        assert_eq!(gsi.active_slot(), Err(Error::InvalidInput));

        // Invalid UTF-8 before NUL terminator in raw bytes is rejected on read.
        gsi.0.active_slot.fill(0);
        gsi.0.active_slot[0] = 0xff;
        assert_eq!(gsi.active_slot(), Err(Error::InvalidInput));
        assert_eq!(gsi.is_locked_dsu(), Err(Error::InvalidInput));
    }

    #[test]
    fn test_misc_gsi_message_is_locked_dsu() {
        let mut gsi = MiscGsiMessage::default();
        assert_eq!(gsi.is_locked_dsu(), Ok(false));

        gsi.set_active_slot("dsu").unwrap();
        assert_eq!(gsi.is_locked_dsu(), Ok(false));

        gsi.set_active_slot("dsu.lock").unwrap();
        assert_eq!(gsi.is_locked_dsu(), Ok(true));

        gsi.set_active_slot(".lock").unwrap();
        assert_eq!(gsi.is_locked_dsu(), Ok(true));

        gsi.set_active_slot("dsu.lock.extra").unwrap();
        assert_eq!(gsi.is_locked_dsu(), Ok(false));
    }
}
