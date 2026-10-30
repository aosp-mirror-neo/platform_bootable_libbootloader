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

//! GBL AVB implementation.

use crate::android_boot::STANDARD_PARTITIONS;
use arrayvec::ArrayVec;
use avb_bindgen::AVB_MAX_NUMBER_OF_LOADED_PARTITIONS;
use core::{ffi::CStr, fmt};
use liberror::Error;

pub(crate) mod ops;
pub mod state;

/// Maximum name length for specialized partitions (including nul terminator).
///
/// Use 36 to match GPT; some use cases might further limit size (e.g. libavb has a 32-byte limit)
/// but those limits should be enforced closer to the usage, in general specialized partitions
/// should support any possible GPT name.
const SPECIALIZED_PARTITION_NAME_MAX_SIZE: usize = 36;

/// Maximum number of partitions that libavb and GBL can verify.
pub(crate) const MAX_PARTITIONS_TO_VERIFY: usize = AVB_MAX_NUMBER_OF_LOADED_PARTITIONS as _;

/// The maximum number of specialized partitions we can support.
///
/// For now we assign this value such that even if all specialized partitions request verification
/// libavb can still handle them all. If we end up having a lot of specialized partitions which
/// don't require verification we could increase this value at the cost of more stack usage; the
/// only hard limit is that the total number of partitions to verify cannot exceed
/// `MAX_PARTITIONS_TO_VERIFY`.
pub const MAX_SPECIALIZED_PARTITIONS: usize = MAX_PARTITIONS_TO_VERIFY - STANDARD_PARTITIONS.len();

/// Array vector capable of storing up to `MAX_PARTITIONS_TO_VERIFY` items.
pub type ArrayMaxParts<T> = ArrayVec<T, MAX_PARTITIONS_TO_VERIFY>;

/// Array vector capable of storing up to `MAX_SPECIALIZED_PARTITIONS` items.
pub type ArrayMaxSpecializedParts<T> = ArrayVec<T, MAX_SPECIALIZED_PARTITIONS>;

/// Represents AVB (Android Verified Boot) device status information.
#[derive(Clone, Debug, PartialEq)]
pub struct AvbDeviceStatus {
    /// Indicates if the device is currently in an unlocked state.
    pub is_unlocked: bool,
    /// Indicates if the device critical lock is unlocked.
    pub is_unlocked_critical: bool,
    /// Indicates if a dm-verity error has been detected.
    pub is_dm_verity_error: bool,
    /// Indicates if the device is unlockable.
    pub is_unlockable: bool,
}

/// Represents AVB vbmeta property.
pub struct AvbProperty<'a> {
    /// Name of the source partition.
    pub partition: &'a CStr,
    /// Property key name.
    pub key: &'a CStr,
    /// Property value.
    pub value_with_nul: &'a [u8],
}

/// Represents AVB loaded/verified partition.
pub struct AvbPartition<'a> {
    /// Name of the partition.
    pub name: &'a CStr,
    /// Data of the partition.
    pub data: &'a [u8],
}

/// The different kinds of verification that can be requested for `SpecializedPartition`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Verification {
    /// The partition must exist and must be successfully verified by vbmeta.
    Required,
    /// Only verify the partition if it exists and has a hash descriptor in the vbmeta blob.
    IfExists,
}

/// Indicates whether a partition is linked to FDR or not.
///
/// Linked to FDR goes both directions:
///
/// * when performing FDR (e.g. during lock/unlock), these partitions should be erased first
/// * when modifying these partitions, we should automatically trigger FDR afterwards
///
/// Generally all partitions that contain user data should be FDR-linked, but devices may want
/// to additionally FDR-link other partitions that contain other transient state.
///
/// Note however that this state should be viewed as a developer convenience only, not security
/// load-bearing e.g. performing an FDR must not rely on the state of non-secure storage.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Fdr {
    /// Partition is not linked to FDR.
    No,
    /// Partition is linked to FDR.
    Yes,
}

/// Indicates whether a partition should be critically-locked.
///
/// Any partition that is necessary to get into fastboot should be critically-locked. The idea
/// is that as long as the critical lock is active, the user is protected against permanently
/// bricking their device via fastboot flashing since they can always reboot back into fastboot
/// and re-flash new images. But once the critical lock is disengaged, it's possible to overwrite
/// those partitions and permanently brick a device.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Critical {
    /// Partition is not guarded by the critical lock.
    No,
    /// Partition is guarded by the critical lock.
    Yes,
}

/// Nul-terminated UTF-8 partition name.
///
/// Every constructor validates the input so that the backing buffer always contains at most
/// [`Self::MAX_LEN`] non-nul UTF-8 bytes followed exclusively by zero bytes (`0u8`).
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct PartitionName([u8; SPECIALIZED_PARTITION_NAME_MAX_SIZE]);

impl PartitionName {
    /// Maximum partition name length in bytes (excluding the trailing nul terminator).
    pub const MAX_LEN: usize = SPECIALIZED_PARTITION_NAME_MAX_SIZE - 1;

    /// Returns the partition name as a [`CStr`].
    pub fn as_cstr(&self) -> &CStr {
        CStr::from_bytes_until_nul(&self.0).unwrap_or(c"")
    }

    /// Returns the partition name as a [`str`].
    pub fn as_str(&self) -> &str {
        self.as_cstr().to_str().unwrap_or("")
    }
}

impl Default for PartitionName {
    fn default() -> Self {
        Self([0; SPECIALIZED_PARTITION_NAME_MAX_SIZE])
    }
}

impl fmt::Debug for PartitionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PartitionName").field(&self.as_str()).finish()
    }
}

impl fmt::Display for PartitionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for PartitionName {
    type Error = Error;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        let bytes = name.as_bytes();
        if bytes.len() > Self::MAX_LEN || bytes.contains(&0) {
            return Err(Error::InvalidInput);
        }
        let mut buffer = [0u8; SPECIALIZED_PARTITION_NAME_MAX_SIZE];
        buffer.get_mut(..bytes.len()).ok_or(Error::InvalidInput)?.copy_from_slice(bytes);
        Ok(Self(buffer))
    }
}

impl TryFrom<&[u8]> for PartitionName {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let name = core::str::from_utf8(bytes).map_err(|_| Error::InvalidInput)?;
        Self::try_from(name)
    }
}

/// A partition which has specialized handling requirements.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SpecializedPartition {
    /// Partition base name (without any slot suffix for slotted partitions).
    pub name: PartitionName,
    /// How to verify this partition, or `None` if this partition does not need to be verified.
    pub verification: Option<Verification>,
    /// Whether this partition is linked to FDR.
    pub fdr: Fdr,
    /// Whether this partition should be critically-locked.
    /// Critical partitions must not be modifiable from fastboot while the critical lock is set.
    pub critical: Critical,
}

impl Default for SpecializedPartition {
    fn default() -> Self {
        SpecializedPartition {
            name: PartitionName::default(),
            verification: None,
            fdr: Fdr::No,
            critical: Critical::No,
        }
    }
}

/// Represents a partition to load and verify during boot.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum LoadPartition<'a> {
    /// boot
    Boot,
    /// vendor_boot
    VendorBoot,
    /// vendor_kernel_boot
    VendorKernelBoot,
    /// init_boot,
    InitBoot,
    /// dtb
    Dtb,
    /// dtbo
    Dtbo,
    /// pVM firmware data
    Pvmfw,
    /// Platform specific partition.
    ///
    /// It's up to the caller to ensure that `SpecializedPartition.verification` is `Some`,
    /// or else trying to use this partition later will panic.
    PlatformSpecific(&'a SpecializedPartition),
}

impl<'a> LoadPartition<'a> {
    /// Returns slotless partition name as &str.
    pub fn name(&self) -> &'a str {
        match self {
            Self::Boot => "boot",
            Self::VendorBoot => "vendor_boot",
            Self::VendorKernelBoot => "vendor_kernel_boot",
            Self::InitBoot => "init_boot",
            Self::Dtb => "dtb",
            Self::Dtbo => "dtbo",
            Self::Pvmfw => "pvmfw",
            Self::PlatformSpecific(part) => part.name.as_str(),
        }
    }

    /// Returns slotless partition name as &CStr.
    pub fn name_cstr(&self) -> &'a CStr {
        match self {
            Self::Boot => c"boot",
            Self::VendorBoot => c"vendor_boot",
            Self::VendorKernelBoot => c"vendor_kernel_boot",
            Self::InitBoot => c"init_boot",
            Self::Dtb => c"dtb",
            Self::Dtbo => c"dtbo",
            Self::Pvmfw => c"pvmfw",
            Self::PlatformSpecific(part) => part.name.as_cstr(),
        }
    }

    /// Returns verification type.
    /// Panics if a `PlatformSpecific` partition is not requesting verification.
    pub fn verification(&self) -> Verification {
        match self {
            Self::PlatformSpecific(part) => part.verification.unwrap(),
            // Treat all standard partitions as optional. The loading logic will decide which ones
            // are actually required.
            _ => Verification::IfExists,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_requested_partition_default_is_empty() {
        let default = SpecializedPartition::default();

        assert_eq!(default.name.as_cstr(), c"");
        assert_eq!(default.name.as_str(), "");
        assert_eq!(default.name, PartitionName::try_from("").unwrap());
    }

    #[test]
    fn test_partition_name_try_from_str() {
        let name = PartitionName::try_from("boot").unwrap();
        assert_eq!(name.as_cstr(), c"boot");
        assert_eq!(name.as_str(), "boot");

        let raw = [b'a'; PartitionName::MAX_LEN];
        let max_str = core::str::from_utf8(&raw).unwrap();
        let max_name = PartitionName::try_from(max_str).unwrap();
        assert_eq!(max_name.as_str(), max_str);

        let too_long_raw = [b'a'; PartitionName::MAX_LEN + 1];
        let too_long_str = core::str::from_utf8(&too_long_raw).unwrap();
        assert_eq!(PartitionName::try_from(too_long_str), Err(Error::InvalidInput));
        assert_eq!(PartitionName::try_from("boot\0extra"), Err(Error::InvalidInput));
    }

    #[test]
    fn test_partition_name_try_from_bytes() {
        let name = PartitionName::try_from(&b"vendor_fw"[..]).unwrap();
        assert_eq!(name.as_str(), "vendor_fw");
        assert_eq!(name.as_cstr(), c"vendor_fw");

        let max_bytes = [b'a'; PartitionName::MAX_LEN];
        assert_eq!(
            PartitionName::try_from(&max_bytes[..]).unwrap().as_cstr().to_bytes(),
            &max_bytes[..]
        );

        let too_long = [b'a'; PartitionName::MAX_LEN + 1];
        assert_eq!(PartitionName::try_from(&too_long[..]), Err(Error::InvalidInput));
        assert_eq!(PartitionName::try_from(&b"boot\0extra"[..]), Err(Error::InvalidInput));
        assert_eq!(PartitionName::try_from(&b"\xff\xfe"[..]), Err(Error::InvalidInput));
    }
}
