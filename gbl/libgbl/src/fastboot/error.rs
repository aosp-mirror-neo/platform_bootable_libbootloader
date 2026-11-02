// Copyright (C) 2026 The Android Open Source Project
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

//! Error type for GBL fastboot commands.

use crate::IntegrationError;
use avb::IoError;
use core::fmt::{Display, Formatter};
use liberror::Error;

/// Error type for GBL fastboot commands.
///
/// Errors keep the values needed to describe them and are only formatted when sent to the host as
/// a "FAIL<message>" response. This avoids reserving space for a formatted string buffer at every
/// call site and async frame that holds a result.
#[derive(Debug, PartialEq)]
pub enum GblFastbootError {
    /// A static message.
    Msg(&'static str),
    /// A libgbl error.
    Libgbl(Error),
    /// A GBL integration error.
    Integration(IntegrationError),
    /// Failed to initialize the boot item container.
    BootItemInit(Error),
    /// Failed to read the device lock state.
    LockState(IoError),
    /// The images loaded before entering fastboot failed to load.
    LoadFailed(IntegrationError),
    /// The download buffer is smaller than the requested download.
    BufferTooSmall {
        /// Size of the download buffer.
        size: usize,
        /// Size of the requested download.
        needed: usize,
    },
    /// The CRC32 of the downloaded data doesn't match the expected value.
    CrcMismatch {
        /// The expected CRC32.
        expected: u32,
        /// The computed CRC32.
        actual: u32,
    },
    /// The CRC32 of the data to flash doesn't match the expected value.
    ChecksumMismatch {
        /// The expected CRC32.
        expected: u32,
        /// The computed CRC32.
        actual: u32,
    },
    /// Slotted partitions have different sizes.
    ///
    /// Partition names aren't reported because that would require a larger buffer at every site.
    /// The caller usually knows which partition hit the problem since they just issued the command.
    PartitionSizeMismatch(u64, u64),
    /// Failed to verify the given vbmeta partition.
    ///
    /// Partition names are reported without the slot suffix to avoid a string buffer; the caller
    /// knows the slot since they just issued the command.
    VbmetaVerifyFailed(&'static str),
    /// The given vbmeta partition is invalid. The slot suffix is omitted as above.
    VbmetaInvalid(&'static str),
    /// The fingerprint in the given vbmeta partition is too long. The slot suffix is omitted as
    /// above.
    FingerprintTooLong(&'static str),
}

/// Result type for GBL fastboot commands.
pub type CommandResult<T> = core::result::Result<T, GblFastbootError>;

impl Display for GblFastbootError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Msg(s) => f.write_str(s),
            Self::Libgbl(e) => write!(f, "{e}"),
            Self::Integration(e) => write!(f, "{e}"),
            Self::BootItemInit(e) => write!(f, "Failed to initialize boot item container {e}"),
            Self::LockState(e) => write!(f, "Failed to read lock state: {e}"),
            Self::LoadFailed(e) => write!(f, "Load didn't succeed: {e}"),
            Self::BufferTooSmall { size, needed } => {
                write!(f, "Buffer too small {size:#x}. Needs {needed:#x}")
            }
            Self::CrcMismatch { expected, actual } => {
                write!(f, "CRC check failed. expected: {expected:#x}, actual: {actual:#x}")
            }
            Self::ChecksumMismatch { expected, actual } => {
                write!(f, "Checksum mismatch: expected {expected:#x}, got {actual:#x}")
            }
            Self::PartitionSizeMismatch(a, b) => {
                write!(f, "Slotted partitions have different sizes: {a:#x} vs {b:#x}")
            }
            Self::VbmetaVerifyFailed(name) => write!(f, "Failed to verify {name}"),
            Self::VbmetaInvalid(name) => write!(f, "Invalid {name}"),
            Self::FingerprintTooLong(name) => write!(f, "Fingerprint in {name} too long"),
        }
    }
}

impl From<&'static str> for GblFastbootError {
    fn from(val: &'static str) -> Self {
        Self::Msg(val)
    }
}

/// Implements `From<T>` for each listed type by converting it into a [liberror::Error] wrapped in
/// [GblFastbootError::Libgbl].
macro_rules! from_gbl_error {
    ($($t:ty),* $(,)?) => {
        $(
            impl From<$t> for GblFastbootError {
                fn from(val: $t) -> Self {
                    Self::Libgbl(val.into())
                }
            }
        )*
    };
}

from_gbl_error!(
    Error,
    abr::Error,
    fastboot::Error,
    IoError,
    safemath::Error,
    core::num::TryFromIntError,
    core::str::Utf8Error,
);

impl From<IntegrationError> for GblFastbootError {
    fn from(val: IntegrationError) -> Self {
        Self::Integration(val)
    }
}

#[cfg(feature = "fuchsia")]
impl From<zbi::ZbiError> for GblFastbootError {
    fn from(val: zbi::ZbiError) -> Self {
        Self::Integration(val.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn display() {
        assert_eq!(GblFastbootError::from("msg").to_string(), "msg");
        assert_eq!(
            GblFastbootError::BufferTooSmall { size: 0x10, needed: 0x20 }.to_string(),
            "Buffer too small 0x10. Needs 0x20"
        );
        assert_eq!(
            GblFastbootError::BootItemInit(Error::NotFound).to_string(),
            format!("Failed to initialize boot item container {}", Error::NotFound)
        );
    }
}
