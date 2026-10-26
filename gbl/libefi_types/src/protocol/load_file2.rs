// Copyright 2026, The Android Open Source Project
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

//! Rust trait and bridge for
//! [`EFI_LOAD_FILE2_PROTOCOL`](https://uefi.org/specs/UEFI/2.11/13_Protocols_Media_Access.html#efi-load-file-2-protocol).

use crate::{
    defs::{
        EfiDevicePathProtocol, EfiGuid, EfiLoadFile2Protocol, EfiStatus,
        EFI_STATUS_INVALID_PARAMETER, EFI_STATUS_UNSUPPORTED,
    },
    protocol::{BridgeToRust, Provider},
    status::{EfiError, EfiResult},
    Identified,
};
use core::{mem::MaybeUninit, ops::Not};

impl Identified for EfiLoadFile2Protocol {
    const GUID: EfiGuid = EfiGuid::from_u64s(
        crate::defs::EFI_LOAD_FILE2_PROTOCOL_GUID_U64_0,
        crate::defs::EFI_LOAD_FILE2_PROTOCOL_GUID_U64_1,
    );
}

/// Protocol Rust API for `EFI_LOAD_FILE2_PROTOCOL`.
#[cfg_attr(feature = "mocks", mockall::automock)]
pub trait LoadFile2 {
    /// Loads a file.
    ///
    /// Returns:
    /// * `Ok(bytes_written)` if `buffer` is sufficiently large.
    /// * `Err(EfiError::BufferTooSmall(required_size))` otherwise.
    fn load_file<'a, 'b>(
        &self,
        file_path: Option<&'a EfiDevicePathProtocol>,
        buffer: Option<&'b mut [MaybeUninit<u8>]>,
    ) -> EfiResult<usize>;
}

// SAFETY: Provided function pointers use the EFI calling convention, have static lifetime and
// adhere to the protocol spec.
unsafe impl<R: LoadFile2> BridgeToRust<R> for EfiLoadFile2Protocol {
    unsafe fn create_bridge(_rust_impl: &R) -> Self {
        Self { load_file: Some(Provider::<_, R>::load_file) }
    }
}

impl<R: LoadFile2> Provider<'_, EfiLoadFile2Protocol, R> {
    /// # Safety
    ///
    /// * `this` must point to an `EfiLoadFile2Protocol` instance and non-null.
    /// * `file_path` must point to an `EfiDevicePathProtocol` if non-null.
    /// * `buffer_size` must point to a writable `usize` if non-null.
    /// * `buffer` must point to a writable buffer of at least `*buffer_size` bytes if non-null.
    unsafe extern "efiapi" fn load_file(
        this: *mut EfiLoadFile2Protocol,
        file_path: *mut EfiDevicePathProtocol,
        boot_policy: bool,
        buffer_size: *mut usize,
        buffer: *mut core::ffi::c_void,
    ) -> EfiStatus {
        if boot_policy {
            return EFI_STATUS_UNSUPPORTED;
        }
        // SAFETY: `buffer_size` points to an `usize` if non-null.
        let Some(buffer_size) = (unsafe { buffer_size.as_mut() }) else {
            return EFI_STATUS_INVALID_PARAMETER;
        };
        // SAFETY: `this` is the C interface pointer of `EfiLoadFile2Protocol`.
        let rust_impl = unsafe { Self::to_rust(this) };
        // SAFETY: `file_path` points to an `EfiDevicePathProtocol` if non-null.
        let file_path = unsafe { file_path.as_ref() };
        let buffer_slice = buffer.is_null().not().then(|| {
            // SAFETY: `buffer` is non-null and points to a writable buffer of size `*buffer_size`.
            unsafe { core::slice::from_raw_parts_mut(buffer as *mut MaybeUninit<u8>, *buffer_size) }
        });

        let res = rust_impl.load_file(file_path, buffer_slice);
        match res {
            Ok(bytes_written) => *buffer_size = bytes_written,
            Err(EfiError::BufferTooSmall(required)) => *buffer_size = required,
            _ => {}
        }
        res.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defs::{EFI_STATUS_BUFFER_TOO_SMALL, EFI_STATUS_SUCCESS};
    use crate::protocol::test::TestProtocolTunnel;
    use core::ptr::null_mut;

    #[test]
    fn test_load_file_boot_policy_unsupported() {
        let mock = MockLoadFile2::new();
        let tunnel = TestProtocolTunnel::new(&mock);
        let interface: &EfiLoadFile2Protocol = tunnel.client().interface();
        let mut size = 0;

        // SAFETY: `interface` is a `Client<EfiLoadFile2Protocol>` backed by `MockLoadFile2`.
        let status = unsafe {
            interface.load_file.unwrap()(
                interface as *const _ as *mut _,
                null_mut(),
                true,
                &mut size,
                null_mut(),
            )
        };

        assert_eq!(status, EFI_STATUS_UNSUPPORTED);
    }

    #[test]
    fn test_load_file_null_buffer_size_invalid_parameter() {
        let mock = MockLoadFile2::new();
        let tunnel = TestProtocolTunnel::new(&mock);
        let interface: &EfiLoadFile2Protocol = tunnel.client().interface();

        // SAFETY: `interface` is a `Client<EfiLoadFile2Protocol>` backed by `MockLoadFile2`.
        let status = unsafe {
            interface.load_file.unwrap()(
                interface as *const _ as *mut _,
                null_mut(),
                false,
                null_mut(),
                null_mut(),
            )
        };

        assert_eq!(status, EFI_STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn test_load_file_null_buffer_too_small_and_updates_size() {
        let mut mock = MockLoadFile2::new();
        mock.expect_load_file().returning(|_, _| Err(EfiError::BufferTooSmall(123)));

        let tunnel = TestProtocolTunnel::new(&mock);
        let interface: &EfiLoadFile2Protocol = tunnel.client().interface();
        let mut size = 0;

        // SAFETY: `interface` is a `Client<EfiLoadFile2Protocol>` backed by `MockLoadFile2`.
        let status = unsafe {
            interface.load_file.unwrap()(
                interface as *const _ as *mut _,
                null_mut(),
                false,
                &mut size,
                null_mut(),
            )
        };

        assert_eq!(status, EFI_STATUS_BUFFER_TOO_SMALL);
        assert_eq!(size, 123);
    }

    #[test]
    fn test_load_file_success() {
        let mut mock = MockLoadFile2::new();
        mock.expect_load_file().returning(|_, buffer| {
            let buf = buffer.unwrap();
            for (d, &s) in buf.iter_mut().zip(b"hello") {
                d.write(s);
            }
            Ok(5)
        });

        let tunnel = TestProtocolTunnel::new(&mock);
        let interface: &EfiLoadFile2Protocol = tunnel.client().interface();
        let mut buffer = vec![0u8; 20];
        let mut size = buffer.len();

        // SAFETY: `interface` is a `Client<EfiLoadFile2Protocol>` backed by `MockLoadFile2`.
        let status = unsafe {
            interface.load_file.unwrap()(
                interface as *const _ as *mut _,
                null_mut(),
                false,
                &mut size,
                buffer.as_mut_ptr() as *mut _,
            )
        };

        assert_eq!(status, EFI_STATUS_SUCCESS);
        assert_eq!(size, 5);
        assert_eq!(&buffer[..5], b"hello");
    }
}
