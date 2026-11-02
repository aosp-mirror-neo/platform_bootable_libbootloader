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

//! C-visible wrappers for EFI based RNG functions.

#![cfg_attr(not(test), no_std)]

use core::slice::from_raw_parts_mut;
use efi::{
    protocol::random_number_generator::{get_rng_bytes, RngAlgorithm},
    with_global_efi_entry,
};

/// Maximum byte length accepted by POSIX.1-2024 / OpenBSD `getentropy(2)`.
const GETENTROPY_MAX: usize = 256;

/// Implementation of getentropy(2) for UEFI environment using EFI_RNG_PROTOCOL.
///
/// Returns `0` on success, or `-1` on error (including if `buffer` is null or
/// `length > GETENTROPY_MAX`, matching POSIX.1-2024 / OpenBSD `getentropy(2)`).
///
/// # Safety
///
/// * If `buffer` is non-null and `0 < length <= GETENTROPY_MAX`, `buffer` must be valid for writes
///   of `length` bytes.
/// * It is the responsibility of initialization code to guarantee that the
///   global efi entry is valid.
#[no_mangle]
pub unsafe extern "C" fn getentropy(buffer: *mut u8, length: usize) -> core::ffi::c_int {
    if buffer.is_null() || length > GETENTROPY_MAX {
        return -1;
    }
    // UEFI GetRng rejects 0-byte requests, whereas POSIX getentropy succeeds.
    if length == 0 {
        return 0;
    }

    // Safety: `buffer` is valid for `length` bytes per function safety contract. Zero-initialize
    // first so `from_raw_parts_mut` never materializes `&mut [u8]` over uninitialized C memory.
    let mut buf = unsafe {
        core::ptr::write_bytes(buffer, 0, length);
        from_raw_parts_mut(buffer, length)
    };
    // Safety:
    // * It is the responsibility of initialization code to guarantee that the
    //   global efi entry is valid.
    let res =
        unsafe { with_global_efi_entry(|e| get_rng_bytes(e, RngAlgorithm::Default, &mut buf)) };

    if matches!(res, Ok(Ok(()))) {
        0
    } else {
        -1
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::{cell::Cell, ffi::c_void, ptr::null_mut};
    use efi::{initialize, EfiAllocator};
    use efi_types::{
        EfiBootService, EfiGuid, EfiHandle, EfiLocateHandleSearchType, EfiOpenProtocolAttributes,
        EfiRngProtocol, EfiSimpleTextOutputProtocol, EfiStatus, EfiSystemTable,
        EFI_STATUS_DEVICE_ERROR, EFI_STATUS_INVALID_PARAMETER, EFI_STATUS_NOT_FOUND,
        EFI_STATUS_SUCCESS, EFI_STATUS_UNSUPPORTED,
    };
    use std::sync::OnceLock;

    // Defines `libefi`'s extern `EFI_GLOBAL_ALLOCATOR` symbol required by `efi::initialize()`
    // without `#[global_allocator]`, so host tests keep the `std` allocator.
    //
    // SAFETY: `EFI_GLOBAL_ALLOCATOR` does not collide with any other symbol in this test binary
    // and has the exact `EfiAllocator` type expected by `libefi`.
    #[unsafe(no_mangle)]
    static EFI_GLOBAL_ALLOCATOR: EfiAllocator = EfiAllocator::new();

    // Arbitrary non-zero fill byte for mock RNG output; exact value does not matter.
    const MOCK_RNG_BYTE: u8 = 0x3C;

    #[derive(Copy, Clone)]
    enum MockRngMode {
        MissingProtocol,
        RngDeviceError,
        Success(u8),
    }

    thread_local! {
        static MOCK_MODE: Cell<MockRngMode> = const { Cell::new(MockRngMode::MissingProtocol) };
    }

    /// Mock of `EFI_RNG_PROTOCOL.GetRng` for unit tests.
    ///
    /// # Safety
    ///
    /// If `out` is non-null and `length > 0`, `out` must be valid for writes of `length` bytes.
    unsafe extern "efiapi" fn mock_get_rng(
        _: *mut EfiRngProtocol,
        algorithm: *const EfiGuid,
        length: usize,
        out: *mut u8,
    ) -> EfiStatus {
        if !algorithm.is_null() {
            return EFI_STATUS_UNSUPPORTED;
        }
        if out.is_null() || length == 0 {
            return EFI_STATUS_INVALID_PARAMETER;
        }
        match MOCK_MODE.get() {
            MockRngMode::MissingProtocol => EFI_STATUS_NOT_FOUND,
            MockRngMode::RngDeviceError => EFI_STATUS_DEVICE_ERROR,
            MockRngMode::Success(byte) => {
                // SAFETY: `out` is non-null with `length > 0`, so per function safety requirements
                // `out` is valid for writes of `length` bytes (and `u8` has alignment 1).
                unsafe { core::ptr::write_bytes(out, byte, length) };
                EFI_STATUS_SUCCESS
            }
        }
    }

    static RNG_PROTO: EfiRngProtocol =
        EfiRngProtocol { get_info: None, get_rng: Some(mock_get_rng) };

    /// Mock of `EFI_BOOT_SERVICES.LocateHandle` for unit tests.
    ///
    /// # Safety
    ///
    /// When `MOCK_MODE` is not `MissingProtocol`, non-null `buffer_size` and `buf` must be aligned
    /// and writable for one `usize` and one `EfiHandle`, respectively.
    unsafe extern "efiapi" fn mock_locate_handle(
        _: EfiLocateHandleSearchType,
        _: *const EfiGuid,
        _: *const c_void,
        buffer_size: *mut usize,
        buf: *mut EfiHandle,
    ) -> EfiStatus {
        if matches!(MOCK_MODE.get(), MockRngMode::MissingProtocol) {
            return EFI_STATUS_NOT_FOUND;
        }
        if buffer_size.is_null() || buf.is_null() {
            return EFI_STATUS_INVALID_PARAMETER;
        }
        // SAFETY: `buffer_size` and `buf` are non-null, and per function safety requirements are
        // aligned and writable.
        unsafe {
            *buffer_size = 1;
            *buf = 1usize as EfiHandle;
        }
        EFI_STATUS_SUCCESS
    }

    /// Mock of `EFI_BOOT_SERVICES.OpenProtocol` for unit tests.
    ///
    /// # Safety
    ///
    /// If `intf` is non-null, it must be aligned and writable for a `*const c_void`.
    unsafe extern "efiapi" fn mock_open_protocol(
        _: EfiHandle,
        _: *const EfiGuid,
        intf: *mut *const c_void,
        _: EfiHandle,
        _: EfiHandle,
        _: EfiOpenProtocolAttributes,
    ) -> EfiStatus {
        if intf.is_null() {
            return EFI_STATUS_INVALID_PARAMETER;
        }
        // SAFETY: `intf` is non-null, per function safety requirements is aligned and writable,
        // and `RNG_PROTO` is `'static`.
        unsafe {
            *intf = &raw const RNG_PROTO as *const c_void;
        }
        EFI_STATUS_SUCCESS
    }

    /// No-op mock of `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.OutputString` for unit tests.
    extern "efiapi" fn mock_output_string(
        _: *mut EfiSimpleTextOutputProtocol,
        _: *mut u16,
    ) -> EfiStatus {
        EFI_STATUS_SUCCESS
    }

    fn call_getentropy(buf: &mut [u8]) -> core::ffi::c_int {
        // SAFETY: `buf` points to `buf.len()` valid writable bytes.
        unsafe { getentropy(buf.as_mut_ptr(), buf.len()) }
    }

    fn call_getentropy_null(len: usize) -> core::ffi::c_int {
        // SAFETY: `getentropy` allows a null `buffer` and returns `-1` without dereferencing it.
        unsafe { getentropy(null_mut(), len) }
    }

    /// Lazily initializes the process-wide global `EfiEntry` once (capturing the pre-init
    /// `getentropy` result before `efi::initialize` runs so parallel tests cannot race with it).
    fn ensure_mock_efi_initialized() -> (core::ffi::c_int, [u8; 8]) {
        static PRE_INIT_RESULT: OnceLock<(core::ffi::c_int, [u8; 8])> = OnceLock::new();
        *PRE_INIT_RESULT.get_or_init(|| {
            let mut pre_init_buf = [MOCK_RNG_BYTE; 8];
            let pre_init_rc = call_getentropy(&mut pre_init_buf);

            let con_out = Box::leak(Box::new(EfiSimpleTextOutputProtocol {
                output_string: Some(mock_output_string),
                ..Default::default()
            }));
            let boot_services = Box::leak(Box::new(EfiBootService {
                locate_handle: Some(mock_locate_handle),
                open_protocol: Some(mock_open_protocol),
                ..Default::default()
            }));
            let system_table = Box::leak(Box::new(EfiSystemTable {
                con_out: con_out as *mut _,
                boot_services: boot_services as *mut _,
                ..Default::default()
            }));

            // SAFETY: Called once in this test binary with `'static` system_table and
            // boot_services.
            let _ = unsafe { initialize(1usize as EfiHandle, system_table as *const _) }.unwrap();
            (pre_init_rc, pre_init_buf)
        })
    }

    /// Ensures the global `EfiEntry` is initialized and sets the current thread's [`MockRngMode`].
    fn set_mock_mode(mode: MockRngMode) {
        let _ = ensure_mock_efi_initialized();
        MOCK_MODE.set(mode);
    }

    #[test]
    fn test_getentropy_before_init() {
        let (rc, buf) = ensure_mock_efi_initialized();
        assert_eq!(rc, -1);
        assert_eq!(buf, [0u8; 8]);
    }

    #[test]
    fn test_getentropy_null_buffer() {
        assert_eq!(call_getentropy_null(8), -1);
        assert_eq!(call_getentropy_null(0), -1);
    }

    #[test]
    fn test_getentropy_zero_length() {
        set_mock_mode(MockRngMode::Success(MOCK_RNG_BYTE));
        let mut buf = [0u8; 8];
        assert_eq!(call_getentropy(&mut buf[..0]), 0);
        assert_eq!(buf, [0u8; 8]);
    }

    #[test]
    fn test_getentropy_missing_protocol() {
        set_mock_mode(MockRngMode::MissingProtocol);
        let mut buf = [0u8; 8];
        assert_eq!(call_getentropy(&mut buf), -1);
        assert_eq!(buf, [0u8; 8]);
    }

    #[test]
    fn test_getentropy_device_error() {
        set_mock_mode(MockRngMode::RngDeviceError);
        let mut buf = [0u8; 8];
        assert_eq!(call_getentropy(&mut buf), -1);
        assert_eq!(buf, [0u8; 8]);
    }

    #[test]
    fn test_getentropy_success() {
        set_mock_mode(MockRngMode::Success(MOCK_RNG_BYTE));
        let mut buf = [0u8; 8];
        assert_eq!(call_getentropy(&mut buf), 0);
        assert_eq!(buf, [MOCK_RNG_BYTE; 8]);
    }

    #[test]
    fn test_getentropy_max_length_boundary() {
        set_mock_mode(MockRngMode::Success(MOCK_RNG_BYTE));
        let mut max_buf = [0u8; GETENTROPY_MAX + 1];
        assert_eq!(call_getentropy(&mut max_buf[..GETENTROPY_MAX]), 0);
        assert_eq!(&max_buf[..GETENTROPY_MAX], &[MOCK_RNG_BYTE; GETENTROPY_MAX]);
        assert_eq!(max_buf[GETENTROPY_MAX], 0);
    }

    #[test]
    fn test_getentropy_exceeds_max_length() {
        set_mock_mode(MockRngMode::Success(MOCK_RNG_BYTE));
        let mut max_buf = [0u8; GETENTROPY_MAX + 1];
        assert_eq!(call_getentropy(&mut max_buf), -1);
        assert_eq!(max_buf, [0u8; GETENTROPY_MAX + 1]);
    }
}
