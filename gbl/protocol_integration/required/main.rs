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

//! Driver application for integration tests.

#![no_std]
#![no_main]

use efi::{
    efi_global_allocator, efi_println, initialize, report_error_and_reset_with_global_entry,
    utils::wait,
};
use efi_types::{
    EfiHandle, EfiStatus, EfiSystemTable, EFI_STATUS_INVALID_PARAMETER, EFI_STATUS_PROTOCOL_ERROR,
    EFI_STATUS_SUCCESS, GBL_EFI_DEBUG_ERROR_TAG_ASSERTION_ERROR,
};
use gbl_async::block_on;
use libprotocol_test::test_all_required_protocols;

#[panic_handler]
fn handle_panic(p_info: &core::panic::PanicInfo) -> ! {
    // Safety:
    // * The very first thing the application does is initialize the global EFI entry.
    unsafe {
        report_error_and_reset_with_global_entry(p_info, GBL_EFI_DEBUG_ERROR_TAG_ASSERTION_ERROR)
    }
}

efi_global_allocator!();

/// Driver for the integration test application
///
/// # Safety
///
/// * It is the responsibility of the UEFI firmware to pass valid, non null
///   `image_handle` and `systab_ptr` parameters.
#[no_mangle]
pub unsafe extern "C" fn efi_main(
    image_handle: EfiHandle,
    systab_ptr: *mut EfiSystemTable,
) -> EfiStatus {
    // SAFETY:
    // * caller provides valid `image_handle` and `systab_ptr` objects
    // * we only call `initialize()` once
    let Ok(entry) = (unsafe { initialize(image_handle, systab_ptr) }) else {
        // Can't panic, can't log. Just return.
        return EFI_STATUS_INVALID_PARAMETER;
    };
    efi_println!(&entry, "Running GBL UEFI integration test for required protocols");

    let res = test_all_required_protocols(&entry)
        .inspect_err(|_| efi_println!(&entry, "REQUIRED TEST FAILED"));

    // Pause to let the runner verify console output.
    let _ = block_on(wait(&entry, core::time::Duration::from_secs(5)));

    if res.is_ok() {
        EFI_STATUS_SUCCESS
    } else {
        EFI_STATUS_PROTOCOL_ERROR
    }
}
