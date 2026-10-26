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

//! Routine for clearing memory containing confidential data, used by the open-dice library.

use core::{ffi::c_void, mem::MaybeUninit};
use zeroize::Zeroize;

/// Zeroes data over the provided address range & flushes data caches.
///
/// # Safety
///
/// The provided address and size must be for an address range that is valid for read and write
/// from a single allocation (e.g. stack array).
#[no_mangle]
unsafe extern "C" fn DiceClearMemory(_ctx: *mut c_void, size: usize, addr: *mut c_void) {
    if size == 0 || addr.is_null() {
        return;
    }
    let ptr = addr as *mut u8;
    {
        // SAFETY: As per function requirements, `addr` is non-null and valid for reads and writes
        // of `size` bytes from a single allocation. `MaybeUninit<u8>` has no initialization or
        // alignment requirements, so this is sound even if the C buffer is uninitialized.
        let buf = unsafe { core::slice::from_raw_parts_mut(ptr as *mut MaybeUninit<u8>, size) };
        buf.zeroize();
    }

    #[cfg(target_arch = "aarch64")]
    // SAFETY: All `size` bytes at `ptr` have just been initialized to zero, and the mutable `buf`
    // borrow ended with its scope above, so this shared slice doesn't overlap it.
    aarch64_cache_helper::flush_dcache_buffer(unsafe { core::slice::from_raw_parts(ptr, size) });
}
