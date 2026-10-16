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

//! Contains API for tracing in GBL.

#![cfg_attr(not(test), no_std)]

#[cfg(feature = "gbl_tracing")]
unsafe extern "C" {
    // The following are system wide APIs to be implemented by backend.

    /// Enables or disables GBL tracing.
    pub safe fn gbl_trace_set_enable(enable: bool);

    /// Returns whether GBL tracing is enabled.
    pub safe fn gbl_trace_get_enable() -> bool;

    /// Adds a heap snapshot trace.
    ///
    /// # Args:
    ///
    /// * total: Total amount of heap usage.
    pub safe fn gbl_trace_add_heap_snapshot(total: usize);

    /// Leaks and returns trace buffer to caller.
    ///
    /// Implemented by the backend, e.g. `efi/arch/aarch64/mcount.c`, where `efi_main_tracing`
    /// allocates the buffer before GBL starts. The backend writes NULL to `out` if tracing was never
    /// set up or the buffer was already taken. After handing off the buffer, it stops writing to it.
    /// The mcount backend resets the device if called off the GBL main stack.
    ///
    /// # Args:
    ///
    /// `out`: output pointer for the buffer.
    /// `out_buffer_size`: output pointer for the buffer size.
    /// `out_data_size`: output pointer for actual trace data size.
    ///
    /// # Safety
    ///
    /// * Caller must guarantee that all pointers point to valid memory and outlives the call.
    unsafe fn _gbl_trace_take_buffer(
        out: *mut *mut u8,
        out_buffer_size: *mut usize,
        out_data_size: *mut usize,
    );
}

/// Leaks and return trace buffer.
///
/// # Returns
///
/// * Returns `Some((<buffer>, <data size>))` if trace buffer is available.
/// * Returns `None` otherwise.
#[cfg(feature = "gbl_tracing")]
pub fn gbl_trace_take_buffer() -> Option<(&'static mut [u8], usize)> {
    use core::slice::from_raw_parts_mut;
    let mut out: *mut u8 = core::ptr::null_mut();
    let mut buffer_size = 0;
    let mut data_size = 0;
    // SAFETY:
    // * `out`, `out_buffer_size` and `out_data_size` are valid memories and outlive the call.
    unsafe { _gbl_trace_take_buffer(&mut out, &mut buffer_size, &mut data_size) };
    if out.is_null() {
        return None;
    }
    // SAFETY: `_gbl_trace_take_buffer` (see `efi/arch/aarch64/mcount.c`) returns a buffer of
    // `buffer_size` bytes with `data_size` initialized bytes, then points its global state at an
    // empty placeholder before returning. GBL is single-core, and UEFI event callbacks that preempt
    // it only see the placeholder from then on, so nothing else accesses the buffer and it is safe
    // to treat as `'static` and exclusively ours. Zero-initialize the remaining tail before
    // materializing `&'static mut [u8]`.
    unsafe {
        if data_size < buffer_size {
            core::ptr::write_bytes(out.add(data_size), 0, buffer_size - data_size);
        }
        Some((from_raw_parts_mut(out, buffer_size), data_size))
    }
}

#[cfg(not(feature = "gbl_tracing"))]
mod placeholder {
    /// Placeholder
    pub fn gbl_trace_set_enable(_: bool) {}

    /// Placeholder
    pub fn gbl_trace_get_enable() -> bool {
        false
    }

    /// Placeholder
    pub fn gbl_trace_add_heap_snapshot(_: usize) {}

    /// Placeholder
    pub fn gbl_trace_take_buffer() -> Option<(&'static mut [u8], usize)> {
        None
    }
}

#[cfg(not(feature = "gbl_tracing"))]
pub use placeholder::*;

/// A helper class to temporarily change the trace config and restore it on drop.
pub struct TraceGuard(bool);

impl TraceGuard {
    /// Creates a new instance.
    // Always inline to avoid generating too many traces.
    #[inline(always)]
    pub fn new(config: bool) -> Self {
        let orig = gbl_trace_get_enable();
        gbl_trace_set_enable(config);
        Self(orig)
    }
}

impl Drop for TraceGuard {
    // Always inline drop function to avoid generating too many traces.
    #[inline(always)]
    fn drop(&mut self) {
        gbl_trace_set_enable(self.0)
    }
}
