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

//! C-visible wrappers for EFI based hash functions.

use crate::{
    hash2::{HashAlgorithm, Hasher, Sha256, Sha512},
    protocol::hash2::RawHasher,
    with_global_efi_entry,
};
use avb_bindgen::{avb_abort, EfiHasherStorage};
use core::{
    mem::size_of_val,
    ptr::{copy_nonoverlapping, null_mut, replace},
    slice::from_raw_parts,
};
use zerocopy::IntoBytes;

/// Panics unless `hasher` is non-null and aligned for `EfiHasherStorage`.
///
/// libavb passes `&ctx->impl.state.efi_hasher`, so a violation means memory corruption or API
/// misuse, which cannot be recovered from.
fn check_hasher(hasher: *const EfiHasherStorage) {
    assert!(!hasher.is_null(), "EFI hasher storage pointer is null");
    assert!(hasher.is_aligned(), "EFI hasher storage pointer is misaligned");
}

/// Initializes a detached [`RawHasher`] in `hasher` and returns `true` on success.
///
/// `RawHasher` stores four raw UEFI pointers (`device` + `interface` for the service-binding and
/// child protocols), which cannot use `zerocopy` byte serialization without stripping pointer
/// provenance. Instead, `EfiHasherStorage` holds `[*mut c_void; 4]` directly so Rust reads and
/// writes the exact bindgen `#[repr(C)]` type without cross-type pointer casts or `NonNull` niche
/// assumptions.
///
/// # Safety
///
/// * `hasher` must point to writable, properly aligned storage for `EfiHasherStorage`.
/// * In `#[cfg(test)]` builds, if `crate::GLOBAL_EFI_ENTRY` is `Some`, it must point to a valid
///   live `EfiEntry` (in production builds, `EFI_GLOBAL_ALLOCATOR` guarantees this automatically).
///
/// Panics if `hasher` is null or misaligned.
unsafe fn efi_sha_init<Algorithm: HashAlgorithm>(hasher: *mut EfiHasherStorage) -> bool {
    check_hasher(hasher);
    // SAFETY: In production builds, `EFI_GLOBAL_ALLOCATOR` yields an `&EfiEntry` only after
    // `efi::initialize` (whose caller proved `EfiEntry` validity) and before `exit_boot_services`,
    // returning `Err(Error::InvalidState)` otherwise. In `#[cfg(test)]` builds, validity of
    // `GLOBAL_EFI_ENTRY` is guaranteed by the function's test-only precondition.
    let raw =
        unsafe { with_global_efi_entry(|e| Hasher::<Algorithm>::new(e).map(Hasher::into_raw)) };
    if let Ok(raw) = raw.flatten() {
        // SAFETY: `check_hasher` verified `hasher` is non-null and aligned for
        // `EfiHasherStorage`, and by caller precondition `hasher` is valid for writes of
        // `EfiHasherStorage`. `ptr::write` initializes `*hasher` directly without reading prior
        // uninitialized bytes or casting between distinct pointee types.
        unsafe { hasher.write(EfiHasherStorage { opaque: raw.into_raw_ptrs() }) };
        true
    } else {
        false
    }
}

/// # Safety
///
/// * `hasher` must point to an `EfiHasherStorage` initialized by `efi_sha_init::<Algorithm>`
///   during the current boot services session and not yet finalized.
/// * `data` must be valid to read for `len` bytes whenever `len != 0`.
/// * In `#[cfg(test)]` builds, if `crate::GLOBAL_EFI_ENTRY` is `Some`, it must point to a valid
///   live `EfiEntry`.
///
/// Panics if `hasher` is null or misaligned, or if `data` is null while `len` is non-zero.
unsafe fn efi_sha_update<Algorithm: HashAlgorithm>(
    hasher: *mut EfiHasherStorage,
    data: *const u8,
    len: usize,
) {
    check_hasher(hasher);
    if len == 0 {
        // Nothing to hash. `data` may legitimately be null here, so don't build a slice from it.
        return;
    }
    assert!(!data.is_null(), "EFI hash input data pointer is null");

    // SAFETY: `check_hasher` verified `hasher` is non-null and aligned, and by caller precondition
    // `*hasher` was initialized by `efi_sha_init`.
    let ptrs = unsafe { (*hasher).opaque };

    // SAFETY:
    // * `with_global_efi_entry` is sound (see `efi_sha_init`).
    // * By caller precondition, `ptrs` came from `efi_sha_init::<Algorithm>` in the current boot
    //   services session and has not been finalized, and `data` is valid to read for `len` bytes.
    //
    // Errors (including `InvalidState` if boot services have exited) are ignored as before: a
    // failed update produces a digest mismatch, or `efi_sha_final` aborts if boot services exited.
    let _ = unsafe {
        with_global_efi_entry(|e| {
            if let Some(mut raw) = RawHasher::<Algorithm>::from_raw_ptrs(ptrs) {
                let _ = raw.update(e, from_raw_parts(data, len));
            }
        })
    };
}

/// # Safety
///
/// * `hasher` must point to an `EfiHasherStorage` initialized by `efi_sha_init::<Algorithm>`
///   during the current boot services session and not yet finalized.
/// * `out` must be valid to write for `core::mem::size_of::<Algorithm::DigestType>()` bytes.
/// * In `#[cfg(test)]` builds, if `crate::GLOBAL_EFI_ENTRY` is `Some`, it must point to a valid
///   live `EfiEntry`.
///
/// Panics if `hasher` is null or misaligned, or if `out` is null.
unsafe fn efi_sha_final<Algorithm: HashAlgorithm>(hasher: *mut EfiHasherStorage, out: *mut u8) {
    check_hasher(hasher);
    assert!(!out.is_null(), "EFI hash output pointer is null");

    // SAFETY:
    // * `check_hasher` verified `hasher` is non-null and aligned, and by caller precondition
    //   `*hasher` holds an initialized `EfiHasherStorage`, which we take and zero out so any
    //   accidental repeat call fails closed with `avb_abort()`.
    // * `with_global_efi_entry` is sound (see `efi_sha_init`), and `raw` came from
    //   `efi_sha_init::<Algorithm>` in the current boot services session.
    // * By caller precondition, `out` is valid to write for `size_of_val(&digest)` bytes and
    //   cannot overlap the stack-local `digest`.
    unsafe {
        let ptrs = replace(hasher, EfiHasherStorage { opaque: [null_mut(); 4] }).opaque;
        let Some(raw) = RawHasher::<Algorithm>::from_raw_ptrs(ptrs) else {
            avb_abort();
        };
        let Ok(digest) = with_global_efi_entry(|e| Hasher::from_raw(raw, e).finalize()).flatten()
        else {
            avb_abort();
        };
        copy_nonoverlapping(digest.as_bytes().as_ptr(), out, size_of_val(&digest));
    }
}

/// Initializes a `RawHasher<Sha256>` in-place in `hasher` and returns `true` on success.
/// Ownership of the hasher is passed to the caller.
///
/// # Safety
///
/// * `hasher` must point to writable, properly aligned storage for `EfiHasherStorage`.
/// * In `#[cfg(test)]` builds, if `crate::GLOBAL_EFI_ENTRY` is `Some`, it must point to a valid
///   live `EfiEntry`.
#[no_mangle]
pub unsafe extern "C" fn efi_sha256_init(hasher: *mut EfiHasherStorage) -> bool {
    // SAFETY: Guaranteed by caller preconditions.
    unsafe { efi_sha_init::<Sha256>(hasher) }
}

/// Adds data to an initialized SHA-256 `EfiHasherStorage` context.
///
/// # Safety
///
/// * `hasher` must point to an `EfiHasherStorage` initialized by [`efi_sha256_init`] during the
///   current boot services session and not yet finalized.
/// * `data` must be valid to read for `len` bytes whenever `len != 0`.
/// * In `#[cfg(test)]` builds, if `crate::GLOBAL_EFI_ENTRY` is `Some`, it must point to a valid
///   live `EfiEntry`.
#[no_mangle]
pub unsafe extern "C" fn efi_sha256_update(
    hasher: *mut EfiHasherStorage,
    data: *const u8,
    len: usize,
) {
    // SAFETY: Guaranteed by caller preconditions.
    unsafe { efi_sha_update::<Sha256>(hasher, data, len) }
}

/// Consumes an initialized SHA-256 `EfiHasherStorage` and writes its 32-byte digest to `out`.
///
/// # Safety
///
/// * `hasher` must point to an `EfiHasherStorage` initialized by [`efi_sha256_init`] during the
///   current boot services session and not yet finalized.
/// * `out` must be valid to write for 32 bytes.
/// * In `#[cfg(test)]` builds, if `crate::GLOBAL_EFI_ENTRY` is `Some`, it must point to a valid
///   live `EfiEntry`.
#[no_mangle]
pub unsafe extern "C" fn efi_sha256_final(hasher: *mut EfiHasherStorage, out: *mut u8) {
    // SAFETY: Guaranteed by caller preconditions.
    unsafe { efi_sha_final::<Sha256>(hasher, out) }
}

/// Initializes a `RawHasher<Sha512>` in-place in `hasher` and returns `true` on success.
/// Ownership of the hasher is passed to the caller.
///
/// # Safety
///
/// * `hasher` must point to writable, properly aligned storage for `EfiHasherStorage`.
/// * In `#[cfg(test)]` builds, if `crate::GLOBAL_EFI_ENTRY` is `Some`, it must point to a valid
///   live `EfiEntry`.
#[no_mangle]
pub unsafe extern "C" fn efi_sha512_init(hasher: *mut EfiHasherStorage) -> bool {
    // SAFETY: Guaranteed by caller preconditions.
    unsafe { efi_sha_init::<Sha512>(hasher) }
}

/// Adds data to an initialized SHA-512 `EfiHasherStorage` context.
///
/// # Safety
///
/// * `hasher` must point to an `EfiHasherStorage` initialized by [`efi_sha512_init`] during the
///   current boot services session and not yet finalized.
/// * `data` must be valid to read for `len` bytes whenever `len != 0`.
/// * In `#[cfg(test)]` builds, if `crate::GLOBAL_EFI_ENTRY` is `Some`, it must point to a valid
///   live `EfiEntry`.
#[no_mangle]
pub unsafe extern "C" fn efi_sha512_update(
    hasher: *mut EfiHasherStorage,
    data: *const u8,
    len: usize,
) {
    // SAFETY: Guaranteed by caller preconditions.
    unsafe { efi_sha_update::<Sha512>(hasher, data, len) }
}

/// Consumes an initialized SHA-512 `EfiHasherStorage` and writes its 64-byte digest to `out`.
///
/// # Safety
///
/// * `hasher` must point to an `EfiHasherStorage` initialized by [`efi_sha512_init`] during the
///   current boot services session and not yet finalized.
/// * `out` must be valid to write for 64 bytes.
/// * In `#[cfg(test)]` builds, if `crate::GLOBAL_EFI_ENTRY` is `Some`, it must point to a valid
///   live `EfiEntry`.
#[no_mangle]
pub unsafe extern "C" fn efi_sha512_final(hasher: *mut EfiHasherStorage, out: *mut u8) {
    // SAFETY: Guaranteed by caller preconditions.
    unsafe { efi_sha_final::<Sha512>(hasher, out) }
}

#[cfg(test)]
mod test {
    extern crate avb_sysdeps;

    use super::*;
    use crate::{
        hash2::HashAlgorithm,
        protocol::{
            hash2::test::{hash2_call_traces, hash_final, hash_init, hash_update},
            service_binding::test::{
                create_child, destroy_child, reinitialized_service_binding_call_traces,
                service_binding_call_traces,
            },
        },
        test::*,
        DeviceHandle, EfiEntry,
    };
    use efi_types::{EfiHash2Protocol, EfiServiceBindingProtocol, EFI_STATUS_SUCCESS};
    use std::collections::VecDeque;
    use zerocopy::{FromZeros, IntoBytes};

    const DATA: &str = "Well if it seems to be real, it's illusion.";

    struct HashTest {
        init: unsafe extern "C" fn(*mut EfiHasherStorage) -> bool,
        update: unsafe extern "C" fn(*mut EfiHasherStorage, *const u8, usize),
        r#final: unsafe extern "C" fn(*mut EfiHasherStorage, *mut u8),
    }

    fn efi_hash_wrapper_test<Algorithm: HashAlgorithm>(test_struct: HashTest) {
        run_test(|image_handle, systab_ptr| {
            let efi_entry = EfiEntry { image_handle, systab_ptr };
            let handles = [DeviceHandle(std::ptr::dangling())];

            let mut h2_sp = EfiServiceBindingProtocol {
                create_child: Some(create_child),
                destroy_child: Some(destroy_child),
            };

            let mut h2_p = EfiHash2Protocol {
                hash_init: Some(hash_init),
                hash_update: Some(hash_update),
                hash_final: Some(hash_final),
                ..Default::default()
            };

            efi_call_traces().with(|traces| {
                let mut traces = traces.borrow_mut();

                traces.locate_handle_trace.outputs = VecDeque::from([handles.into()]);

                traces.open_protocol_trace.outputs =
                    VecDeque::from([(as_efi_handle(&mut h2_sp), EFI_STATUS_SUCCESS)]);

                let interface = &mut h2_p as *mut _;
                traces.handle_protocol_trace.outputs.push_back(interface as *mut _);
            });

            reinitialized_service_binding_call_traces().with(|traces| {
                let mut traces = traces.borrow_mut();

                traces.create_child_trace.outputs =
                    VecDeque::from([(2 as *const _, EFI_STATUS_SUCCESS)]);
            });

            hash2_call_traces().with(|traces| {
                *traces.borrow_mut() = Default::default();
            });

            // Safety:
            // * `efi_entry` is valid for the duration of this test.
            crate::GLOBAL_EFI_ENTRY
                .with(|e| *e.borrow_mut() = Some(std::ptr::NonNull::from_ref(&efi_entry)));

            let mut hasher = EfiHasherStorage::default();
            let mut digest = Algorithm::DigestType::new_zeroed();
            // Safety:
            // * `hasher` is valid writable storage for `EfiHasherStorage`.
            // * `DATA` is valid to read for `DATA.len()`.
            // * `digest` is valid to write for `size_of::<Algorithm::DigestType>()`.
            // * It is the caller's responsibility to match the correct
            //   HashAlgorithm type, and init, update, and final values.
            unsafe {
                assert!((test_struct.init)(&mut hasher));
                service_binding_call_traces().with(|traces| {
                    assert!(traces.borrow().destroy_child_trace.inputs.is_empty());
                });
                (test_struct.update)(&mut hasher, DATA.as_bytes().as_ptr(), DATA.len());
                (test_struct.r#final)(&mut hasher, digest.as_mut_bytes().as_mut_ptr());
            }

            crate::GLOBAL_EFI_ENTRY.with(|e| *e.borrow_mut() = None);

            hash2_call_traces().with(|traces| {
                let traces = traces.borrow();
                assert_eq!(traces.init.call_count, 1);
                assert_eq!(traces.update.call_count, 1);
                assert_eq!(traces.r#final.call_count, 1);
            });
            service_binding_call_traces().with(|traces| {
                assert_eq!(
                    traces.borrow().destroy_child_trace.inputs,
                    VecDeque::from([2 as *const _])
                );
            });
        });
    }

    #[test]
    fn test_efi_wrapper_sha256() {
        efi_hash_wrapper_test::<Sha256>(HashTest {
            init: efi_sha256_init,
            update: efi_sha256_update,
            r#final: efi_sha256_final,
        })
    }

    #[test]
    fn test_efi_wrapper_sha512() {
        efi_hash_wrapper_test::<Sha512>(HashTest {
            init: efi_sha512_init,
            update: efi_sha512_update,
            r#final: efi_sha512_final,
        })
    }

    // The checks below call the Rust-ABI helpers directly: a panic cannot unwind out of the
    // `extern "C"` wrappers, so `should_panic` tests through them would abort the test binary.

    #[test]
    #[should_panic(expected = "EFI hasher storage pointer is null")]
    fn test_efi_sha256_init_null_hasher_panics() {
        // Safety: the null pointer is rejected before any dereference.
        unsafe { efi_sha_init::<Sha256>(core::ptr::null_mut()) };
    }

    #[test]
    #[should_panic(expected = "EFI hasher storage pointer is misaligned")]
    fn test_efi_sha512_init_misaligned_hasher_panics() {
        let mut storage = [EfiHasherStorage::default(), EfiHasherStorage::default()];
        let misaligned =
            storage.as_mut_ptr().cast::<u8>().wrapping_add(1).cast::<EfiHasherStorage>();
        // Safety: the misaligned pointer is rejected before any dereference.
        unsafe { efi_sha_init::<Sha512>(misaligned) };
    }

    #[test]
    #[should_panic(expected = "EFI hasher storage pointer is null")]
    fn test_efi_sha256_update_null_hasher_panics() {
        // Safety: the null pointer is rejected before any dereference.
        unsafe { efi_sha_update::<Sha256>(core::ptr::null_mut(), DATA.as_ptr(), DATA.len()) };
    }

    #[test]
    #[should_panic(expected = "EFI hash input data pointer is null")]
    fn test_efi_sha256_update_null_data_panics() {
        let mut hasher = EfiHasherStorage::default();
        // Safety: null `data` with a non-zero length is rejected before `hasher` is read.
        unsafe { efi_sha_update::<Sha256>(&mut hasher, core::ptr::null(), 1) };
    }

    #[test]
    fn test_efi_sha256_update_empty_null_data_is_noop() {
        let mut hasher = EfiHasherStorage::default();
        // Safety: an empty update returns before `hasher` or `data` is read.
        unsafe { efi_sha_update::<Sha256>(&mut hasher, core::ptr::null(), 0) };
    }

    #[test]
    #[should_panic(expected = "EFI hash output pointer is null")]
    fn test_efi_sha512_final_null_out_panics() {
        let mut hasher = EfiHasherStorage::default();
        // Safety: the null `out` is rejected before `hasher` is read.
        unsafe { efi_sha_final::<Sha512>(&mut hasher, core::ptr::null_mut()) };
    }

    #[test]
    fn test_efi_sha256_update_after_exit_boot_services_skips_protocol_call() {
        run_test(|image_handle, systab_ptr| {
            let efi_entry = EfiEntry { image_handle, systab_ptr };
            let handles = [DeviceHandle(std::ptr::dangling())];

            let mut h2_sp = EfiServiceBindingProtocol {
                create_child: Some(create_child),
                destroy_child: Some(destroy_child),
            };
            let mut h2_p = EfiHash2Protocol {
                hash_init: Some(hash_init),
                hash_update: Some(hash_update),
                hash_final: Some(hash_final),
                ..Default::default()
            };

            efi_call_traces().with(|traces| {
                let mut traces = traces.borrow_mut();
                traces.locate_handle_trace.outputs = VecDeque::from([handles.into()]);
                traces.open_protocol_trace.outputs =
                    VecDeque::from([(as_efi_handle(&mut h2_sp), EFI_STATUS_SUCCESS)]);
                traces.handle_protocol_trace.outputs.push_back((&mut h2_p as *mut _) as *mut _);
            });
            reinitialized_service_binding_call_traces().with(|traces| {
                traces.borrow_mut().create_child_trace.outputs =
                    VecDeque::from([(2 as *const _, EFI_STATUS_SUCCESS)]);
            });
            hash2_call_traces().with(|traces| *traces.borrow_mut() = Default::default());

            crate::GLOBAL_EFI_ENTRY
                .with(|e| *e.borrow_mut() = Some(std::ptr::NonNull::from_ref(&efi_entry)));

            let mut hasher = EfiHasherStorage::default();
            // SAFETY: `hasher` is valid writable storage for `EfiHasherStorage`.
            assert!(unsafe { efi_sha_init::<Sha256>(&mut hasher) });

            // Simulate `exit_boot_services()` clearing the active global `EfiEntry`.
            crate::GLOBAL_EFI_ENTRY.with(|e| *e.borrow_mut() = None);

            // SAFETY: `hasher` was initialized above and `DATA` is valid to read for `DATA.len()`.
            unsafe { efi_sha_update::<Sha256>(&mut hasher, DATA.as_ptr(), DATA.len()) };

            hash2_call_traces().with(|traces| {
                assert_eq!(traces.borrow().update.call_count, 0);
            });
        });
    }
}
