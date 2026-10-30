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

//! Rust wrapper for `EFI_HASH2_PROTOCOL`.
//!
//! Provides the `hash` function for hashing a contiguous chunk of data,
//! the `Hasher` struct for hashing incrementally, and definitions for the
//! Sha1, Sha256, and Sha512 hash algorithms.

use crate::{
    efi_call,
    protocol::{
        service_binding::{ProtocolBinder, ServiceBindingProtocolInfo},
        MaybeVersioned, Protocol, ProtocolInfo, Requirement,
    },
    EfiEntry,
};
use core::marker::PhantomData;
use efi_types::{
    EfiGuid, EfiHash2Output, EfiHash2Protocol, EfiSha1Hash2, EfiSha256Hash2, EfiSha512Hash2,
    EFI_HASH2_PROTOCOL_GUID_U64_0, EFI_HASH2_PROTOCOL_GUID_U64_1,
    EFI_HASH2_SERVICE_BINDING_PROTOCOL_GUID_U64_0, EFI_HASH2_SERVICE_BINDING_PROTOCOL_GUID_U64_1,
    EFI_HASH_ALGORITHM_SHA1_GUID_U64_0, EFI_HASH_ALGORITHM_SHA1_GUID_U64_1,
    EFI_HASH_ALGORITHM_SHA256_GUID_U64_0, EFI_HASH_ALGORITHM_SHA256_GUID_U64_1,
    EFI_HASH_ALGORITHM_SHA512_GUID_U64_0, EFI_HASH_ALGORITHM_SHA512_GUID_U64_1,
};
use liberror::Result;
use zerocopy::{FromBytes, Immutable, IntoBytes};

impl MaybeVersioned for EfiHash2Protocol {}

/// Definition for a hash algorithm used by the EfiHash2Protocol.
///
/// # Safety
///
/// * It is the implementor's responsibility to guarantee that `Self::Output`
///   is the correct output type for the hash algorthm.
/// * It is the implementor's responsibility to guarantee that `Self::digest`
///   returns the correct field from EfiHash2Output.
///
/// Note: the HashAlgorithm trait is sealed. Callers cannot implement it themselves.
pub unsafe trait HashAlgorithm: private::Sealed {
    /// The GUID used to reference the algorithm.
    const GUID: EfiGuid;

    /// The type of the digest.
    type DigestType: IntoBytes + FromBytes + Immutable + Eq;

    /// Access the relevant hash digest field in a `EfiHash2Output` union.
    ///
    /// # Safety
    ///
    /// * It is the caller's responsibility to guarantee that `output` has been initialized with the
    ///   appropriate union member.
    unsafe fn digest(output: EfiHash2Output) -> Self::DigestType;
}

mod private {
    pub trait Sealed {}
}

/// Wrapper for `Sha1`.
#[derive(Debug)]
pub struct Sha1;

impl private::Sealed for Sha1 {}

/// SAFETY:
/// * `sha1_hash` is the correct field to access for a message of type Sha1.
unsafe impl HashAlgorithm for Sha1 {
    const GUID: EfiGuid =
        EfiGuid::from_u64s(EFI_HASH_ALGORITHM_SHA1_GUID_U64_0, EFI_HASH_ALGORITHM_SHA1_GUID_U64_1);

    type DigestType = EfiSha1Hash2;

    /// SAFETY:
    /// * Caller is required to verify that `sha1_hash` is the active field of `output`.
    unsafe fn digest(output: EfiHash2Output) -> Self::DigestType {
        // SAFETY: The caller guarantees that `sha1_hash` is the active field of `output`.
        unsafe { output.sha1_hash }
    }
}

/// Wrapper for `Sha256`.
#[derive(Debug)]
pub struct Sha256;

impl private::Sealed for Sha256 {}

/// SAFETY:
/// * `sha256_hash` is the correct field to access for a message of type Sha256.
unsafe impl HashAlgorithm for Sha256 {
    const GUID: EfiGuid = EfiGuid::from_u64s(
        EFI_HASH_ALGORITHM_SHA256_GUID_U64_0,
        EFI_HASH_ALGORITHM_SHA256_GUID_U64_1,
    );

    type DigestType = EfiSha256Hash2;

    /// SAFETY:
    /// * Caller is required to verify that `sha256_hash` is the active field of `output`.
    unsafe fn digest(output: EfiHash2Output) -> Self::DigestType {
        // SAFETY: The caller guarantees that `sha256_hash` is the active field of `output`.
        unsafe { output.sha256_hash }
    }
}

/// Wrapper for `Sha512`.
#[derive(Debug)]
pub struct Sha512;

impl private::Sealed for Sha512 {}

/// SAFETY:
/// * `sha512_hash` is the correct field to access for a message of type Sha512.
unsafe impl HashAlgorithm for Sha512 {
    const GUID: EfiGuid = EfiGuid::from_u64s(
        EFI_HASH_ALGORITHM_SHA512_GUID_U64_0,
        EFI_HASH_ALGORITHM_SHA512_GUID_U64_1,
    );

    type DigestType = EfiSha512Hash2;

    /// SAFETY:
    /// * Caller is required to verify that `sha512_hash` is the active field of `output`.
    unsafe fn digest(output: EfiHash2Output) -> Self::DigestType {
        // SAFETY: The caller guarantees that `sha512_hash` is the active field of `output`.
        unsafe { output.sha512_hash }
    }
}

/// Note: the Hash2Protocol is not exported because
///       1) It must be created and destroyed via the ServiceBindingProtocol.
///       2) Its API requires manual coordination between initiating the hash
///          and accessing the correct field in the output union.
///
/// Callers should use the `hash` and `Hasher` interfaces instead.
struct Hash2Protocol;

impl ProtocolInfo for Hash2Protocol {
    type InterfaceType = EfiHash2Protocol;

    const GUID: EfiGuid =
        EfiGuid::from_u64s(EFI_HASH2_PROTOCOL_GUID_U64_0, EFI_HASH2_PROTOCOL_GUID_U64_1);

    const REQUIREMENT: Requirement = Requirement::Optional;
}

impl Protocol<'_, Hash2Protocol> {
    fn hash<H: HashAlgorithm>(&self, message: &[u8]) -> Result<EfiHash2Output> {
        let mut output = EfiHash2Output::default();
        // SAFETY:
        // `self.interface_ptr()` points to a valid object.
        // `self.interface_ptr()` is an input parameter and will not be retained. It outlives the call.
        // `message` is an input parameter and will not be retained. It outlives the call.
        // `output` is an output parameter and will not be retained. It outlives the call.
        unsafe {
            efi_call!(
                self.interface().hash,
                self.interface_ptr(),
                &H::GUID,
                message.as_ptr(),
                message.len(),
                &mut output
            )?;
        }
        Ok(output)
    }

    fn hash_init<H: HashAlgorithm>(&self) -> Result<()> {
        // SAFETY:
        // `self.interface_ptr()` points to a valid object.
        // `self.interface_ptr()` is an input parameter and will not be retained. It outlives the call.
        unsafe { efi_call!(self.interface().hash_init, self.interface_ptr(), &H::GUID) }
    }

    fn hash_update(&self, message: &[u8]) -> Result<()> {
        // SAFETY:
        // `self.interface_ptr()` points to a valid object.
        // `self.interface_ptr()` is an input parameter and will not be retained. It outlives the call.
        // `message` is an input parameter and will not be retained. It outlives the call.
        unsafe {
            efi_call!(
                self.interface().hash_update,
                self.interface_ptr(),
                message.as_ptr(),
                message.len()
            )
        }
    }

    fn hash_final(&self) -> Result<EfiHash2Output> {
        let mut output = EfiHash2Output::default();
        // SAFETY:
        // `self.interface_ptr()` points to a valid object.
        // `self.interface_ptr()` is an input parameter and will not be retained. It outlives the call.
        // `output` is an output parameter and will not be retained. It outlives the call.
        unsafe {
            efi_call!(self.interface().hash_final, self.interface_ptr(), &mut output)?;
        }
        Ok(output)
    }
}

// Service Binding Protocol used to create instances of the Hash2Protocol.
//
// See https://uefi.org/specs/UEFI/2.11/37_Secure_Technologies.html#efi-hash2-service-binding-protocol
// for more infformation.
struct Hash2ServiceBindingProtocol;

impl ServiceBindingProtocolInfo for Hash2ServiceBindingProtocol {
    const GUID: EfiGuid = EfiGuid::from_u64s(
        EFI_HASH2_SERVICE_BINDING_PROTOCOL_GUID_U64_0,
        EFI_HASH2_SERVICE_BINDING_PROTOCOL_GUID_U64_1,
    );

    type ChildProtocol = Hash2Protocol;
}

/// Hashes the message and returns the digest.
pub fn hash<H: HashAlgorithm>(entry: &EfiEntry, message: &[u8]) -> Result<H::DigestType> {
    ProtocolBinder::<Hash2ServiceBindingProtocol>::new(entry)?
        .child_protocol()
        .hash::<H>(message)
        // SAFETY:
        // * The hash method was just called with the corresponding algorithm,
        //   and the message digest union has been zero-initialized so all bytes are valid.
        // * It is the responsibility of `H::digest` to return the correct union field.
        .map(|d| unsafe { H::digest(d) })
}

/// Interface for incremental hashing.
pub struct Hasher<'a, H: HashAlgorithm> {
    binder: ProtocolBinder<'a, Hash2ServiceBindingProtocol>,
    phantom: PhantomData<H>,
}

impl<'a, H: HashAlgorithm> Hasher<'a, H> {
    /// Instantiates a new `Hasher`.
    pub fn new(entry: &'a EfiEntry) -> Result<Self> {
        let binder = ProtocolBinder::new(entry)?;
        binder.child_protocol().hash_init::<H>()?;

        Ok(Self { binder, phantom: PhantomData })
    }

    /// Incorporates `message` into the digest.
    pub fn update(&mut self, message: &[u8]) -> Result<()> {
        self.binder.child_protocol().hash_update(message)
    }

    /// Finalizes the hash and returns the digest.
    pub fn finalize(self) -> Result<H::DigestType> {
        // SAFETY:
        // * This protocol instance is under the control of the hasher.
        // * `self` has called `hash_init` with `H::GUID`.
        // * In `hash_final`, the digest is zero initialized, so all bytes are valid.
        // * It is the responsibility of `H::digest` to return the right union field.
        self.binder.child_protocol().hash_final().map(|d| unsafe { H::digest(d) })
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::protocol::hash2::Hash2ServiceBindingProtocol;
    use crate::protocol::{
        service_binding::test::{
            create_child, destroy_child, reinitialized_service_binding_call_traces,
            service_binding_call_traces,
        },
        ProtocolInfo,
    };
    use crate::test::*;
    use crate::DeviceHandle;
    use efi_types::{
        EfiGuid, EfiHash2Output, EfiHash2Protocol, EfiServiceBindingProtocol, EfiSha256Hash2,
        EfiStatus, EFI_STATUS_SUCCESS,
    };
    use std::{cell::RefCell, collections::VecDeque};

    #[derive(Default)]
    pub(crate) struct Hash2InitTrace {
        pub call_count: usize,
    }

    #[derive(Default)]
    pub(crate) struct Hash2UpdateTrace {
        pub call_count: usize,
    }

    #[derive(Default)]
    pub(crate) struct Hash2FinalTrace {
        pub call_count: usize,
    }

    #[derive(Default)]
    pub(crate) struct Hash2CallTraces {
        pub init: Hash2InitTrace,
        pub update: Hash2UpdateTrace,
        pub r#final: Hash2FinalTrace,
    }

    thread_local! {
        static HASH2_CALL_TRACES: RefCell<Hash2CallTraces> =
            RefCell::new(Default::default());
    }

    pub(crate) fn hash2_call_traces() -> &'static std::thread::LocalKey<RefCell<Hash2CallTraces>> {
        &HASH2_CALL_TRACES
    }

    pub(crate) extern "efiapi" fn hash_func(
        _: *const EfiHash2Protocol,
        _: *const EfiGuid,
        _: *const u8,
        _: usize,
        _: *mut EfiHash2Output,
    ) -> EfiStatus {
        EFI_STATUS_SUCCESS
    }

    pub(crate) extern "efiapi" fn hash_init(
        _: *const EfiHash2Protocol,
        _: *const EfiGuid,
    ) -> EfiStatus {
        hash2_call_traces().with(|traces| {
            traces.borrow_mut().init.call_count += 1;
        });
        EFI_STATUS_SUCCESS
    }

    pub(crate) extern "efiapi" fn hash_update(
        _: *const EfiHash2Protocol,
        _: *const u8,
        _: usize,
    ) -> EfiStatus {
        hash2_call_traces().with(|traces| {
            traces.borrow_mut().update.call_count += 1;
        });
        EFI_STATUS_SUCCESS
    }

    pub(crate) extern "efiapi" fn hash_final(
        _: *const EfiHash2Protocol,
        _: *mut EfiHash2Output,
    ) -> EfiStatus {
        hash2_call_traces().with(|traces| {
            traces.borrow_mut().r#final.call_count += 1;
        });
        EFI_STATUS_SUCCESS
    }

    #[test]
    fn test_hash() {
        run_test(|image_handle, systab_ptr| {
            let efi_entry = EfiEntry { image_handle, systab_ptr };
            let handles = [DeviceHandle(std::ptr::dangling())];

            let mut h2_sp = EfiServiceBindingProtocol {
                create_child: Some(create_child),
                destroy_child: Some(destroy_child),
            };

            let mut h2_p = EfiHash2Protocol { hash: Some(hash_func), ..Default::default() };

            efi_call_traces().with(|traces| {
                let mut traces = traces.borrow_mut();
                traces.locate_handle_trace.outputs = VecDeque::from([handles.into()]);

                traces.open_protocol_trace.outputs =
                    VecDeque::from([(as_efi_handle(&mut h2_sp), EFI_STATUS_SUCCESS)]);

                traces.handle_protocol_trace.outputs.push_back(&mut h2_p as *mut _ as *mut _);
            });

            reinitialized_service_binding_call_traces().with(|traces| {
                let mut traces = traces.borrow_mut();

                traces.create_child_trace.outputs =
                    VecDeque::from([(2 as *const _, EFI_STATUS_SUCCESS)]);
            });

            // New scope to trigger cleanup.
            {
                let digest = hash::<Sha256>(&efi_entry, &[]).unwrap();
                assert_eq!(digest, EfiSha256Hash2::default());
            }

            efi_call_traces().with(|traces| {
                let traces = traces.borrow();

                assert_eq!(
                    traces.open_protocol_trace.inputs,
                    [(
                        DeviceHandle(std::ptr::dangling_mut()),
                        <Hash2ServiceBindingProtocol as ProtocolInfo>::GUID,
                        image_handle
                    ),]
                );
            });

            service_binding_call_traces().with(|traces| {
                let traces = traces.borrow();

                assert_eq!(traces.destroy_child_trace.inputs, [(2 as *const _)]);
            })
        });
    }

    #[test]
    fn test_hasher() {
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
                    VecDeque::from([((2 as *const _), EFI_STATUS_SUCCESS)]);
            });

            // New scope to trigger cleanup.
            {
                let mut hasher = Hasher::<Sha256>::new(&efi_entry).unwrap();
                hasher.update(&[]).unwrap();
                assert_eq!(
                    hasher.finalize().unwrap(),
                    <Sha256 as HashAlgorithm>::DigestType::default()
                );
            }

            efi_call_traces().with(|traces| {
                let traces = traces.borrow();

                assert_eq!(
                    traces.open_protocol_trace.inputs,
                    [(
                        DeviceHandle(std::ptr::dangling()),
                        <Hash2ServiceBindingProtocol as ProtocolInfo>::GUID,
                        image_handle
                    ),]
                );
            });

            service_binding_call_traces().with(|traces| {
                let traces = traces.borrow();

                assert_eq!(traces.destroy_child_trace.inputs, [(2 as *const _)]);
            })
        });
    }
}
