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

//! Rust wrapper for `EFI_RANDOM_NUMBER_GENERATOR_PROTOCOL`.

use crate::{
    efi_call,
    protocol::{MaybeVersioned, Protocol, ProtocolInfo},
    EfiEntry,
};
use core::default::Default;
use efi_types::{
    EfiGuid, EfiRngProtocol, EFI_RNG_ALGORITHM_RAW_GUID_U64_0, EFI_RNG_ALGORITHM_RAW_GUID_U64_1,
    EFI_RNG_PROTOCOL_GUID_U64_0, EFI_RNG_PROTOCOL_GUID_U64_1,
};
use liberror::Result;
use zerocopy::{FromBytes, IntoBytes};

impl MaybeVersioned for EfiRngProtocol {}

/// Wraps `EFI_RANDOM_NUMBER_GENERATOR_PROTOCOL`
pub struct RandomNumberGeneratorProtocol;

impl ProtocolInfo for RandomNumberGeneratorProtocol {
    type InterfaceType = EfiRngProtocol;

    const GUID: EfiGuid =
        EfiGuid::from_u64s(EFI_RNG_PROTOCOL_GUID_U64_0, EFI_RNG_PROTOCOL_GUID_U64_1);
}

/// Requested random number generator algorithm.
pub enum RngAlgorithm {
    /// No specific algorithm is required. Up to FW to decide.
    Default,
    /// Entropy directly from the source, without it going through some deterministic
    /// random bit generator.
    Raw,
}

/// Raw entropy GUID:
/// https://uefi.org/specs/UEFI/2.10/37_Secure_Technologies.html#efi-rng-algorithm-definitions
const RAW_ALGORITHM_GUID: EfiGuid =
    EfiGuid::from_u64s(EFI_RNG_ALGORITHM_RAW_GUID_U64_0, EFI_RNG_ALGORITHM_RAW_GUID_U64_1);

impl Protocol<'_, RandomNumberGeneratorProtocol> {
    // `get_info` is deliberately not provided. See b/413744208 for details.

    /// Wrapper of `EFI_RANDOM_NUMBER_GENERATOR_PROTOCOL.get_rng()` which fills a
    /// byte slice.
    pub fn get_rng_bytes(
        &self,
        algorithm: RngAlgorithm,
        mut buffer: impl AsMut<[u8]>,
    ) -> Result<()> {
        // SAFETY:
        // * `self.interface_ptr()` points to a valid object
        //   established by `Protocol::new()`.
        // * `self.interface_ptr()` is an input parameter and will not be retained.
        //   It outlives the call.
        // * `rng_algorithm` is optional. Null is a valid value.
        // * `buffer.as_mut().as_mut_ptr()` is a non-null writable buffer.
        //   It is not retained, outlives the call, and points to `buffer.as_mut().len()`
        //   bytes that will be written to.
        unsafe {
            efi_call!(
                self.interface().get_rng,
                self.interface_ptr(),
                match algorithm {
                    RngAlgorithm::Default => core::ptr::null(),
                    RngAlgorithm::Raw => &RAW_ALGORITHM_GUID as _,
                },
                buffer.as_mut().len(),
                buffer.as_mut().as_mut_ptr(),
            )?;
        }
        Ok(())
    }

    /// Wrapper of `EFI_RANDOM_NUMBER_GENERATOR_PROTOCOL.get_rng()`
    pub fn get_rng<T: FromBytes + IntoBytes + Default>(
        &self,
        algorithm: RngAlgorithm,
    ) -> Result<T> {
        let mut value = T::default();
        self.get_rng_bytes(algorithm, value.as_bytes_mut())?;
        Ok(value)
    }
}

/// Opens `EFI_RANDOM_NUMBER_GENERATOR_PROTOCOL` and fills `buffer` with random bytes.
///
/// This is a convenience helper for one-shot RNG reads; callers making repeated requests should
/// open [`RandomNumberGeneratorProtocol`] once and call [`Protocol::get_rng_bytes`] directly.
pub fn get_rng_bytes(
    entry: &EfiEntry,
    algorithm: RngAlgorithm,
    buffer: impl AsMut<[u8]>,
) -> Result<()> {
    entry
        .system_table_checked()?
        .boot_services_checked()?
        .find_first_and_open::<RandomNumberGeneratorProtocol>()?
        .get_rng_bytes(algorithm, buffer)
}

/// Opens `EFI_RANDOM_NUMBER_GENERATOR_PROTOCOL` and generates a random value of type `T`.
///
/// This is a convenience helper for one-shot RNG reads; callers making repeated requests should
/// open [`RandomNumberGeneratorProtocol`] once and call [`Protocol::get_rng`] directly.
pub fn get_rng<T: FromBytes + IntoBytes + Default>(
    entry: &EfiEntry,
    algorithm: RngAlgorithm,
) -> Result<T> {
    let mut value = T::default();
    get_rng_bytes(entry, algorithm, value.as_mut_bytes())?;
    Ok(value)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        test::{as_efi_handle, efi_call_traces, run_test},
        DeviceHandle,
    };
    use efi_types::{
        EfiStatus, EFI_STATUS_DEVICE_ERROR, EFI_STATUS_INVALID_PARAMETER, EFI_STATUS_SUCCESS,
        EFI_STATUS_UNSUPPORTED,
    };
    use liberror::Error;
    use std::collections::VecDeque;

    /// Mock of `EFI_RNG_PROTOCOL.GetRng` for unit tests.
    ///
    /// # Safety
    ///
    /// * If `algorithm` is non-null, it must be properly aligned and point to an initialized
    ///   `EfiGuid` valid for reads.
    /// * If `out` is non-null and `length > 0`, `out` must be valid for writes of `length` bytes.
    unsafe extern "efiapi" fn mock_get_rng(
        _: *mut EfiRngProtocol,
        algorithm: *const EfiGuid,
        length: usize,
        out: *mut u8,
    ) -> EfiStatus {
        if out.is_null() || length == 0 {
            return EFI_STATUS_INVALID_PARAMETER;
        }
        let fill = if algorithm.is_null() {
            0xA5u8
        } else {
            // SAFETY: `algorithm` is non-null, so per function safety requirements it is aligned
            // and points to an initialized `EfiGuid` valid for reads.
            let algorithm = unsafe { algorithm.read() };
            match algorithm {
                RAW_ALGORITHM_GUID => 0x5Au8,
                _ => return EFI_STATUS_UNSUPPORTED,
            }
        };
        // SAFETY: `out` is non-null with `length > 0`, so per function safety requirements `out`
        // is valid for writes of `length` bytes (and `u8` has alignment 1).
        unsafe { core::ptr::write_bytes(out, fill, length) };
        EFI_STATUS_SUCCESS
    }

    #[test]
    fn test_get_rng_bytes_raw() {
        run_test(|image_handle, systab_ptr| {
            let efi_entry = EfiEntry { image_handle, systab_ptr };
            let handles = [DeviceHandle::from(1)];
            let mut rng_proto =
                EfiRngProtocol { get_rng: Some(mock_get_rng), ..Default::default() };

            efi_call_traces().with(|traces| {
                let mut traces = traces.borrow_mut();
                traces.locate_handle_trace.outputs = VecDeque::from([handles.into()]);
                traces.open_protocol_trace.outputs =
                    VecDeque::from([(as_efi_handle(&mut rng_proto), EFI_STATUS_SUCCESS)]);
            });

            let mut buf = [0u8; 4];
            assert_eq!(get_rng_bytes(&efi_entry, RngAlgorithm::Raw, &mut buf), Ok(()));
            assert_eq!(buf, [0x5A; 4]);
        });
    }

    #[test]
    fn test_get_rng_default() {
        run_test(|image_handle, systab_ptr| {
            let efi_entry = EfiEntry { image_handle, systab_ptr };
            let handles = [DeviceHandle::from(1)];
            let mut rng_proto =
                EfiRngProtocol { get_rng: Some(mock_get_rng), ..Default::default() };

            efi_call_traces().with(|traces| {
                let mut traces = traces.borrow_mut();
                traces.locate_handle_trace.outputs = VecDeque::from([handles.into()]);
                traces.open_protocol_trace.outputs =
                    VecDeque::from([(as_efi_handle(&mut rng_proto), EFI_STATUS_SUCCESS)]);
            });

            let val: u32 = get_rng(&efi_entry, RngAlgorithm::Default).unwrap();
            assert_eq!(val, 0xA5A5_A5A5);
        });
    }

    #[test]
    fn test_get_rng_error() {
        /// Error-returning mock of `EFI_RNG_PROTOCOL.GetRng` for unit tests.
        extern "efiapi" fn mock_get_rng_err(
            _: *mut EfiRngProtocol,
            _: *const EfiGuid,
            _: usize,
            _: *mut u8,
        ) -> EfiStatus {
            EFI_STATUS_DEVICE_ERROR
        }

        run_test(|image_handle, systab_ptr| {
            let efi_entry = EfiEntry { image_handle, systab_ptr };
            let handles = [DeviceHandle::from(1)];
            let mut rng_proto =
                EfiRngProtocol { get_rng: Some(mock_get_rng_err), ..Default::default() };

            efi_call_traces().with(|traces| {
                let mut traces = traces.borrow_mut();
                traces.locate_handle_trace.outputs = VecDeque::from([handles.into()]);
                traces.open_protocol_trace.outputs =
                    VecDeque::from([(as_efi_handle(&mut rng_proto), EFI_STATUS_SUCCESS)]);
            });

            assert_eq!(get_rng::<u64>(&efi_entry, RngAlgorithm::Default), Err(Error::DeviceError));
        });
    }
}
