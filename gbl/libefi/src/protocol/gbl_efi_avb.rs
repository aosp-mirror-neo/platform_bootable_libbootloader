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

//! Rust wrapper for `GBL_EFI_AVB_PROTOCOL`.

use crate::{
    efi_call, efi_println,
    protocol::{Protocol, ProtocolInfo},
    versioned_protocol,
};
use arrayvec::ArrayVec;
use core::{ffi::CStr, iter, ptr::null};
use efi_types::{
    EfiGuid, GblEfiAvbDeviceStatus, GblEfiAvbKeyValidationStatus, GblEfiAvbLockState,
    GblEfiAvbLockType, GblEfiAvbPartitionAttributes, GblEfiAvbProtocol,
    GblEfiAvbVerificationResult, GBL_EFI_AVB_PARTITION_FLAG_FDR,
    GBL_EFI_AVB_PARTITION_FLAG_FLASH_CRITICAL, GBL_EFI_AVB_PARTITION_FLAG_VERIFY,
    GBL_EFI_AVB_PARTITION_FLAG_VERIFY_IF_EXISTS, GBL_EFI_AVB_PROTOCOL_GUID_U64_0,
    GBL_EFI_AVB_PROTOCOL_GUID_U64_1, GBL_EFI_AVB_PROTOCOL_REVISION,
};
use liberror::{Error, Result};
use libgbl::gbl_avb::{Critical, Fdr, SpecializedPartition, Verification};

/// `GBL_EFI_AVB_PROTOCOL` implementation.
pub struct GblAvbProtocol;

versioned_protocol!(GblAvbProtocol, GBL_EFI_AVB_PROTOCOL_REVISION);

impl ProtocolInfo for GblAvbProtocol {
    type InterfaceType = GblEfiAvbProtocol;

    const GUID: EfiGuid =
        EfiGuid::from_u64s(GBL_EFI_AVB_PROTOCOL_GUID_U64_0, GBL_EFI_AVB_PROTOCOL_GUID_U64_1);

    const METRICS_TAG: Option<&'static str> = Some("gbl_avb");

    #[cfg(feature = "gbl_dev")]
    const REQUIREMENT: crate::protocol::Requirement = crate::protocol::Requirement::Optional;
}

// Protocol interface wrappers.
impl Protocol<'_, GblAvbProtocol> {
    /// Wraps `GBL_EFI_AVB_PROTOCOL.read_partition_attributes()`.
    ///
    /// The returned `ArrayVec` will contain the number of provided partitions, each with a
    /// nul-terminated name in its `name_buffer`.
    ///
    /// # Errors
    ///
    /// * `BufferTooSmall(Some(size))` - `N` is not large enough to hold all partitions.
    /// * other - implementation reported a different error.
    ///
    /// # Panics
    ///
    /// Panics if the protocol overflowed the partition array or any of the partition name buffers.
    /// This is an API violation and likely indicates memory corruption so is not recoverable.
    pub fn read_partition_attributes<const N: usize>(
        &self,
    ) -> Result<ArrayVec<SpecializedPartition, N>> {
        // Our Rust objects which contain the backing storage for the partition names.
        // Start at capacity, we will later shrink it to the elements that were actually filled.
        // `SpecializedPartition` is not `Copy` so we need to iterate to initialize it.
        let mut partitions: ArrayVec<SpecializedPartition, N> =
            iter::repeat_n(SpecializedPartition::default(), N).collect();

        // The protocol partition format backed by `partitions`.
        let mut partitions_ffi = ArrayVec::from([GblEfiAvbPartitionAttributes::default(); N]);

        // Initialize the FFI name buffers to point to the Rust backing storage.
        partitions.iter_mut().zip(partitions_ffi.iter_mut()).for_each(
            |(partition, partition_ffi)| {
                // Capacity -1 to ensure we can null-terminate for libavb.
                partition_ffi.base_name_len = partition.name_buffer.len() - 1;
                partition_ffi.base_name = partition.name_buffer.as_mut_ptr();
            },
        );

        let mut num_partitions = partitions_ffi.len();

        // SAFETY:
        // * `self.interface_ptr()` (in) points to a valid object established by `Protocol::new()`.
        // * `num_partitions` (in/out) points to a writeable usize.
        // * `partitions_ffi` (in/out) points to `num_partitions` consecutive writable
        //   `GblEfiAvbPartitionAttributes`.
        // * Each `partitions_ffi[i].base_name` points to a writable buffer of at least
        //   `partitions_ffi[i].base_name_len` bytes.
        //
        // All parameters are only borrowed for the duration of the function.
        unsafe {
            efi_call!(
                @bufsize num_partitions,
                self.interface().read_partition_attributes,
                self.interface_ptr(),
                &mut num_partitions,
                partitions_ffi.as_mut_ptr(),
            )?;
        }

        // Shrink the arrays to just the used elements.
        partitions_ffi.truncate(num_partitions);
        partitions.truncate(num_partitions);

        // Copy the results back to the Rust objects.
        for (partition, partition_ffi) in partitions.iter_mut().zip(partitions_ffi.iter()) {
            // Ensure we still have the null terminator for libavb, in case the protocol overwrote
            // it at some point. This also serves as a safety check that the protocol didn't
            // overflow the name buffer, since this will panic if `base_name_len` was set past the
            // allotted buffer length.
            partition.name_buffer[partition_ffi.base_name_len] = 0;

            // Translate the verification bitmask.
            const VERIFY_MASK: u64 =
                GBL_EFI_AVB_PARTITION_FLAG_VERIFY | GBL_EFI_AVB_PARTITION_FLAG_VERIFY_IF_EXISTS;
            partition.verification = match partition_ffi.flags & VERIFY_MASK {
                0 => None,
                GBL_EFI_AVB_PARTITION_FLAG_VERIFY => Some(Verification::Required),
                GBL_EFI_AVB_PARTITION_FLAG_VERIFY_IF_EXISTS => Some(Verification::IfExists),
                VERIFY_MASK => {
                    // Providing both VERIFY and VERIFY_IF_EXISTS is an API violation.
                    efi_println!(
                        self.efi_entry,
                        "Error: '{:?}' cannot specify both VERIFY and VERIFY_IF_EXISTS",
                        partition.name_cstr()
                    );
                    return Err(Error::InvalidInput);
                }
                // The compiler doesn't take bitmasks into account for `match` so it
                // still requires us to provide a catch-all arm.
                _ => unreachable!(),
            };

            // Translate the other bitflags.
            partition.fdr = match partition_ffi.flags & GBL_EFI_AVB_PARTITION_FLAG_FDR {
                0 => Fdr::No,
                _ => Fdr::Yes,
            };
            partition.critical =
                match partition_ffi.flags & GBL_EFI_AVB_PARTITION_FLAG_FLASH_CRITICAL {
                    0 => Critical::No,
                    _ => Critical::Yes,
                };
        }

        Ok(partitions)
    }

    /// Wraps `GBL_EFI_AVB_PROTOCOL.read_device_status()`.
    pub fn read_device_status(&self) -> Result<GblEfiAvbDeviceStatus> {
        let mut flags = 0;

        // SAFETY:
        // * `self.interface_ptr()` points to a valid object established by `Protocol::new()`
        // * `flags` is non-null buffer points to a `u64` available to write, must be used
        //   only within the call
        unsafe { efi_call!(self.interface().read_device_status, self.interface_ptr(), &mut flags)? }

        Ok(flags)
    }

    /// Wraps `GBL_EFI_AVB_PROTOCOL.validate_vbmeta_public_key()`.
    pub fn validate_vbmeta_public_key(
        &self,
        public_key: &[u8],
        public_key_metadata: Option<&[u8]>,
    ) -> Result<GblEfiAvbKeyValidationStatus> {
        let mut validation_status = efi_types::GBL_EFI_AVB_KEY_VALIDATION_STATUS_INVALID;

        // SAFETY:
        // * `self.interface_ptr()` points to a valid object established by `Protocol::new()`
        // * `public_key` pointer is not-null and used only within the call
        // * `public_key_metadata` pointer (can be null), used only within the call
        // * `validation_status` non-null pointer available to write
        unsafe {
            efi_call!(
                self.interface().validate_vbmeta_public_key,
                self.interface_ptr(),
                public_key.len(),
                public_key.as_ptr() as *const _,
                public_key_metadata.map_or(0, |m| m.len()),
                public_key_metadata.map_or(null(), |m| m.as_ptr() as *const _),
                &mut validation_status,
            )?
        }

        Ok(validation_status as _)
    }

    /// Wraps `GBL_EFI_AVB_PROTOCOL.read_rollback_index()`.
    pub fn read_rollback_index(&self, index_location: usize) -> Result<u64> {
        let mut rollback_index: u64 = 0;

        // SAFETY:
        // * `self.interface_ptr()` guarantees `self.interface_ptr()` is non-null and points to a valid
        //   object established by `Protocol::new()`.
        // * `rollback_index` is a valid pointer to a `u64` available for write.
        unsafe {
            efi_call!(
                self.interface().read_rollback_index,
                self.interface_ptr(),
                index_location,
                &mut rollback_index,
            )?
        }

        Ok(rollback_index)
    }

    /// Wraps `GBL_EFI_AVB_PROTOCOL.write_rollback_index()`.
    pub fn write_rollback_index(&self, index_location: usize, rollback_index: u64) -> Result<()> {
        // SAFETY:
        // * `self.interface_ptr()` guarantees `self.interface_ptr()` is non-null and points to a valid
        //   object established by `Protocol::new()`.
        unsafe {
            efi_call!(
                self.interface().write_rollback_index,
                self.interface_ptr(),
                index_location,
                rollback_index,
            )?
        }

        Ok(())
    }

    /// Wraps `GBL_EFI_AVB_PROTOCOL.read_persistent_value()`.
    pub fn read_persistent_value(&self, name: &CStr, value: &mut [u8]) -> Result<usize> {
        let mut value_buffer_size = value.len();

        let value_ptr = match value.is_empty() {
            true => core::ptr::null_mut(),
            false => value.as_mut_ptr(),
        };

        // SAFETY:
        // * `self.interface_ptr()` guarantees `self.interface_ptr()` is non-null and points to a valid
        //   object established by `Protocol::new()`.
        // * `name` is a valid pointer to a null-terminated string used only within the call.
        // * `value_buffer_size` holds a mutable reference to `usize`, used only within the call.
        // * `value_ptr` is either a valid pointer to a writable buffer or a null pointer, used only
        //   within the call
        unsafe {
            efi_call!(
                @bufsize value_buffer_size,
                self.interface().read_persistent_value,
                self.interface_ptr(),
                name.as_ptr() as _,
                &mut value_buffer_size,
                value_ptr,
            )?
        }

        Ok(value_buffer_size)
    }

    /// Wraps `GBL_EFI_AVB_PROTOCOL.write_persistent_value()`.
    pub fn write_persistent_value(&self, name: &CStr, value: Option<&[u8]>) -> Result<()> {
        let (value_ptr, value_len) = match value {
            Some(v) => (v.as_ptr(), v.len()),
            None => (core::ptr::null(), 0),
        };

        // SAFETY:
        // * `self.interface_ptr()` guarantees `self.interface_ptr()` is non-null and points to a valid
        //   object established by `Protocol::new()`.
        // * `name` is a valid pointer to a null-terminated string used only within the call.
        // * `value_ptr` is a valid pointer to `value_len` sized buffer or null, used only within
        //   the call.
        unsafe {
            efi_call!(
                self.interface().write_persistent_value,
                self.interface_ptr(),
                name.as_ptr() as _,
                value_len,
                value_ptr,
            )?
        }

        Ok(())
    }

    /// Wraps `GBL_EFI_AVB_PROTOCOL.handle_verification_result()`.
    pub fn handle_verification_result(
        &self,
        verification_result: &GblEfiAvbVerificationResult,
    ) -> Result<()> {
        // SAFETY:
        // * `self.interface_ptr()` points to a valid object established by `Protocol::new()`.
        // * `verification_result` pointer is not-null and used only within the call.
        unsafe {
            efi_call!(
                self.interface().handle_verification_result,
                self.interface_ptr(),
                verification_result as *const _
            )
        }
    }

    /// Wraps `GBL_EFI_AVB_PROTOCOL.write_lock_state()`.
    pub fn write_lock_state(
        &self,
        lock_type: GblEfiAvbLockType,
        lock_state: GblEfiAvbLockState,
    ) -> Result<()> {
        // Safety:
        // * `self.interface_ptr()` points to a valid object established by `Protocol::new()`.
        unsafe {
            efi_call!(
                self.interface().write_lock_state,
                self.interface_ptr(),
                lock_type,
                lock_state
            )
        }
    }

    /// Wraps `GBL_EFI_AVB_PROTOCOL.FactoryDataReset()`.
    pub fn factory_data_reset(&self) -> Result<()> {
        // Safety: `self.interface_ptr()` points to a valid object established by `Protocol::new()`.
        unsafe { efi_call!(self.interface().factory_data_reset, self.interface_ptr()) }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{test::run_test_with_mock_protocol, Error};
    use efi_types::defs::{
        EfiStatus, GblEfiAvbBootColorFlags, GblEfiAvbDeviceStatus, EFI_STATUS_ACCESS_DENIED,
        EFI_STATUS_BUFFER_TOO_SMALL, EFI_STATUS_INVALID_PARAMETER, EFI_STATUS_OUT_OF_RESOURCES,
        EFI_STATUS_SUCCESS, GBL_EFI_AVB_BOOT_COLOR_RED,
    };
    use libutils::cstr_buffer;
    use std::{
        cell::Cell,
        cmp::min,
        ptr,
        slice::{from_raw_parts, from_raw_parts_mut},
    };

    /// Test helper for `read_partition_attributes()`.
    ///
    /// Sets up a fake C backend for the UEFI protocol API which will populate the partition
    /// attributes, calls it using our Rust wrapper, and then returns the result.
    ///
    /// If the provided partition information cannot fit in the buffers, this function will not
    /// overflow but will update the length fields as if it had. This can be used to test that
    /// our Rust wrapper is properly panicking if it detects memory corruption.
    ///
    /// # Arguments
    ///
    /// * `names_and_flags` - the list of partition names and flags to populate.
    /// * `return_value` - the EFI status value to return from the fake C backend.
    fn read_partition_attributes_test<const N: usize>(
        names_and_flags: &[(&'static str, u64)],
        return_value: EfiStatus,
    ) -> Result<ArrayVec<SpecializedPartition, N>> {
        // The UEFI protocol API is just a C function pointer so can't see any local state.
        // Stash the partition information in static thread storage so we can access it there.
        thread_local! {
            static NAMES_AND_FLAGS: Cell<Vec<(&'static str, u64)>> = Default::default();
            static RETURN_VALUE: Cell<EfiStatus> = Cell::new(EFI_STATUS_SUCCESS);
        }
        NAMES_AND_FLAGS.set(names_and_flags.to_vec());
        RETURN_VALUE.set(return_value);

        /// UEFI protocol backend implementation.
        unsafe extern "efiapi" fn read_partition_attributes(
            _: *mut GblEfiAvbProtocol,
            num_partitions: *mut usize,
            partitions: *mut GblEfiAvbPartitionAttributes,
        ) -> EfiStatus {
            // Fetch our stashed arguments from thread-local storage.
            let names_and_flags = NAMES_AND_FLAGS.take();
            let return_value = RETURN_VALUE.replace(EFI_STATUS_SUCCESS);

            // SAFETY: API guarantees `num_partitions` points to a writeable usize.
            let num_partitions = unsafe { num_partitions.as_mut().unwrap() };

            // SAFETY: API guarantees `partitions` points to a writeable array of `num_partitions`.
            let partitions = unsafe { from_raw_parts_mut(partitions, *num_partitions) };

            for ((name, flags), partition) in names_and_flags.iter().zip(partitions.iter_mut()) {
                // Copy the name.
                let name_bytes = name.as_bytes();
                // SAFETY: API guarantees each partition `base_name` points to writeable array
                // of `base_name_len` bytes. We use `min()` to ensure we stay inside this buffer.
                unsafe {
                    ptr::copy_nonoverlapping(
                        name_bytes.as_ptr(),
                        partition.base_name,
                        min(partition.base_name_len, name_bytes.len()),
                    )
                };

                // Update the length field to indicate how much we wrote.
                // If the input name was too large, this value will indicate we overflowed the name
                // buffer (even though we didn't actually).
                partition.base_name_len = name_bytes.len();

                // Copy the flags.
                partition.flags = *flags;
            }

            // Update `num_partition` to indicate how many we filled, or would have filled if there
            // was enough room.
            *num_partitions = names_and_flags.len();

            return_value
        }

        // Create the protocol struct with our test function populated.
        let c_interface = GblEfiAvbProtocol {
            read_partition_attributes: Some(read_partition_attributes),
            ..Default::default()
        };

        // Create our Rust wrapper around the test protocol and call it.
        let mut result = None;
        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            result = Some(avb_protocol.read_partition_attributes::<N>());
        });
        result.unwrap()
    }

    #[test]
    fn read_partition_attributes_success() {
        let result = read_partition_attributes_test::<16>(
            &[
                ("no_flags", 0),
                ("verify", GBL_EFI_AVB_PARTITION_FLAG_VERIFY),
                ("verify_if_exists", GBL_EFI_AVB_PARTITION_FLAG_VERIFY_IF_EXISTS),
                ("fdr", GBL_EFI_AVB_PARTITION_FLAG_FDR),
                ("critical", GBL_EFI_AVB_PARTITION_FLAG_FLASH_CRITICAL),
            ],
            EFI_STATUS_SUCCESS,
        );

        assert_eq!(
            &result.unwrap()[..],
            [
                SpecializedPartition { name_buffer: cstr_buffer("no_flags"), ..Default::default() },
                SpecializedPartition {
                    name_buffer: cstr_buffer("verify"),
                    verification: Some(Verification::Required),
                    ..Default::default()
                },
                SpecializedPartition {
                    name_buffer: cstr_buffer("verify_if_exists"),
                    verification: Some(Verification::IfExists),
                    ..Default::default()
                },
                SpecializedPartition {
                    name_buffer: cstr_buffer("fdr"),
                    fdr: Fdr::Yes,
                    ..Default::default()
                },
                SpecializedPartition {
                    name_buffer: cstr_buffer("critical"),
                    critical: Critical::Yes,
                    ..Default::default()
                },
            ]
        );
    }

    #[test]
    fn read_partition_attributes_multiple_flags() {
        let result = read_partition_attributes_test::<16>(
            &[
                (
                    "fdr_and_critical",
                    GBL_EFI_AVB_PARTITION_FLAG_FDR | GBL_EFI_AVB_PARTITION_FLAG_FLASH_CRITICAL,
                ),
                (
                    "verify_and_critical",
                    GBL_EFI_AVB_PARTITION_FLAG_VERIFY | GBL_EFI_AVB_PARTITION_FLAG_FLASH_CRITICAL,
                ),
            ],
            EFI_STATUS_SUCCESS,
        );

        assert_eq!(
            &result.unwrap()[..],
            [
                SpecializedPartition {
                    name_buffer: cstr_buffer("fdr_and_critical"),
                    fdr: Fdr::Yes,
                    critical: Critical::Yes,
                    ..Default::default()
                },
                SpecializedPartition {
                    name_buffer: cstr_buffer("verify_and_critical"),
                    verification: Some(Verification::Required),
                    critical: Critical::Yes,
                    ..Default::default()
                },
            ]
        );
    }

    #[test]
    fn read_partition_attributes_invalid_flags() {
        // Specifying both VERIFY flags is ambiguous and breaks API requirements, should error.
        let result = read_partition_attributes_test::<16>(
            &[(
                "verify_and_if_exists",
                GBL_EFI_AVB_PARTITION_FLAG_VERIFY | GBL_EFI_AVB_PARTITION_FLAG_VERIFY_IF_EXISTS,
            )],
            EFI_STATUS_SUCCESS,
        );

        assert_eq!(result, Err(Error::InvalidInput));
    }

    #[test]
    fn read_partition_attributes_buffer_too_small() {
        // Only allocate space for 2 partitions but the backend needs 3.
        let result = read_partition_attributes_test::<2>(
            &[("1", 0), ("2", 0), ("3", 0)],
            EFI_STATUS_BUFFER_TOO_SMALL,
        );

        assert_eq!(result, Err(Error::BufferTooSmall(Some(3))));
    }

    #[test]
    fn read_partition_attributes_error() {
        // Backend reports some other error.
        let result = read_partition_attributes_test::<16>(&[], EFI_STATUS_OUT_OF_RESOURCES);

        assert_eq!(result, Err(Error::OutOfResources));
    }

    #[test]
    #[should_panic]
    fn read_partition_attributes_name_buffer_overflow() {
        // Fake a buffer overflow in a partition name buffer by "writing" too long of a name but
        // returning SUCCESS.
        // This should panic since it looks like memory has been corrupted.
        let _ = read_partition_attributes_test::<16>(
            &[("this_name_is_36_characters_long_____", 0)],
            EFI_STATUS_SUCCESS,
        );
    }

    #[test]
    #[should_panic]
    fn read_partition_attributes_partitions_buffer_overflow() {
        // Fake a buffer overflow in a partitions buffer by "writing" too many partitions but
        // returning SUCCESS.
        // This should panic since it looks like memory has been corrupted.
        let _ = read_partition_attributes_test::<2>(
            &[("1", 0), ("2", 0), ("3", 0)],
            EFI_STATUS_SUCCESS,
        );
    }

    #[test]
    fn read_device_status_returns_unlocked() {
        /// C callback implementation that sets the flags for unlocked status.
        unsafe extern "efiapi" fn c_return_unlocked_and_ok(
            _: *mut GblEfiAvbProtocol,
            flags_ptr: *mut GblEfiAvbDeviceStatus,
        ) -> EfiStatus {
            // SAFETY: flags_ptr is a valid u64 pointer available to write.
            unsafe { *flags_ptr = efi_types::GBL_EFI_AVB_DEVICE_STATUS_UNLOCKED };
            EFI_STATUS_SUCCESS
        }

        let c_interface = GblEfiAvbProtocol {
            read_device_status: Some(c_return_unlocked_and_ok),
            ..Default::default()
        };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            let expected_flags = efi_types::GBL_EFI_AVB_DEVICE_STATUS_UNLOCKED;
            assert_eq!(avb_protocol.read_device_status(), Ok(expected_flags));
        });
    }

    #[test]
    fn read_device_status_error_handled() {
        /// C callback implementation that returns an error.
        unsafe extern "efiapi" fn c_return_error(
            _: *mut GblEfiAvbProtocol,
            _: *mut GblEfiAvbDeviceStatus,
        ) -> EfiStatus {
            EFI_STATUS_INVALID_PARAMETER
        }

        let c_interface =
            GblEfiAvbProtocol { read_device_status: Some(c_return_error), ..Default::default() };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            assert_eq!(avb_protocol.read_device_status(), Err(Error::InvalidInput));
        });
    }

    #[test]
    fn validate_vbmeta_public_key_status_provided() {
        const EXPECTED_PUBLIC_KEY: &[u8] = b"test_key";
        const EXPECTED_STATUS: GblEfiAvbKeyValidationStatus =
            efi_types::GBL_EFI_AVB_KEY_VALIDATION_STATUS_VALID_CUSTOM_KEY;

        // C callback implementation that returns an error
        unsafe extern "efiapi" fn c_return_error(
            _: *mut GblEfiAvbProtocol,
            public_key_len: usize,
            public_key_ptr: *const u8,
            _metadata_len: usize,
            _metadata_ptr: *const u8,
            validation_status_ptr: *mut GblEfiAvbKeyValidationStatus,
        ) -> EfiStatus {
            // SAFETY:
            // * `public_key_ptr` is a non-null pointer to the buffer at least `public_key_len`
            // size.
            let public_key_buffer = unsafe { from_raw_parts(public_key_ptr, public_key_len) };

            assert_eq!(public_key_buffer, EXPECTED_PUBLIC_KEY);

            // SAFETY:
            // * `validation_status_ptr` is a non-null pointer to GblEfiAvbKeyValidationStatus
            // available to write.
            unsafe { *validation_status_ptr = EXPECTED_STATUS };

            EFI_STATUS_SUCCESS
        }

        let c_interface = GblEfiAvbProtocol {
            validate_vbmeta_public_key: Some(c_return_error),
            ..Default::default()
        };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            assert_eq!(
                avb_protocol.validate_vbmeta_public_key(EXPECTED_PUBLIC_KEY, None),
                Ok(EXPECTED_STATUS)
            );
        });
    }

    #[test]
    fn validate_vbmeta_public_key_error_handled() {
        // C callback implementation that returns an error
        unsafe extern "efiapi" fn c_return_error(
            _: *mut GblEfiAvbProtocol,
            _public_key_len: usize,
            _public_key_ptr: *const u8,
            _metadata_len: usize,
            _metadata_ptr: *const u8,
            _validation_status_ptr: *mut GblEfiAvbKeyValidationStatus,
        ) -> EfiStatus {
            EFI_STATUS_INVALID_PARAMETER
        }

        let c_interface = GblEfiAvbProtocol {
            validate_vbmeta_public_key: Some(c_return_error),
            ..Default::default()
        };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            assert!(avb_protocol.validate_vbmeta_public_key(b"test_key", None).is_err());
        });
    }

    #[test]
    fn handle_verification_result_data_provided() {
        const COLOR: GblEfiAvbBootColorFlags = GBL_EFI_AVB_BOOT_COLOR_RED;

        // C callback implementation that returns success.
        unsafe extern "efiapi" fn c_return_success(
            _: *mut GblEfiAvbProtocol,
            result: *const GblEfiAvbVerificationResult,
        ) -> EfiStatus {
            // SAFETY:
            // * `result` is non-null.
            assert_eq!(unsafe { (*result).color_flags }, COLOR);
            EFI_STATUS_SUCCESS
        }

        let c_interface = GblEfiAvbProtocol {
            handle_verification_result: Some(c_return_success),
            ..Default::default()
        };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            let verification_result =
                GblEfiAvbVerificationResult { color_flags: COLOR, ..Default::default() };

            assert!(avb_protocol.handle_verification_result(&verification_result).is_ok());
        });
    }

    #[test]
    fn handle_verification_result_error() {
        // C callback implementation that returns an error.
        unsafe extern "efiapi" fn c_return_error(
            _: *mut GblEfiAvbProtocol,
            _: *const GblEfiAvbVerificationResult,
        ) -> EfiStatus {
            EFI_STATUS_INVALID_PARAMETER
        }

        let c_interface = GblEfiAvbProtocol {
            handle_verification_result: Some(c_return_error),
            ..Default::default()
        };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            let verification_result = GblEfiAvbVerificationResult::default();

            assert!(avb_protocol.handle_verification_result(&verification_result).is_err());
        });
    }

    #[test]
    fn read_rollback_index_returns_value() {
        const EXPECTED_INDEX_LOCATION: usize = 1;
        const EXPECTED_ROLLBACK_INDEX: u64 = 42;

        /// C callback implementation that sets rollback_index to EXPECTED_ROLLBACK_INDEX.
        ///
        /// # Safety:
        /// Caller must guaranteed that `rollback_index_ptr` points to a valid u64 variable
        /// available for write.
        unsafe extern "efiapi" fn c_return_value(
            _: *mut GblEfiAvbProtocol,
            index_location: usize,
            rollback_index_ptr: *mut u64,
        ) -> EfiStatus {
            assert_eq!(index_location, EXPECTED_INDEX_LOCATION);

            // SAFETY: By safety requirement of this function, `rollback_index_ptr` is a valid
            // pointer.
            unsafe { *rollback_index_ptr = EXPECTED_ROLLBACK_INDEX };
            EFI_STATUS_SUCCESS
        }

        let c_interface =
            GblEfiAvbProtocol { read_rollback_index: Some(c_return_value), ..Default::default() };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            assert_eq!(
                avb_protocol.read_rollback_index(EXPECTED_INDEX_LOCATION),
                Ok(EXPECTED_ROLLBACK_INDEX)
            );
        });
    }

    #[test]
    fn read_rollback_index_error_handled() {
        /// C callback implementation that returns an error.
        unsafe extern "efiapi" fn c_return_error(
            _: *mut GblEfiAvbProtocol,
            _: usize,
            _: *mut u64,
        ) -> EfiStatus {
            EFI_STATUS_INVALID_PARAMETER
        }

        let c_interface =
            GblEfiAvbProtocol { read_rollback_index: Some(c_return_error), ..Default::default() };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            assert!(avb_protocol.read_rollback_index(0).is_err());
        });
    }

    #[test]
    fn write_rollback_index_success() {
        const EXPECTED_INDEX_LOCATION: usize = 1;
        const EXPECTED_ROLLBACK_INDEX: u64 = 42;

        /// C callback implementation that checks the passed parameters and returns success.
        unsafe extern "efiapi" fn c_return_success(
            _: *mut GblEfiAvbProtocol,
            index_location: usize,
            rollback_index: u64,
        ) -> EfiStatus {
            assert_eq!(index_location, EXPECTED_INDEX_LOCATION);
            assert_eq!(rollback_index, EXPECTED_ROLLBACK_INDEX);
            EFI_STATUS_SUCCESS
        }

        let c_interface = GblEfiAvbProtocol {
            write_rollback_index: Some(c_return_success),
            ..Default::default()
        };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            assert!(avb_protocol
                .write_rollback_index(EXPECTED_INDEX_LOCATION, EXPECTED_ROLLBACK_INDEX)
                .is_ok());
        });
    }

    #[test]
    fn write_rollback_index_error_handled() {
        /// C callback implementation that returns an error.
        unsafe extern "efiapi" fn c_return_error(
            _: *mut GblEfiAvbProtocol,
            _: usize,
            _: u64,
        ) -> EfiStatus {
            EFI_STATUS_INVALID_PARAMETER
        }

        let c_interface =
            GblEfiAvbProtocol { write_rollback_index: Some(c_return_error), ..Default::default() };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            assert!(avb_protocol.write_rollback_index(0, 0).is_err());
        });
    }

    #[test]
    fn read_persistent_value_success() {
        const EXPECTED_NAME: &CStr = c"test_key";
        const EXPECTED_VALUE: &[u8] = b"test_value";

        /// C callback implementation.
        ///
        /// # Safety:
        /// * Caller must guaranteed that `name` points to a valid null-terminated string.
        /// * Caller must guaranteed that `value_size` points to a valid usize available to write
        ///   value buffer.
        /// * Caller must guaranteed that `value` points to non-null `value_size` sized bytes
        ///   buffer.
        unsafe extern "efiapi" fn c_read_persistent_value_success(
            _: *mut GblEfiAvbProtocol,
            name: *const u8,
            value_size: *mut usize,
            value: *mut u8,
        ) -> EfiStatus {
            assert_eq!(
                // SAFETY:
                // * `name` is a valid pointer to null-terminated string.
                unsafe { CStr::from_ptr(name as _) },
                EXPECTED_NAME
            );
            assert_eq!(
                // SAFETY:
                // * `value_size` is a valid non-null pointer to `usize` value.
                unsafe { ptr::read(value_size) },
                EXPECTED_VALUE.len()
            );

            // SAFETY:
            // * `value` is non-null pointer available for write.
            let value_buffer = unsafe { from_raw_parts_mut(value, EXPECTED_VALUE.len()) };
            value_buffer.copy_from_slice(EXPECTED_VALUE);

            EFI_STATUS_SUCCESS
        }

        let c_interface = GblEfiAvbProtocol {
            read_persistent_value: Some(c_read_persistent_value_success),
            ..Default::default()
        };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            let mut buffer = [0u8; EXPECTED_VALUE.len()];

            assert_eq!(
                avb_protocol.read_persistent_value(EXPECTED_NAME, &mut buffer),
                Ok(EXPECTED_VALUE.len())
            );
            assert_eq!(&buffer, EXPECTED_VALUE);
        });
    }

    #[test]
    fn read_persistent_value_buffer_too_small() {
        const EXPECTED_BUFFER_SIZE: usize = 12;

        /// C callback implementation.
        ///
        /// # Safety:
        /// * Caller must guaranteed that `value_size` points to a valid usize available to write
        ///   value buffer.
        unsafe extern "efiapi" fn c_read_persistent_value_buffer_too_small(
            _: *mut GblEfiAvbProtocol,
            _: *const u8,
            value_size: *mut usize,
            _: *mut u8,
        ) -> EfiStatus {
            // SAFETY:
            // * `value_size` is a valid non-null pointer to `usize` value.
            unsafe { ptr::write(value_size, EXPECTED_BUFFER_SIZE) };

            EFI_STATUS_BUFFER_TOO_SMALL
        }

        let c_interface = GblEfiAvbProtocol {
            read_persistent_value: Some(c_read_persistent_value_buffer_too_small),
            ..Default::default()
        };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            let mut buffer = [0u8; 0];

            assert_eq!(
                avb_protocol.read_persistent_value(c"name", &mut buffer),
                Err(Error::BufferTooSmall(Some(EXPECTED_BUFFER_SIZE)))
            );
        });
    }

    #[test]
    fn write_persistent_value_success() {
        const EXPECTED_NAME: &CStr = c"test_key";
        const EXPECTED_VALUE: &[u8] = b"test_value";

        /// C callback implementation.
        ///
        /// # Safety:
        /// * Caller must guarantee that `name` points to a valid null-terminated string.
        /// * Caller must guarantee that `value` points to a valid `value_size` sized bytes buffer.
        unsafe extern "efiapi" fn c_write_persistent_value_success(
            _: *mut GblEfiAvbProtocol,
            name: *const u8,
            value_size: usize,
            value: *const u8,
        ) -> EfiStatus {
            assert_eq!(
                // SAFETY:
                // * `name` is a valid pointer to null-terminated string.
                unsafe { CStr::from_ptr(name as _) },
                EXPECTED_NAME
            );
            assert_eq!(value_size, EXPECTED_VALUE.len());

            // SAFETY:
            // * `value` is a valid pointer to `value_size` bytes.
            let value_buffer = unsafe { from_raw_parts(value, value_size) };
            assert_eq!(value_buffer, EXPECTED_VALUE);

            EFI_STATUS_SUCCESS
        }

        let c_interface = GblEfiAvbProtocol {
            write_persistent_value: Some(c_write_persistent_value_success),
            ..Default::default()
        };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            assert_eq!(
                avb_protocol.write_persistent_value(EXPECTED_NAME, Some(EXPECTED_VALUE)),
                Ok(())
            );
        });
    }

    #[test]
    fn write_persistent_value_delete() {
        const EXPECTED_NAME: &CStr = c"test_key";

        /// C callback implementation for deleting a persistent value.
        ///
        /// # Safety:
        /// * Caller must guarantee that `name` points to a valid null-terminated string.
        unsafe extern "efiapi" fn c_write_persistent_value_delete(
            _: *mut GblEfiAvbProtocol,
            name: *const u8,
            value_size: usize,
            value: *const u8,
        ) -> EfiStatus {
            assert_eq!(
                // SAFETY:
                // * `name` is a valid pointer to null-terminated string.
                unsafe { CStr::from_ptr(name as _) },
                EXPECTED_NAME
            );
            assert!(value.is_null());
            assert_eq!(value_size, 0);

            EFI_STATUS_SUCCESS
        }

        let c_interface = GblEfiAvbProtocol {
            write_persistent_value: Some(c_write_persistent_value_delete),
            ..Default::default()
        };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            assert_eq!(avb_protocol.write_persistent_value(EXPECTED_NAME, None), Ok(()));
        });
    }

    #[test]
    fn write_persistent_value_error_handled() {
        const EXPECTED_NAME: &CStr = c"test_key";
        const EXPECTED_VALUE: &[u8] = b"test_value";

        /// C callback implementation that returns an error.
        ///
        /// # Safety:
        /// * Caller must guarantee that `name` points to a valid null-terminated string.
        unsafe extern "efiapi" fn c_write_persistent_value_error(
            _: *mut GblEfiAvbProtocol,
            name: *const u8,
            _: usize,
            _: *const u8,
        ) -> EfiStatus {
            assert_eq!(
                // SAFETY:
                // * `name` is a valid pointer to null-terminated string.
                unsafe { CStr::from_ptr(name as _) },
                EXPECTED_NAME
            );

            EFI_STATUS_INVALID_PARAMETER
        }

        let c_interface = GblEfiAvbProtocol {
            write_persistent_value: Some(c_write_persistent_value_error),
            ..Default::default()
        };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            assert_eq!(
                avb_protocol.write_persistent_value(EXPECTED_NAME, Some(EXPECTED_VALUE)),
                Err(Error::InvalidInput),
            );
        });
    }

    #[test]
    fn factory_data_reset_success() {
        /// C callback implementation that returns success.
        unsafe extern "efiapi" fn c_return_success(_: *mut GblEfiAvbProtocol) -> EfiStatus {
            EFI_STATUS_SUCCESS
        }

        let c_interface =
            GblEfiAvbProtocol { factory_data_reset: Some(c_return_success), ..Default::default() };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            assert_eq!(avb_protocol.factory_data_reset(), Ok(()));
        });
    }

    #[test]
    fn factory_data_reset_error() {
        /// C callback implementation that returns success.
        unsafe extern "efiapi" fn c_return_error(_: *mut GblEfiAvbProtocol) -> EfiStatus {
            EFI_STATUS_ACCESS_DENIED
        }

        let c_interface =
            GblEfiAvbProtocol { factory_data_reset: Some(c_return_error), ..Default::default() };

        run_test_with_mock_protocol(c_interface, |avb_protocol| {
            assert_eq!(avb_protocol.factory_data_reset(), Err(Error::AccessDenied));
        });
    }
}
