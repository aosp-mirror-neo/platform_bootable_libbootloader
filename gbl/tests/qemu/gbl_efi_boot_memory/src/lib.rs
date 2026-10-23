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

//! Implementation of the `GblEfiBootMemoryProtocol` for qemu tests.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::ffi::CStr;
use efi_types::{
    defs::{
        GblEfiBootBufferType, GBL_EFI_BOOT_BUFFER_TYPE_FASTBOOT_DOWNLOAD,
        GBL_EFI_BOOT_BUFFER_TYPE_FDT, GBL_EFI_BOOT_BUFFER_TYPE_GENERAL_LOAD,
        GBL_EFI_BOOT_BUFFER_TYPE_KERNEL, GBL_EFI_BOOT_BUFFER_TYPE_PVMFW_DATA,
        GBL_EFI_BOOT_BUFFER_TYPE_RAMDISK, GBL_EFI_BOOT_MEMORY_PROTOCOL_REVISION,
        GBL_EFI_PARTITION_BUFFER_FLAG_PRELOADED,
    },
    protocol::gbl_efi_boot_memory::{BootBuffer, GblEfiBootMemorySafe},
    status::{EfiError, EfiResult},
    GblEfiPartitionBufferFlag,
};
use libgbl::partition::RAW_PARTITION_NAME_LEN;

/// Test implementation of `GblEfiBootMemory`.
pub struct GblEfiBootMemoryImpl;

/// Helper to find preloaded partitions.
///
/// The function checks for environment variable `PART_PRELOADED_<part_name>` to look up
/// the corresponding image file path.
fn find_preloaded(part_name: &CStr) -> EfiResult<Vec<u8>> {
    let mut buf = [0u8; RAW_PARTITION_NAME_LEN + 18];
    libutils::snprintf!(buf, "PART_PRELOADED_{}\0", part_name.to_str().unwrap());
    let env_key = CStr::from_bytes_until_nul(&buf).unwrap();
    let mut out = [0u8; 128];
    semihosting::getenv(Some(env_key.to_str().unwrap()), &mut out)?;
    let file = CStr::from_bytes_until_nul(&out).unwrap();
    let mut file = semihosting::File::open(file, semihosting::OpenMode::ReadOnly).unwrap();
    let mut buffer = vec![0u8; file.len().unwrap()];
    file.read(&mut buffer).unwrap();
    Ok(buffer)
}

/// Helper to find designated partition buffer.
///
/// The function checks for environment variable `PART_DESIGNATED_<part_name>` to look up
/// the corresponding buffer size.
fn find_designated(part_name: &CStr) -> EfiResult<Vec<u8>> {
    let mut buf = [0u8; RAW_PARTITION_NAME_LEN + 18];
    libutils::snprintf!(buf, "PART_DESIGNATED_{}\0", part_name.to_str().unwrap());
    let env_key = CStr::from_bytes_until_nul(&buf).unwrap();
    Ok(vec![0u8; semihosting::getenv_as_usize(env_key.to_str().unwrap())?])
}

impl GblEfiBootMemorySafe for GblEfiBootMemoryImpl {
    type PartitionBuffer = Vec<u8>;

    fn revision(&self) -> u64 {
        GBL_EFI_BOOT_MEMORY_PROTOCOL_REVISION
    }

    fn sync_partition_buffer(&self, _: bool) -> EfiResult<()> {
        Ok(())
    }

    fn get_partition_buffer(
        &self,
        part: &CStr,
    ) -> EfiResult<(Self::PartitionBuffer, GblEfiPartitionBufferFlag)> {
        match find_preloaded(part) {
            Ok(v) => Ok((v, GBL_EFI_PARTITION_BUFFER_FLAG_PRELOADED)),
            Err(EfiError::NotFound) => Ok((find_designated(part)?, GblEfiPartitionBufferFlag(0))),
            Err(e) => Err(e),
        }
    }

    fn take_boot_buffer(&self, buffer_type: GblEfiBootBufferType) -> EfiResult<BootBuffer> {
        let (env_name, default_size) = match buffer_type {
            GBL_EFI_BOOT_BUFFER_TYPE_GENERAL_LOAD => ("GBL_GENERAL_LOAD_SIZE", Some(1024 * 1024)),
            GBL_EFI_BOOT_BUFFER_TYPE_KERNEL => ("GBL_KERNEL_SIZE", Some(1024 * 1024)),
            GBL_EFI_BOOT_BUFFER_TYPE_RAMDISK => ("GBL_RAMDISK_SIZE", Some(1024 * 1024)),
            GBL_EFI_BOOT_BUFFER_TYPE_FDT => ("GBL_FDT_SIZE", None),
            GBL_EFI_BOOT_BUFFER_TYPE_PVMFW_DATA => ("GBL_PVMFW_DATA_SIZE", None),
            GBL_EFI_BOOT_BUFFER_TYPE_FASTBOOT_DOWNLOAD => {
                ("GBL_FASTBOOT_DOWNLOAD_SIZE", Some(16 * 1024 * 1024))
            }
            _ => unreachable!(),
        };

        let size = match semihosting::getenv_as_usize(env_name) {
            Ok(sz) => sz,
            Err(liberror::Error::NotFound) => default_size.ok_or(EfiError::NotFound)?,
            Err(e) => return Err(e.into()),
        };

        Ok(BootBuffer::ToAllocate(size))
    }
}
