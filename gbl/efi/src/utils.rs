// Copyright 2023, The Android Open Source Project
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

//! Contains util APIs for EFI.

use crate::efi;
use ::efi::{efi_println, EfiMemoryAttributesTable};
use core::marker::PhantomData;
use core::time::Duration;
use efi::{
    protocol::{
        device_path::{DevicePathProtocol, DevicePathText, DevicePathToTextProtocol},
        gbl_efi_boot_memory::{
            gbl_clear_boot_buffer, gbl_get_boot_buffer, GblVendorReservedMemory,
        },
        loaded_image::LoadedImageProtocol,
        simple_text_input::SimpleTextInputProtocol,
        timestamp::TimestampProtocol,
        Protocol,
    },
    utils::Timeout,
    DeviceHandle, EfiEntry,
};
#[cfg(any(target_arch = "x86_64", feature = "fuchsia"))]
use efi_types::EfiMemoryType;
use efi_types::{
    EfiInputKey, GBL_EFI_BOOT_BUFFER_TYPE_FASTBOOT_DOWNLOAD, GBL_EFI_BOOT_BUFFER_TYPE_FDT,
    GBL_EFI_BOOT_BUFFER_TYPE_GENERAL_LOAD, GBL_EFI_BOOT_BUFFER_TYPE_KERNEL,
    GBL_EFI_BOOT_BUFFER_TYPE_PVMFW_DATA, GBL_EFI_BOOT_BUFFER_TYPE_RAMDISK,
};
use liberror::Error;
use libgbl::{android_boot::BootBuffer, metrics::GblTime};

type Result<T> = core::result::Result<T, Error>;

/// Helper function to get the `DevicePathText` from a `DeviceHandle`.
pub fn get_device_path<'a>(
    entry: &'a EfiEntry,
    handle: DeviceHandle,
) -> Result<DevicePathText<'a>> {
    let bs = entry.system_table().boot_services();
    let path = bs.open_protocol::<DevicePathProtocol>(handle)?;
    let path_to_text = bs.find_first_and_open::<DevicePathToTextProtocol>()?;
    path_to_text.convert_device_path_to_text(&path, false, false)
}

/// Helper function to get the loaded image path.
pub fn loaded_image_path(entry: &EfiEntry) -> Result<DevicePathText<'_>> {
    let bs = entry.system_table().boot_services();
    let path_to_text = bs.find_first_and_open::<DevicePathToTextProtocol>()?;
    let loaded_image = bs.open_protocol::<LoadedImageProtocol>(entry.image_handle())?;
    if let Ok(file_path) = loaded_image.file_path() {
        path_to_text.convert_device_path_to_text(&file_path, false, false)
    } else {
        let device_path = bs.open_protocol::<DevicePathProtocol>(loaded_image.device_handle())?;
        path_to_text.convert_device_path_to_text(&device_path, false, false)
    }
}

/// Helper function to get the loaded image base address.
pub fn image_base(entry: &EfiEntry) -> Result<usize> {
    Ok(entry
        .system_table()
        .boot_services()
        .open_protocol::<LoadedImageProtocol>(entry.image_handle())
        .inspect_err(|e| efi_println!(entry, "Failed to open LoadedImageProtocol: {e}"))?
        .image_base())
}

#[cfg(all(target_arch = "x86_64", not(feature = "efi_boot_stub")))]
pub(crate) fn efi_to_e820_mem_type(efi_mem_type: EfiMemoryType) -> u32 {
    match efi_mem_type {
        efi_types::EFI_MEMORY_TYPE_LOADER_CODE
        | efi_types::EFI_MEMORY_TYPE_LOADER_DATA
        | efi_types::EFI_MEMORY_TYPE_BOOT_SERVICES_CODE
        | efi_types::EFI_MEMORY_TYPE_BOOT_SERVICES_DATA
        | efi_types::EFI_MEMORY_TYPE_CONVENTIONAL_MEMORY => boot::x86::E820_ADDRESS_TYPE_RAM,
        efi_types::EFI_MEMORY_TYPE_RUNTIME_SERVICES_CODE
        | efi_types::EFI_MEMORY_TYPE_RUNTIME_SERVICES_DATA
        | efi_types::EFI_MEMORY_TYPE_MEMORY_MAPPED_IO
        | efi_types::EFI_MEMORY_TYPE_MEMORY_MAPPED_IOPORT_SPACE
        | efi_types::EFI_MEMORY_TYPE_PAL_CODE
        | efi_types::EFI_MEMORY_TYPE_RESERVED_MEMORY_TYPE => boot::x86::E820_ADDRESS_TYPE_RESERVED,
        efi_types::EFI_MEMORY_TYPE_UNUSABLE_MEMORY => boot::x86::E820_ADDRESS_TYPE_UNUSABLE,
        efi_types::EFI_MEMORY_TYPE_ACPIRECLAIM_MEMORY => boot::x86::E820_ADDRESS_TYPE_ACPI,
        efi_types::EFI_MEMORY_TYPE_ACPIMEMORY_NVS => boot::x86::E820_ADDRESS_TYPE_NVS,
        efi_types::EFI_MEMORY_TYPE_PERSISTENT_MEMORY => boot::x86::E820_ADDRESS_TYPE_PMEM,
        v => panic!("Unmapped EFI memory type {:?}", v),
    }
}

/// Repetitively runs a closure until it signals completion or timeout.
///
/// * If `f` returns `Ok(R)`, an `Ok(Some(R))` is returned immediately.
/// * If `f` has been repetitively called and returning `Err(false)` for `timeout_duration`,  an
///   `Ok(None)` is returned. This is the time out case.
/// * If `f` returns `Err(true)` the timeout is reset.
pub fn loop_with_timeout<F, R>(
    efi_entry: &EfiEntry,
    timeout_duration: Duration,
    mut f: F,
) -> Result<Option<R>>
where
    F: FnMut() -> core::result::Result<R, bool>,
{
    let timeout = Timeout::new(efi_entry, timeout_duration)?;
    while !timeout.check()? {
        match f() {
            Ok(v) => return Ok(Some(v)),
            Err(true) => timeout.reset(timeout_duration)?,
            _ => {}
        }
    }
    Ok(None)
}

/// Waits for a key stroke value from simple text input.
///
/// # Returns
///
/// * Returns `Ok(Some(key))` if a key is received that satisfies `pred(key) == true`.
/// * Returns `Ok(None)` if no key is received that satisfies `pred(key) == true`.
/// * Returns `Err` on error.
pub fn wait_key_stroke(
    efi_entry: &EfiEntry,
    pred: impl Fn(EfiInputKey) -> bool,
    timeout: Duration,
) -> Result<Option<EfiInputKey>> {
    let input = efi_entry
        .system_table()
        .boot_services()
        .find_first_and_open::<SimpleTextInputProtocol>()?;
    loop_with_timeout(efi_entry, timeout, || -> core::result::Result<Result<EfiInputKey>, bool> {
        match input.read_key_stroke() {
            Ok(Some(key)) if pred(key) => Ok(Ok(key)),
            Err(e) => Ok(Err(e)),
            _ => Err(false),
        }
    })?
    .transpose()
}

// Converts an EFI memory type to a zbi_mem_range_t type.
#[cfg(feature = "fuchsia")]
pub(crate) fn efi_to_zbi_mem_range_type(efi_mem_type: EfiMemoryType) -> u32 {
    match efi_mem_type {
        efi_types::EFI_MEMORY_TYPE_LOADER_CODE
        | efi_types::EFI_MEMORY_TYPE_LOADER_DATA
        | efi_types::EFI_MEMORY_TYPE_BOOT_SERVICES_CODE
        | efi_types::EFI_MEMORY_TYPE_BOOT_SERVICES_DATA
        | efi_types::EFI_MEMORY_TYPE_CONVENTIONAL_MEMORY => zbi::zbi_format::ZBI_MEM_TYPE_RAM,
        _ => zbi::zbi_format::ZBI_MEM_TYPE_RESERVED,
    }
}

/// Find Memory attributes from EFI configuration_table
#[allow(unused)]
pub(crate) fn get_efi_mem_attr(entry: &EfiEntry) -> Option<EfiMemoryAttributesTable<'static>> {
    entry.system_table().configuration_table().and_then(|config_tables| {
        config_tables
            .iter()
            .find_map(|&table| {
                // SAFETY:
                // `table` is valid EFI Configuration table provided by EFI
                match unsafe { EfiMemoryAttributesTable::new(table) } {
                    Err(Error::NotFound) => None,
                    other => Some(other.ok()),
                }
            })
            .flatten()
    })
}

pub(crate) const SZ_MB: usize = 1024 * 1024;

/// Intermediate strucutre that can generate a `BootBuffer` instance.
pub(crate) struct GblEfiBootBuffer {
    general: GblVendorReservedMemory,
    kernel: Option<GblVendorReservedMemory>,
    ramdisk: Option<GblVendorReservedMemory>,
    fdt: Option<GblVendorReservedMemory>,
    pvmfw_data: Option<GblVendorReservedMemory>,
}

impl<'b> From<GblEfiBootBuffer> for BootBuffer<'b> {
    fn from(v: GblEfiBootBuffer) -> Self {
        Self::new(
            v.general.leak(),
            v.kernel.map(GblVendorReservedMemory::leak),
            v.ramdisk.map(GblVendorReservedMemory::leak),
            v.fdt.map(GblVendorReservedMemory::leak),
            v.pvmfw_data.map(GblVendorReservedMemory::leak),
        )
    }
}

/// Helper for getting boot buffer.
pub(crate) fn get_boot_buffer(entry: &EfiEntry, default: usize) -> Result<GblEfiBootBuffer> {
    let [kernel, ramdisk, fdt, pvmfw_data] = [
        GBL_EFI_BOOT_BUFFER_TYPE_KERNEL,
        GBL_EFI_BOOT_BUFFER_TYPE_RAMDISK,
        GBL_EFI_BOOT_BUFFER_TYPE_FDT,
        GBL_EFI_BOOT_BUFFER_TYPE_PVMFW_DATA,
    ]
    .map(|v| match gbl_get_boot_buffer(entry, v, 0) {
        Err(Error::NotFound) => Ok(None),
        v => v.map(Some),
    });

    let general = gbl_get_boot_buffer(entry, GBL_EFI_BOOT_BUFFER_TYPE_GENERAL_LOAD, default)?;
    Ok(GblEfiBootBuffer {
        general,
        kernel: kernel?,
        ramdisk: ramdisk?,
        fdt: fdt?,
        pvmfw_data: pvmfw_data?,
    })
}

/// Represents a fastboot buffer
pub(crate) struct FastbootBuffer<'a> {
    entry: &'a EfiEntry,
    // Uses option so that we can manually drop it.
    buffer: Option<GblVendorReservedMemory>,
}

impl<'a> FastbootBuffer<'a> {
    /// Requests the buffer.
    pub(crate) fn new(entry: &'a EfiEntry) -> Result<Self> {
        let buffer = Some(gbl_get_boot_buffer(
            entry,
            GBL_EFI_BOOT_BUFFER_TYPE_FASTBOOT_DOWNLOAD,
            512 * SZ_MB,
        )?);
        Ok(FastbootBuffer { entry, buffer })
    }

    /// Gets the buffer
    pub(crate) fn get(&mut self) -> &mut [u8] {
        self.buffer.as_mut().unwrap()
    }
}

impl Drop for FastbootBuffer<'_> {
    fn drop(&mut self) {
        self.buffer.take();
        gbl_clear_boot_buffer(self.entry, GBL_EFI_BOOT_BUFFER_TYPE_FASTBOOT_DOWNLOAD).unwrap();
    }
}

/// EFI implementation of GblTime.
pub(crate) struct EfiTime<'a> {
    /// EFI timestamp protocol handle.
    ts: Protocol<'a, TimestampProtocol>,
    /// Timestamp frequency in Hz.
    frequency: u64,
    /// Timestamp maximum value before wrap-around.
    end_value: u64,
    // We need `PhantomData` here because in test builds, `Protocol` might be mocked
    // in a way that drops the lifetime parameter `'a`, leading to an "unused lifetime" error.
    _marker: PhantomData<&'a ()>,
}

impl<'a> EfiTime<'a> {
    /// Creates a new instance of `EfiTime`.
    pub(crate) fn new(ts: Protocol<'a, TimestampProtocol>) -> Result<Self> {
        let props = ts.get_properties()?;
        Ok(Self {
            ts,
            frequency: props.frequency,
            end_value: props.end_value,
            _marker: PhantomData,
        })
    }
}

impl GblTime for EfiTime<'_> {
    fn current_tick(&self) -> Result<u64> {
        self.ts.get_timestamp()
    }

    fn elapsed_ticks(&self, start: u64) -> Result<u64> {
        let end = self.current_tick()?;
        if end >= start {
            Ok(end - start)
        } else {
            Ok(self.end_value - start + end + 1)
        }
    }

    fn ticks_to_us(&self, ticks: u64) -> u64 {
        if self.frequency == 0 {
            return 0;
        }
        ((ticks as u128 * 1_000_000) / self.frequency as u128) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use efi_mocks::protocol::timestamp::MockTimestampProtocol;
    use efi_types::EfiTimestampProperties;
    use libgbl::metrics::GblTime;

    #[test]
    fn test_efi_time_new() {
        let mut mock_ts = MockTimestampProtocol::new();
        mock_ts
            .expect_get_properties()
            .returning(|| Ok(EfiTimestampProperties { frequency: 1000, end_value: 999_999 }));

        let efi_time = EfiTime::new(mock_ts).unwrap();

        assert_eq!(efi_time.frequency, 1000);
        assert_eq!(efi_time.end_value, 999_999);
    }

    #[test]
    fn test_efi_time_current_tick() {
        let mut mock_ts = MockTimestampProtocol::new();
        mock_ts.expect_get_timestamp().returning(|| Ok(1234));
        let efi_time =
            EfiTime { ts: mock_ts, frequency: 1000, end_value: 999_999, _marker: PhantomData };

        let tick = efi_time.current_tick().unwrap();

        assert_eq!(tick, 1234);
    }

    #[test]
    fn test_efi_time_elapsed_ticks() {
        let mut mock_ts = MockTimestampProtocol::new();
        mock_ts.expect_get_timestamp().returning(|| Ok(500));
        let efi_time =
            EfiTime { ts: mock_ts, frequency: 1000, end_value: 999_999, _marker: PhantomData };

        let elapsed = efi_time.elapsed_ticks(100).unwrap();

        assert_eq!(elapsed, 400);
    }

    #[test]
    fn test_efi_time_elapsed_ticks_wrap() {
        let mut mock_ts = MockTimestampProtocol::new();
        mock_ts.expect_get_timestamp().returning(|| Ok(100));
        let efi_time =
            EfiTime { ts: mock_ts, frequency: 1000, end_value: 999_999, _marker: PhantomData };

        let elapsed = efi_time.elapsed_ticks(900_000).unwrap();

        assert_eq!(elapsed, 100_100);
    }

    #[test]
    fn test_efi_time_ticks_to_us() {
        let mock_ts = MockTimestampProtocol::new();
        let efi_time =
            EfiTime { ts: mock_ts, frequency: 1000, end_value: 999_999, _marker: PhantomData };

        let us = efi_time.ticks_to_us(1);

        // 1000 Hz = 0.001 seconds per tick = 1000 us per tick
        assert_eq!(us, 1000);
    }

    #[test]
    fn test_efi_time_ticks_to_us_zero_freq() {
        let mock_ts = MockTimestampProtocol::new();
        let efi_time =
            EfiTime { ts: mock_ts, frequency: 0, end_value: 999_999, _marker: PhantomData };

        let us = efi_time.ticks_to_us(100);

        assert_eq!(us, 0);
    }
}
