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

use crate::{fastboot::efi_gbl_fastboot_entry, ops::Ops};
use efi::{efi_println, exit_boot_services, EfiEntry};
use libgbl::{
    android_boot::{android_main, BootBuffer},
    gbl_println, GblOps, Result,
};

/// Android bootloader main entry (before booting).
///
/// On success, returns a tuple of slices (ramdisk, fdt, kernel, remains).
pub fn efi_android_load<'a>(
    ops: &mut Ops,
    load: BootBuffer<'a>,
) -> Result<(&'a [u8], &'a [u8], &'a [u8], &'a mut [u8])> {
    let entry = ops.efi_entry;
    gbl_println!(ops, "Try booting as Android");
    Ok(android_main(ops, load, |fb| efi_gbl_fastboot_entry(entry, fb))?)
}

/// Exits boot services and boots loaded android images.
pub fn efi_android_boot(
    entry: EfiEntry,
    kernel: &'static [u8],
    ramdisk: &'static [u8],
    fdt: &'static [u8],
    remains: &'static mut [u8],
) -> Result<()> {
    efi_println!(entry, "");
    efi_println!(
        entry,
        "Booting kernel @ {:#x}, ramdisk @ {:#x}, fdt @ {:#x}",
        kernel.as_ptr() as usize,
        ramdisk.as_ptr() as usize,
        fdt.as_ptr() as usize
    );

    #[cfg(target_arch = "aarch64")]
    {
        // TODO(b/473552136): Temporary test for tracing functionality.
        #[cfg(feature = "gbl_tracing")]
        {
            unsafe extern "C" {
                safe fn get_peak_stack() -> usize;
            }
            efi_println!(entry, "max stack used: {} bytes", get_peak_stack());
        }
        let _ = exit_boot_services(entry, remains)?;
        // SAFETY: We currently targets at Cuttlefish emulator where images are provided valid.
        unsafe { boot::aarch64::jump_linux_el2_or_lower(kernel, ramdisk, fdt) };
    }

    #[cfg(any(target_arch = "x86_64"))]
    {
        use fdt::Fdt;
        use liberror::Error;
        use libgbl::android_boot::device_tree::PROP_BOOTARGS;

        const EFI_PAGE_SIZE: u64 = efi_types::EFI_PAGE_SIZE as u64;

        let fdt = Fdt::new(&fdt[..])?;
        let efi_mmap = exit_boot_services(entry, remains)?;
        // SAFETY: We currently target at Cuttlefish emulator where images are provided valid.
        unsafe {
            boot::x86::boot_linux_bzimage(
                kernel,
                ramdisk,
                fdt.get_property("chosen", PROP_BOOTARGS).unwrap(),
                |e820_entries| {
                    // Convert EFI memory type to e820 memory type.
                    if efi_mmap.len() > e820_entries.len() {
                        return Err(Error::MemoryMapCallbackError(-1));
                    }
                    for (idx, mem) in efi_mmap.into_iter().enumerate() {
                        e820_entries[idx] = boot::x86::e820entry {
                            addr: mem.physical_start,
                            size: mem.number_of_pages * EFI_PAGE_SIZE,
                            type_: crate::utils::efi_to_e820_mem_type(mem.memory_type),
                        };
                    }
                    Ok(efi_mmap.len().try_into().unwrap())
                },
                0x9_0000,
            )?;
        }
        unreachable!();
    }

    #[cfg(target_arch = "riscv64")]
    {
        let boot_hart_id = entry
            .system_table()
            .boot_services()
            .find_first_and_open::<efi::protocol::riscv::RiscvBootProtocol>()?
            .get_boot_hartid()?;
        efi_println!(entry, "riscv boot_hart_id: {}", boot_hart_id);
        let _ = exit_boot_services(entry, remains)?;
        // SAFETY: We currently target at Cuttlefish emulator where images are provided valid.
        unsafe { boot::riscv64::jump_linux(kernel, boot_hart_id, fdt) };
    }
}
