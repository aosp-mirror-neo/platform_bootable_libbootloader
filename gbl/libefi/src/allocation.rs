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

use crate::{AllocationAddress, EfiEntry, RuntimeServices};
#[cfg(feature = "gbl_tracing")]
use core::sync::atomic::AtomicUsize;
use core::{
    alloc::{GlobalAlloc, Layout},
    mem::size_of,
    ptr::{copy, null_mut},
    slice::from_raw_parts,
    sync::atomic::{AtomicBool, Ordering},
};
use efi_types::EFI_MEMORY_TYPE_LOADER_DATA;
use liberror::{Error, Result};
use safemath::SafeNum;
use spin::Once;

// Alignment guaranteed by EFI AllocatePoll()
const EFI_ALLOCATE_POOL_ALIGNMENT: usize = 8;
// Page size of AllocatePages() by UEFI spec.
const EFI_PAGE_SIZE: usize = efi_types::EFI_PAGE_SIZE as usize;

/// Installs [`EfiAllocator`] as the UEFI application's global allocator and exports the unmangled
/// `EFI_GLOBAL_ALLOCATOR` symbol linked by `libefi` with the exact type expected by its
/// `unsafe extern "Rust"` declaration.
///
/// This is only useful for real UEFI applications; attempting to install the global allocator for
/// host-side unit tests will cause the test to panic immediately.
#[macro_export]
macro_rules! efi_global_allocator {
    () => {
        // SAFETY:
        // * `EFI_GLOBAL_ALLOCATOR` is a GBL-specific symbol name that does not collide with any
        //   other symbol (including C or firmware symbols) in the linked UEFI binary.
        // * Expanding `$crate::EfiAllocator` guarantees by construction that this definition's
        //   type matches `libefi`'s
        //   `unsafe extern "Rust" { safe static EFI_GLOBAL_ALLOCATOR: EfiAllocator; }`
        //   declaration, which the linker does not check.
        #[unsafe(no_mangle)]
        #[global_allocator]
        static EFI_GLOBAL_ALLOCATOR: $crate::EfiAllocator = $crate::EfiAllocator::new();
    };
}

/// Implements a global allocator using `EFI_BOOT_SERVICES.AllocatePool()/FreePool()`.
///
/// Install in a UEFI application crate using [`efi::efi_global_allocator!`]:
///
/// ```no_run
/// efi::efi_global_allocator!();
/// ```
///
/// This is only useful for real UEFI applications; attempting to install the global allocator
/// for host-side unit tests will cause the test to panic immediately.
pub struct EfiAllocator {
    /// Initialized once by `init_efi_global_alloc`.
    state: Once<EfiAllocatorState>,
    /// Set by `exit_efi_global_alloc` after `ExitBootServices()`.
    exited: AtomicBool,
}

struct EfiAllocatorState {
    entry: EfiEntry,
    runtime_services: Option<RuntimeServices>,
}

// SAFETY: `EfiAllocatorState` only holds the firmware-provided image handle, system table
// pointer, and runtime services function table. It is written once by `init_efi_global_alloc()`
// and never mutated afterward, and UEFI applications execute on a single processor, so moving
// `EfiAllocatorState` between execution contexts cannot race.
unsafe impl Send for EfiAllocatorState {}

// SAFETY: See `Send` implementation above; shared references to `EfiAllocatorState` only read
// immutable fields written during `init_efi_global_alloc()`, and UEFI runs on a single processor.
unsafe impl Sync for EfiAllocatorState {}

// Defined in the UEFI application binary via `efi_global_allocator!()`.
//
// SAFETY:
// * Every binary that links a codegen unit referencing `EFI_GLOBAL_ALLOCATOR` defines it via
//   `efi_global_allocator!()` as an unmangled `static` of exact type `EfiAllocator`, initialized
//   with `EfiAllocator::new()` and live for `'static` (omitting `efi_global_allocator!()` fails at
//   link time with an undefined symbol).
// * `EfiAllocator` is `Sync` and mutates only through interior mutability (`Once` and
//   `AtomicBool`), so shared references to `EFI_GLOBAL_ALLOCATOR` from safe code are sound at all
//   points in the program.
unsafe extern "Rust" {
    safe static EFI_GLOBAL_ALLOCATOR: EfiAllocator;
}

/// Calls `f` with a reference to the library's global `EfiEntry` if initialized and boot
/// services have not exited.
pub(crate) fn with_internal_efi_entry<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&EfiEntry) -> R,
{
    let entry = EFI_GLOBAL_ALLOCATOR.efi_entry()?;
    Some(f(entry))
}

/// An internal API to obtain the library's global `RuntimeServices`.
pub(crate) fn internal_runtime_services() -> Option<RuntimeServices> {
    EFI_GLOBAL_ALLOCATOR.state.get().and_then(|s| s.runtime_services)
}

/// Try to print via `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL` in `EFI_SYSTEM_TABLE.ConOut`.
///
/// Errors are ignored.
#[macro_export]
macro_rules! efi_try_print {
    ($( $x:expr ),* $(,)? ) => {
        {
            let _ = $crate::allocation::with_internal_efi_entry(|entry| -> liberror::Result<()> {
                use core::fmt::Write;
                write!(entry.system_table_checked()?.con_out()?, $($x,)*)?;
                Ok(())
            });
        }
    };
}

/// Initializes global allocator.
pub(crate) fn init_efi_global_alloc(efi_entry: EfiEntry) -> Result<()> {
    if EFI_GLOBAL_ALLOCATOR.exited.load(Ordering::Acquire) {
        return Err(Error::AlreadyStarted);
    }
    let mut initialized_now = false;
    EFI_GLOBAL_ALLOCATOR.state.call_once(|| {
        initialized_now = true;
        let runtime_services =
            efi_entry.system_table_checked().and_then(|v| v.runtime_services_checked()).ok();
        EfiAllocatorState { entry: efi_entry, runtime_services }
    });
    if !initialized_now {
        return Err(Error::AlreadyStarted);
    }
    Ok(())
}

/// Internal API to invalidate global allocator after ExitBootService().
pub(crate) fn exit_efi_global_alloc() {
    EFI_GLOBAL_ALLOCATOR.exited.store(true, Ordering::Release);
}

impl Default for EfiAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl EfiAllocator {
    /// Creates a new instance.
    pub const fn new() -> Self {
        Self { state: Once::new(), exited: AtomicBool::new(false) }
    }

    /// Gets a reference to `EfiEntry` tied to `self`'s borrow if boot services are active.
    fn efi_entry(&self) -> Option<&EfiEntry> {
        let state = self.state.get()?;
        (!self.exited.load(Ordering::Acquire)).then_some(&state.entry)
    }

    /// Computes the number of pages with a total size no smaller than `size`.
    fn pages(size: usize) -> Result<usize> {
        Ok(usize::try_from(SafeNum::from(size).round_up(EFI_PAGE_SIZE))? / EFI_PAGE_SIZE)
    }

    /// Allocates memory via EFI `AllocatePages()`.
    fn allocate_pages(&self, size: usize) -> Result<*mut u8> {
        let entry = self.efi_entry().ok_or(Error::InvalidState)?;
        let bs = entry.system_table_checked()?.boot_services_checked()?;
        let ptr = bs.allocate_pages(
            EFI_MEMORY_TYPE_LOADER_DATA,
            AllocationAddress::Any,
            Self::pages(size)?,
        )?;
        Ok(ptr as _)
    }

    /// Deallocates memory previously allocated by `allocate_pages()`.
    ///
    /// Errors are logged but ignored.
    fn deallocate_pages(&self, ptr: *mut u8, size: usize) {
        let Some(entry) = self.efi_entry() else {
            // After EFI_BOOT_SERVICES.ExitBootServices(), all allocated memory is considered
            // leaked and under full ownership of subsequent OS loader code.
            return;
        };
        let _ = entry
            .system_table_checked()
            .and_then(|v| v.boot_services_checked())
            .and_then(|v| v.free_pages(ptr as *mut _, Self::pages(size).unwrap()))
            .inspect_err(|e| efi_try_print!("Failed to deallocate pages: {e}\r\n"));
    }

    /// Allocate memory via EFI_BOOT_SERVICES.AllocatePool().
    fn allocate(&self, size: usize) -> *mut u8 {
        self.efi_entry()
            .ok_or(Error::InvalidState)
            .and_then(|v| v.system_table_checked())
            .and_then(|v| v.boot_services_checked())
            .and_then(|v| v.allocate_pool(EFI_MEMORY_TYPE_LOADER_DATA, size))
            .inspect_err(|e| efi_try_print!("Failed to allocate: {e}"))
            .unwrap_or_default() as _
    }

    /// Deallocates memory previously allocated by `Self::allocate()`.
    ///
    /// Errors are logged but ignored.
    fn deallocate(&self, ptr: *mut u8) {
        // After EFI_BOOT_SERVICES.ExitBootServices(), there is no EFI entry and all allocated
        // memory is considered leaked and under full ownership of subsequent OS loader code.
        if let Some(entry) = self.efi_entry() {
            let _ = entry
                .system_table_checked()
                .and_then(|v| v.boot_services_checked())
                .and_then(|v| v.free_pool(ptr as *mut _))
                .inspect_err(|e| efi_try_print!("Failed to deallocate: {e}"));
        }
    }

    /// Selects whether to allocate by EFI pages and calculate the total alloc size accommodating
    /// alignment adjustment.
    fn select_alloc_type(layout: &Layout) -> Result<(bool, usize)> {
        let (sz, align) = (layout.size(), layout.align());
        let (by_pages, alloc_native_alignment) = match sz % EFI_PAGE_SIZE == 0 {
            true => (true, EFI_PAGE_SIZE),
            _ => (false, EFI_ALLOCATE_POOL_ALIGNMENT),
        };
        // If requested alignment is > alloc_alignment then make sure to allocate bigger buffer
        // to adjust ptr to be aligned and stores the real start address.
        Ok(match align > alloc_native_alignment {
            true => (by_pages, (SafeNum::from(align) + size_of::<usize>() + sz).try_into()?),
            _ => (by_pages, sz),
        })
    }
}

#[cfg(feature = "gbl_tracing")]
static HEAP_USAGE: AtomicUsize = AtomicUsize::new(0);

// SAFETY: This meets the `GlobalAlloc` safety requirements:
// * It does not unwind. Allocation failures are returned as null and deallocation failures are
//   logged and ignored. The remaining `unwrap()`/`assert!()` calls cannot fail for a layout that
//   `alloc()` already succeeded with, and `EfiAllocator` is only used as the global allocator in
//   UEFI applications built with `panic=abort`.
// * Layout calculations are correct. `alloc()` returns either null or a pointer to at least
//   `layout.size()` bytes aligned to `layout.align()`. When alignment adjustment is needed, it
//   over-allocates and stores the original pointer after the block, which `dealloc()` uses to free
//   the original allocation using the same size computed from `layout`.
// * It does not rely on allocations actually happening. Apart from optional heap usage tracing, it
//   has no side effects beyond allocating and freeing memory.
unsafe impl GlobalAlloc for EfiAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        (|| -> Result<*mut u8> {
            let (by_pages, alloc_sz) = Self::select_alloc_type(&layout)?;
            #[cfg(feature = "gbl_tracing")]
            {
                let total = HEAP_USAGE.fetch_add(alloc_sz, Ordering::Relaxed);
                trace::gbl_trace_add_heap_snapshot((total + alloc_sz) as _);
            }
            let ptr = match by_pages {
                false => self.allocate(alloc_sz),
                _ => self.allocate_pages(alloc_sz)?,
            };

            if ptr.is_null() {
                return Err(Error::Other(Some("Allocation failed")));
            } else if alloc_sz == layout.size() {
                // No need for alignment adjustment.
                return Ok(ptr);
            }
            let addr_bytes = (ptr as usize).to_ne_bytes();
            let offset = layout.align() - (ptr as usize % layout.align());
            assert!(offset <= alloc_sz && alloc_sz - offset >= layout.size());

            // SAFETY:
            // - `ptr` is guaranteed to point to buffer bigger than `layout.size()`, plus the
            //   alignment (and thus `offset`) and plus a usize value.
            unsafe {
                let ptr = ptr.add(offset);
                copy(addr_bytes.as_ptr(), ptr.add(layout.size()), addr_bytes.len());
                Ok(ptr)
            }
        })()
        .unwrap_or(null_mut()) as _
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let (by_pages, alloc_sz) = Self::select_alloc_type(&layout).unwrap();
        #[cfg(feature = "gbl_tracing")]
        {
            let total = HEAP_USAGE.fetch_sub(alloc_sz, Ordering::Relaxed);
            trace::gbl_trace_add_heap_snapshot((total - alloc_sz) as _);
        }
        let sz = layout.size();
        // Checks if alignment adjustment was performed and finds real allocated pointer.
        let ptr = match alloc_sz == sz {
            true => ptr,
            _ => {
                // SAFETY:
                // `ptr` guarantees to point to a buffer big enough to contain `layout.size()`,
                // plus a valid usize value.
                let addr_bytes = unsafe { from_raw_parts(ptr.add(sz), size_of::<usize>()) };
                usize::from_ne_bytes(addr_bytes.try_into().unwrap()) as _
            }
        };

        match by_pages {
            false => self.deallocate(ptr),
            _ => self.deallocate_pages(ptr, alloc_sz),
        };
    }
}
