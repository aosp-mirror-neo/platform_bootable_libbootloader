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

//! Linux kernel image header attribute parsing for GBL Android boot.

use cfg_if::cfg_if;
use liberror::Error;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const MISSED_IMAGE_SIZE_ERROR_MSG: &str = "Cannot boot kernel: image_size is unspecified or zero";

#[cfg(target_arch = "aarch64")]
const MISSED_PAGE_SIZE_ERROR_MSG: &str = "Cannot boot kernel: page_size is unspecified";

/// Kernel attributes parsed from the image header.
pub(crate) struct KernelAttributes {
    /// Memory footprint of the kernel region.
    pub(crate) reserved_size: usize,
    /// Alignment page size.
    pub(crate) page_size: usize,
}

/// Parses the kernel image header for the current target architecture.
pub(crate) fn parse_kernel_attributes(kernel: &[u8]) -> Result<KernelAttributes, Error> {
    cfg_if! {
        if #[cfg(target_arch = "aarch64")] {
            let h = boot::parse_aarch64(kernel)?;
            let image_size = h.image_size.ok_or(Error::Other(Some(MISSED_IMAGE_SIZE_ERROR_MSG)))?;
            let page_size = h.page_size.ok_or(Error::Other(Some(MISSED_PAGE_SIZE_ERROR_MSG)))?;
            Ok(KernelAttributes {
                // Account for potential appended payloads so kernel size exceeds header image_size.
                reserved_size: kernel.len().max(image_size),
                page_size,
            })
        } else if #[cfg(target_arch = "riscv64")] {
            let h = boot::parse_riscv64(kernel)?;
            let image_size = h.image_size.ok_or(Error::Other(Some(MISSED_IMAGE_SIZE_ERROR_MSG)))?;
            Ok(KernelAttributes {
                // Account for potential appended payloads so kernel size exceeds header image_size.
                reserved_size: kernel.len().max(image_size),
                page_size: crate::constants::PAGE_SIZE,
            })
        } else {
            let _ = kernel;
            Ok(KernelAttributes {
                reserved_size: kernel.len(),
                page_size: crate::constants::PAGE_SIZE,
            })
        }
    }
}
