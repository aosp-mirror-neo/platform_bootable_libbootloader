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

//! Per-architecture Linux kernel image header parsers.
//!
//! Each parser returns the header fields as encoded; `Option<usize>` signals the header
//! itself does not provide a value. Consumer-side policy (defaults, "must be non-zero")
//! belongs to callers. `Err` is returned only for structurally invalid headers.

#[cfg(any(target_arch = "aarch64", test))]
pub use aarch64::{parse_aarch64, Aarch64Attributes};

#[cfg(any(target_arch = "aarch64", test))]
mod aarch64 {
    use core::mem::size_of;
    use liberror::{Error, Result};
    use static_assertions::const_assert_eq;
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref};

    const AARCH64_MAGIC: [u8; 4] = *b"ARM\x64";

    /// arm64 Linux kernel image header (per Documentation/arm64/booting.rst).
    #[repr(C, packed)]
    #[derive(Copy, Clone, Debug, Immutable, FromBytes, IntoBytes, KnownLayout)]
    struct Aarch64ImageHeader {
        code0: u32,
        code1: u32,
        text_offset: u64,
        image_size: u64,
        flags: u64,
        res2: u64,
        res3: u64,
        res4: u64,
        magic: [u8; 4], // "ARM\x64" at 0x38
        pe_header_offset: u32,
    }
    const_assert_eq!(size_of::<Aarch64ImageHeader>(), 64);

    impl Aarch64ImageHeader {
        fn check_magic(&self) -> Result<()> {
            (self.magic == AARCH64_MAGIC).then_some(()).ok_or(Error::BadMagic)
        }

        /// Runtime memory footprint. `None` when the header reports 0 (pre-Linux 3.17).
        fn image_size(&self) -> Option<usize> {
            usize::try_from(u64::from_le(self.image_size)).ok().filter(|&s| s != 0)
        }

        /// Page size from `flags[2:1]`. `None` when bits are 00 ("unspecified").
        fn page_size(&self) -> Option<usize> {
            match bits(u64::from_le(self.flags), 1, 2) {
                1 => Some(4 * 1024),
                2 => Some(16 * 1024),
                3 => Some(64 * 1024),
                _ => None,
            }
        }
    }

    /// Attributes extracted from an arm64 Linux kernel image header.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub struct Aarch64Attributes {
        /// `header.image_size`. `None` when the header reports 0 (pre-Linux 3.17).
        pub image_size: Option<usize>,
        /// Page size from `flags[2:1]`. `None` when bits are 00 ("unspecified").
        pub page_size: Option<usize>,
    }

    /// Parses the arm64 kernel image header. `Err` only on short buffer or bad magic.
    pub fn parse_aarch64(image: &[u8]) -> Result<Aarch64Attributes> {
        let (header, _) = Ref::<_, Aarch64ImageHeader>::new_from_prefix(image)
            .ok_or(Error::BufferTooSmall(Some(size_of::<Aarch64ImageHeader>())))?;
        header.check_magic()?;
        Ok(Aarch64Attributes { image_size: header.image_size(), page_size: header.page_size() })
    }

    /// Returns bits `[hi:lo]` of `value` (both inclusive) as a right-aligned integer.
    fn bits(value: u64, lo: u32, hi: u32) -> u64 {
        let width = hi - lo + 1;
        (value >> lo) & ((1u64 << width) - 1)
    }
}

#[cfg(any(target_arch = "riscv64", test))]
pub use riscv64::{parse_riscv64, Riscv64Attributes};

#[cfg(any(target_arch = "riscv64", test))]
mod riscv64 {
    use core::mem::size_of;
    use liberror::{Error, Result};
    use static_assertions::const_assert_eq;
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref};

    const RISCV64_MAGIC2: [u8; 4] = *b"RSC\x05";

    /// RISC-V Linux kernel image header (per Documentation/riscv/boot-image-header.rst).
    #[repr(C, packed)]
    #[derive(Copy, Clone, Debug, Immutable, FromBytes, IntoBytes, KnownLayout)]
    struct Riscv64ImageHeader {
        code0: u32,
        code1: u32,
        text_offset: u64,
        image_size: u64,
        flags: u64,
        version: u32,
        res1: u32,
        res2: u64,
        magic: [u8; 8],  // legacy v0.1 magic
        magic2: [u8; 4], // "RSC\x05" at 0x38 (v0.2+)
        res3: u32,
    }
    const_assert_eq!(size_of::<Riscv64ImageHeader>(), 64);

    impl Riscv64ImageHeader {
        fn check_magic(&self) -> Result<()> {
            (self.magic2 == RISCV64_MAGIC2).then_some(()).ok_or(Error::BadMagic)
        }

        /// Runtime memory footprint. `None` when the header reports 0.
        fn image_size(&self) -> Option<usize> {
            usize::try_from(u64::from_le(self.image_size)).ok().filter(|&s| s != 0)
        }
    }

    /// Attributes extracted from a RISC-V Linux kernel image header.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub struct Riscv64Attributes {
        /// `header.image_size`. `None` when the header reports 0.
        pub image_size: Option<usize>,
    }

    /// Parses the RISC-V kernel image header. `Err` only on short buffer or bad v0.2+ magic.
    pub fn parse_riscv64(image: &[u8]) -> Result<Riscv64Attributes> {
        let (header, _) = Ref::<_, Riscv64ImageHeader>::new_from_prefix(image)
            .ok_or(Error::BufferTooSmall(Some(size_of::<Riscv64ImageHeader>())))?;
        header.check_magic()?;
        Ok(Riscv64Attributes { image_size: header.image_size() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_4K: &[u8; 64] = include_bytes!("../test/data/aarch64_4k_header.bin");
    const REAL_16K: &[u8; 64] = include_bytes!("../test/data/aarch64_16k_header.bin");
    const INVALID: &[u8; 64] = include_bytes!("../test/data/aarch64_invalid_header.bin");

    #[test]
    fn aarch64_4k_real_header() {
        let attrs: Aarch64Attributes = parse_aarch64(REAL_4K).unwrap();
        assert_eq!(attrs.page_size, Some(4096));
        assert!(attrs.image_size.is_some());
    }

    #[test]
    fn aarch64_16k_real_header() {
        let attrs: Aarch64Attributes = parse_aarch64(REAL_16K).unwrap();
        assert_eq!(attrs.page_size, Some(16 * 1024));
        assert!(attrs.image_size.is_some());
    }

    #[test]
    fn aarch64_invalid_header_returns_bad_magic() {
        assert!(matches!(parse_aarch64(INVALID), Err(liberror::Error::BadMagic)));
    }

    #[test]
    fn aarch64_short_buffer_returns_err() {
        let buf = [0u8; 32];
        assert!(matches!(parse_aarch64(&buf), Err(liberror::Error::BufferTooSmall(Some(64)))));
    }

    #[test]
    fn aarch64_image_size_zero_returns_none() {
        let mut buf = *REAL_4K;
        buf[0x10..0x18].fill(0);
        let attrs = parse_aarch64(&buf).unwrap();
        assert_eq!(attrs.image_size, None);
        assert_eq!(attrs.page_size, Some(4096));
    }

    #[test]
    fn aarch64_page_size_unspecified_returns_none() {
        // Clear flag bits [2:1] (the "unspecified" encoding).
        let mut buf = *REAL_4K;
        let flags = u64::from_le_bytes(buf[0x18..0x20].try_into().unwrap()) & !0b110;
        buf[0x18..0x20].copy_from_slice(&flags.to_le_bytes());
        let attrs = parse_aarch64(&buf).unwrap();
        assert_eq!(attrs.page_size, None);
        assert!(attrs.image_size.is_some());
    }

    #[test]
    fn riscv64_valid_header() {
        let mut buf = [0u8; 64];
        buf[0x10..0x18].copy_from_slice(&0x0020_0000u64.to_le_bytes());
        buf[0x38..0x3c].copy_from_slice(b"RSC\x05");
        let attrs = parse_riscv64(&buf).unwrap();
        assert_eq!(attrs, Riscv64Attributes { image_size: Some(0x0020_0000) });
    }

    #[test]
    fn riscv64_invalid_magic_returns_bad_magic() {
        let buf = [0u8; 64];
        assert!(matches!(parse_riscv64(&buf), Err(liberror::Error::BadMagic)));
    }

    #[test]
    fn riscv64_short_buffer_returns_err() {
        let buf = [0u8; 32];
        assert!(matches!(parse_riscv64(&buf), Err(liberror::Error::BufferTooSmall(Some(64)))));
    }

    #[test]
    fn riscv64_image_size_zero_returns_none() {
        let mut buf = [0u8; 64];
        buf[0x38..0x3c].copy_from_slice(b"RSC\x05");
        let attrs = parse_riscv64(&buf).unwrap();
        assert_eq!(attrs, Riscv64Attributes { image_size: None });
    }
}
