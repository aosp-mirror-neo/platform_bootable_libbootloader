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

//! Gzip and LZ4 decompression.

#![cfg_attr(not(test), no_std)]

// gzip [DeflateDecoder] requires heap allocation.
extern crate alloc;

use liberror::{Error, Result};
use lz4_flex::decompress_into;
use zune_inflate::DeflateDecoder;

const LZ4_NEXT_BLOCK_FAILED_ERROR_MESSAGE: &str =
    "Failed to handle next block of lz4-compressed data";

/// Returns whether `data` starts with the gzip magic header.
fn is_gzip_compressed(data: &[u8]) -> bool {
    data.starts_with(b"\x1f\x8b")
}

/// Returns whether `data` starts with the legacy LZ4 frame magic header.
fn is_lz4_compressed(data: &[u8]) -> bool {
    data.starts_with(b"\x02\x21\x4c\x18")
}

/// To iterate over compressed blocks within lz4 structure.
struct LZ4BlocksIterator<'a> {
    data: &'a [u8],
}

impl<'a> LZ4BlocksIterator<'a> {
    /// Creates a new iterator from lz4 payload.
    fn new(data: &'a [u8]) -> Self {
        LZ4BlocksIterator { data }
    }
}

impl<'a> Iterator for LZ4BlocksIterator<'a> {
    type Item = Result<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        let Some((block_size, data)) = self.data.split_at_checked(4) else {
            return Some(Err(Error::Other(Some(LZ4_NEXT_BLOCK_FAILED_ERROR_MESSAGE))));
        };
        self.data = data;

        let block_size = u32::from_le_bytes(block_size.try_into().unwrap()).try_into().unwrap();
        // Hit end marker
        if block_size == 0 {
            return None;
        }

        let Some((block_content, data)) = self.data.split_at_checked(block_size) else {
            return Some(Err(Error::Other(Some(LZ4_NEXT_BLOCK_FAILED_ERROR_MESSAGE))));
        };
        self.data = data;

        Some(Ok(block_content))
    }
}

/// Decompresses lz4 `content` (a legacy frame without the magic number) into `out`.
fn decompress_lz4(content: &[u8], out: &mut [u8]) -> Result<usize> {
    // Disable tracing by default to avoid having too many memcpy related calls.
    let _guard = trace::TraceGuard::new(false);
    let blocks = LZ4BlocksIterator::new(content);
    let mut out_pos = 0;

    for block in blocks {
        out_pos += decompress_into(block?, &mut out[out_pos..])
            .map_err(|_| Error::Other(Some("Failed to decompress lz4 block")))?;
    }

    Ok(out_pos)
}

/// Decompresses gzip `content` into `out`.
///
/// Dynamic allocation is used inside `decoder.decode_gzip()`.
fn decompress_gzip(content: &[u8], out: &mut [u8]) -> Result<usize> {
    let mut decoder = DeflateDecoder::new(content);

    let decompressed_data =
        decoder.decode_gzip().map_err(|_| Error::Other(Some("Failed to decompress gzip data")))?;

    let decompressed_len = decompressed_data.len();
    out.get_mut(..decompressed_len)
        .ok_or(Error::BufferTooSmall(Some(decompressed_len)))?
        .clone_from_slice(&decompressed_data);

    Ok(decompressed_len)
}

/// Decompresses `data` into `out`, or copies it if uncompressed.
///
/// Supported formats: gzip, legacy LZ4 frames (`lz4 -l`, used for Linux kernels) and plain
/// (uncompressed). Anything else, including the newer LZ4 frame format, is copied unchanged.
///
/// Returns the size of the data written into `out`.
// Not inlined, so that LTO keeps this opt-level=3 code out of size-optimized callers.
#[inline(never)]
pub fn decompress_or_copy(data: &[u8], out: &mut [u8]) -> Result<usize> {
    if is_gzip_compressed(data) {
        decompress_gzip(data, out)
    } else if is_lz4_compressed(data) {
        decompress_lz4(&data[4..], out)
    } else {
        out.get_mut(..data.len())
            .ok_or(Error::BufferTooSmall(Some(data.len())))?
            .clone_from_slice(data);
        Ok(data.len())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const GZ_KERNEL: &[u8] = include_bytes!("../../libgbl/testdata/android/gki_boot_gz_kernel");
    const GZ_KERNEL_UNCOMPRESSED: &[u8] =
        include_bytes!("../../libgbl/testdata/android/gki_boot_gz_kernel_uncompressed");
    const LZ4_KERNEL: &[u8] = include_bytes!("../../libgbl/testdata/android/gki_boot_lz4_kernel");
    const LZ4_KERNEL_UNCOMPRESSED: &[u8] =
        include_bytes!("../../libgbl/testdata/android/gki_boot_lz4_kernel_uncompressed");
    const RAW_KERNEL: &[u8] = include_bytes!("../../libgbl/testdata/android/kernel_a.img");

    // Asserts byte slice equality with clear error on first mismatch.
    // Avoids full data dump from default assert, which can be very verbose.
    fn assert_bytes_eq(actual: &[u8], expected: &[u8]) {
        assert_eq!(actual.len(), expected.len());

        for (i, (l, r)) in expected.iter().zip(actual.iter()).enumerate() {
            assert_eq!(l, r, "Unmatched byte at index {i}")
        }
    }

    // Uses an output buffer of exactly the expected size.
    fn check_decompress_or_copy(input: &[u8], expected_output: &[u8]) {
        let mut output_buffer = vec![0u8; expected_output.len()];

        let decompressed_len = decompress_or_copy(input, &mut output_buffer).unwrap();

        assert_bytes_eq(&output_buffer[..decompressed_len], expected_output);
    }

    #[test]
    fn decompress_or_copy_gzip() {
        check_decompress_or_copy(GZ_KERNEL, GZ_KERNEL_UNCOMPRESSED);
    }

    #[test]
    fn decompress_or_copy_lz4() {
        check_decompress_or_copy(LZ4_KERNEL, LZ4_KERNEL_UNCOMPRESSED);
    }

    #[test]
    fn decompress_or_copy_raw() {
        check_decompress_or_copy(RAW_KERNEL, RAW_KERNEL);
    }

    #[test]
    fn decompress_or_copy_buffer_too_small() {
        let mut out = vec![0u8; RAW_KERNEL.len() - 1];
        assert_eq!(
            decompress_or_copy(RAW_KERNEL, &mut out),
            Err(Error::BufferTooSmall(Some(RAW_KERNEL.len())))
        );

        let mut out = vec![0u8; GZ_KERNEL_UNCOMPRESSED.len() - 1];
        assert_eq!(
            decompress_or_copy(GZ_KERNEL, &mut out),
            Err(Error::BufferTooSmall(Some(GZ_KERNEL_UNCOMPRESSED.len())))
        );
    }

    #[test]
    fn decompress_or_copy_lz4_truncated() {
        let mut out = vec![0u8; LZ4_KERNEL_UNCOMPRESSED.len()];
        // Cut inside the first block's size field, then inside its data.
        for len in [6, 16] {
            assert_eq!(
                decompress_or_copy(&LZ4_KERNEL[..len], &mut out),
                Err(Error::Other(Some(LZ4_NEXT_BLOCK_FAILED_ERROR_MESSAGE)))
            );
        }
    }

    #[test]
    fn decompress_or_copy_gzip_corrupt() {
        let mut corrupt = GZ_KERNEL.to_vec();
        corrupt[GZ_KERNEL.len() / 2] ^= 0xff;
        let mut out = vec![0u8; GZ_KERNEL_UNCOMPRESSED.len()];
        assert_eq!(
            decompress_or_copy(&corrupt, &mut out),
            Err(Error::Other(Some("Failed to decompress gzip data")))
        );
    }
}
