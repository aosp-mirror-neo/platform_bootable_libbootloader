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

//! This module provides an implementation of [BlockIo] backed by a file on the host.

use bytes::buf::UninitSlice;
use gbl_storage::{BlockInfo, BlockIo};
use liberror::Error;
use std::{
    fs::File,
    // Unix FS gives us `read_exact_at` and `write_all_at`,
    // which take immutable receivers and save a mutable file seek.
    // The alternative would be for `FileBlockIo` to store `file` via a RefCell.
    os::unix::fs::FileExt,
};

const BLOCK_SIZE: u64 = 512;

/// `FileBlockIo` implements [BlockIo] backed by a [File].
pub struct FileBlockIo {
    file: File,
    file_len: u64,
}

impl FileBlockIo {
    /// Creates a new instance from an existing file path.
    ///
    /// Block size is always hardcoded to 1.
    pub fn new(path: &str) -> Result<Self, Error> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| Error::Other(None))?;
        let metadata = file.metadata().map_err(|_| Error::Other(None))?;
        let file_len = metadata.len();
        Ok(Self { file, file_len })
    }

    /// Creates a new file of given size and returns a FileBlockIo.
    pub fn new_create(path: &str, size: u64) -> Result<Self, Error> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|_| Error::Other(None))?;
        file.set_len(size).map_err(|_| Error::Other(None))?;
        Ok(Self { file, file_len: size })
    }
}

// SAFETY:
// `read_blocks` guarantees `out` to be fully initialized on success.
unsafe impl BlockIo for FileBlockIo {
    fn info(&self) -> BlockInfo {
        BlockInfo {
            block_size: BLOCK_SIZE,
            erase_blocks_num: 1,
            num_blocks: self.file_len / BLOCK_SIZE,
            alignment: 1,
        }
    }

    async fn read_blocks<'a>(
        &self,
        blk_offset: u64,
        out: impl Into<&'a mut UninitSlice>,
    ) -> Result<(), Error> {
        let out = out.into();
        let offset = blk_offset * BLOCK_SIZE;
        let mut buf = vec![0u8; out.len()];
        self.file.read_exact_at(&mut buf, offset).map_err(|_| Error::Other(None))?;
        out.copy_from_slice(&buf);
        Ok(())
    }

    async fn write_blocks(&self, blk_offset: u64, data: &mut [u8]) -> Result<(), Error> {
        let offset = blk_offset * BLOCK_SIZE;
        self.file.write_all_at(data, offset).map_err(|_| Error::Other(None))?;
        Ok(())
    }

    async fn erase_blocks(&self, blk_offset: u64, num_blks: u64) -> Result<(), Error> {
        let offset = blk_offset * BLOCK_SIZE;
        let size = num_blks * BLOCK_SIZE;
        let zeros = vec![0u8; size as usize];
        self.file.write_all_at(&zeros, offset).map_err(|_| Error::Other(None))?;
        Ok(())
    }
}
