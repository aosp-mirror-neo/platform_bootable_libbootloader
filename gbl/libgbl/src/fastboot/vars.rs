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

use super::{CommandResult, GblFastbootError};
use crate::{
    android_boot::hasher::{Hasher, Sha256},
    fastboot::{BufferPool, GblFastbootState, PinFutContainerTyped, ResolveMode},
    gbl_avb::ops::GblAvbOps,
    gbl_println,
    partition::{check_part_unique, split_partition_suffix, Partition, RawName},
    slots::{Bootability, Slot, Suffix},
    GblOps,
};
use avb::{slot_verify, HashtreeErrorMode, SlotVerifyError, SlotVerifyFlags, VbmetaVerifyError};
use core::{
    ffi::CStr,
    future::Future,
    mem::size_of,
    ops::{Deref, DerefMut},
    str::from_utf8,
};
use fastboot::VarInfoSender;
use gbl_async::{block_on, select, yield_now};
use gbl_storage::BlockIo;
use libbuild_number::BUILD_NUMBER;
use liberror::Error;
use liblp::LpMetadataPartition;
use libutils::{next_arg, snprintf, FromHexStr};
use zerocopy::{error::SizeError, FromBytes, IntoBytes, Unaligned};

const MAX_DOWNLOAD_SIZE: &str = "max-download-size";

const IS_USERSPACE: &str = "is-userspace";
const VERSION_GBL: &str = "version-gbl";

const SLOT_COUNT: &str = "slot-count";
const CURRENT_SLOT: &str = "current-slot";
const SLOT_SUCCESSFUL: &str = "slot-successful";
const SLOT_UNBOOTABLE: &str = "slot-unbootable";
const SLOT_RETRY_COUNT: &str = "slot-retry-count";
const HAS_SLOT: &str = "has-slot";
const FINGERPRINT: &str = "fingerprint";
const SYSTEM_FINGERPRINT_KEY: &str = "com.android.build.system.fingerprint";
// Maximum size of a `getvar` response buffer in `get_var_all_internal`. Currently sized for the
// system fingerprint, which is bounded by Android's `PROP_VALUE_MAX` (92 bytes, including the null
// terminator).
const GETVAR_RESPONSE_MAX_SIZE: usize = 92;

const MAX_FETCH_SIZE: &str = "max-fetch-size";
// Limited by DATA message which only allows 8 hex digits.
// Additionally fastboot upstream parses this value as int, so we only have 31 bits.
// Defensively capped to 512 MiB (block-aligned) to avoid scratch buffer copying
// in libstorage, provide regular progress reporting during `fastboot fetch`, and
// guard against buggy firmware that misreports IoAlign.
const MAX_FETCH_SIZE_VAL: &str = "0x20000000";

const PARTITION_SIZE: &str = "partition-size";
const PARTITION_TYPE: &str = "partition-type";
const PARTITION_GUID: &str = "partition-guid";
const PARTITION_START: &str = "partition-start";

const BLOCK_DEVICE: &str = "block-device";
const TOTAL_BLOCKS: &str = "total-blocks";
const BLOCK_SIZE: &str = "block-size";

const LOGICAL_BLOCK_SIZE: &str = "logical-block-size";
const ERASE_BLOCK_SIZE: &str = "erase-block-size";

const DEFAULT_BLOCK: &str = "gbl-default-block";

const UNLOCKED: &str = "unlocked";
const UNLOCKED_CRITICAL: &str = "unlocked-critical";

const STREAM_SEGMENT_SIZE: &str = "stream-segment-size";

const SNAPSHOT_UPDATE_STATUS: &str = "snapshot-update-status";

#[derive(FromBytes, IntoBytes, Unaligned)]
#[repr(C, packed)]
struct PartHasSlot(RawName, u8);

/// Query result of `getvar has-slot`.
///
/// If `PartHasSlot(part, NO)`, then `part` is the name of an unslotted partition.
/// If `PartHasSlot(name, YES)`, then `name` is the name-without-suffix of a slotted partition.
impl PartHasSlot {
    const NO: u8 = 0;
    const YES: u8 = 1;
}

/// Extracts the partition name from `LpMetadataPartition`.
fn lp_partition_name(partition: &LpMetadataPartition) -> Option<&str> {
    let name_bytes = partition.name.as_bytes();
    let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
    core::str::from_utf8(&name_bytes[..end]).ok()
}

/// A vector backed by a borrowed slice.
struct SliceVec<'a, T> {
    buf: &'a mut [T],
    len: usize,
}

impl<'a, T> SliceVec<'a, T> {
    fn new(buf: &'a mut [T]) -> Self {
        Self { buf, len: 0 }
    }

    fn push(&mut self, v: T) {
        if self.len >= self.buf.len() {
            panic!("SliceVec capacity exceeded: cap={}", self.buf.len());
        }
        self.buf[self.len] = v;
        self.len += 1;
    }
}

impl<T> Deref for SliceVec<'_, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.buf[..self.len]
    }
}

impl<T> DerefMut for SliceVec<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf[..self.len]
    }
}

impl<'a, T> From<SliceVec<'a, T>> for &'a [T] {
    fn from(v: SliceVec<'a, T>) -> Self {
        &v.buf[..v.len]
    }
}

struct FastbootSlotInfo {
    successful: &'static str,
    unbootable: &'static str,
    retry_count: usize,
}

impl From<Slot> for FastbootSlotInfo {
    fn from(slot: Slot) -> Self {
        match slot.bootability {
            Bootability::Successful(t) => {
                FastbootSlotInfo { successful: "yes", unbootable: "no", retry_count: t.0 }
            }
            Bootability::Unbootable(_) => {
                FastbootSlotInfo { successful: "no", unbootable: "yes", retry_count: 0 }
            }
            Bootability::Retriable(t) => {
                FastbootSlotInfo { successful: "no", unbootable: "no", retry_count: t.0 }
            }
        }
    }
}

/// Returns "yes" if true, "no" if false.
fn yes_no_str(value: bool) -> &'static str {
    match value {
        true => "yes",
        false => "no",
    }
}

/// Formats `slot-count` into `out`.
fn format_slot_count(slot_count: u8, out: &mut [u8]) -> &str {
    snprintf!(out, "{slot_count}")
}

/// Formats `current-slot` into `out`.
fn format_current_slot(slot: Slot, out: &mut [u8]) -> &str {
    snprintf!(out, "{}", slot.suffix.as_char())
}

/// Formats `unlocked` or `unlocked-critical` from `AvbDeviceStatus`.
fn format_unlocked(
    status: &crate::gbl_avb::AvbDeviceStatus,
    lock_type: fastboot::LockType,
) -> &'static str {
    let unlocked = match lock_type {
        fastboot::LockType::Device => status.is_unlocked,
        fastboot::LockType::Critical => status.is_unlocked_critical,
    };
    yes_no_str(unlocked)
}

/// Iterates all slots in the order of slot index.
pub(crate) fn slots_iter<'a>(
    gbl_ops: &mut impl GblOps<'a>,
) -> Result<impl Iterator<Item = Result<Slot, Error>> + '_, Error> {
    Ok((0..gbl_ops.get_slot_count()?).map(|idx| gbl_ops.get_slot_info(idx)))
}

/// Returns the device slot count, or `Ok(None)` when device slotting is not supported
/// (`get_slot_count()` returns `Ok(0)`, `Err(Error::Unsupported)`, or `Err(Error::NotFound)`).
pub(crate) fn slot_count_if_supported<'a>(
    gbl_ops: &mut impl GblOps<'a>,
) -> Result<Option<u8>, Error> {
    match gbl_ops.get_slot_count() {
        Ok(0) | Err(Error::Unsupported | Error::NotFound) => Ok(None),
        Ok(count) => Ok(Some(count)),
        Err(e) => Err(e),
    }
}

/// Set of slot suffixes (`'a'..='z'`) reported by [`GblOps`], as a bit mask.
#[derive(Copy, Clone, Default)]
pub(crate) struct SlotSuffixMask(u32);

impl SlotSuffixMask {
    /// Returns the mask bit for `suffix`. [`Suffix`] guarantees `'a'..='z'`, so the shift is in
    /// `0..26`.
    fn bit(suffix: Suffix) -> u32 {
        let c = suffix.as_char();
        debug_assert!(c.is_ascii_lowercase(), "slot suffix {c:?} is not in 'a'..='z'");
        1u32 << (u32::from(c) - u32::from('a'))
    }

    /// Collects the suffixes of all device slots from `gbl_ops`.
    ///
    /// Returns `Ok(None)` when device slotting is not supported (see
    /// [`slot_count_if_supported`]) and propagates `get_slot_info()` errors.
    pub(crate) fn new<'a>(gbl_ops: &mut impl GblOps<'a>) -> Result<Option<Self>, Error> {
        let Some(count) = slot_count_if_supported(gbl_ops)? else {
            return Ok(None);
        };
        let mut mask = 0u32;
        for idx in 0..count {
            mask |= Self::bit(gbl_ops.get_slot_info(idx)?.suffix);
        }
        Ok(Some(Self(mask)))
    }

    /// Splits `part` into `(base, suffix)` only if `suffix` is a slot suffix on this device.
    pub(crate) fn split(self, part: &str) -> Option<(&str, char)> {
        split_partition_suffix(part).filter(|(_, suffix)| {
            Suffix::from_char(*suffix).is_ok_and(|suffix| self.0 & Self::bit(suffix) != 0)
        })
    }
}

// See definition of [GblFastbootState] for docs on lifetimes and generics parameters.
impl<'a: 'c, 'b: 'c, 'c, 'd, B, P2, T, P, C, F> GblFastbootState<'a, 'b, 'c, 'd, B, P2, T, P, C, F>
where
    B: BlockIo,
    P2: BufferPool,
    T: DerefMut<Target = [u8]>,
    P: BufferPool,
    C: PinFutContainerTyped<'c, F>,
    F: Future<Output = ()> + 'c,
{
    /// Formats a built-in scalar variable that takes no arguments and is shared between
    /// `getvar` and `getvar all`.
    async fn get_builtin_var<'s>(
        &mut self,
        name: &str,
        out: &'s mut [u8],
    ) -> CommandResult<Option<&'s str>> {
        Ok(Some(match name {
            MAX_DOWNLOAD_SIZE => snprintf!(out, "{:#x}", self.max_download_size().await),
            IS_USERSPACE => snprintf!(out, "no"),
            VERSION_GBL => snprintf!(out, "gbl.{}", BUILD_NUMBER),
            MAX_FETCH_SIZE => snprintf!(out, "{}", MAX_FETCH_SIZE_VAL),
            DEFAULT_BLOCK => self.get_var_default_block(out)?,
            STREAM_SEGMENT_SIZE => self.get_var_stream_segment_size(out)?,
            _ => return Ok(None),
        }))
    }

    /// Sends a built-in scalar variable to `send` using [`Self::get_builtin_var`].
    async fn send_builtin_var(
        &mut self,
        name: &str,
        buf: &mut [u8],
        send: &mut impl VarInfoSender,
    ) -> CommandResult<()> {
        let val = self.get_builtin_var(name, buf).await?.ok_or(Error::InvalidInput)?;
        Ok(send.send_var_info(name, [], val).await?)
    }

    /// Entry point for "fastboot getvar <variable>..."
    pub(crate) async fn get_var_internal<'s, 't>(
        &mut self,
        gbl_ops: &mut impl GblOps<'a>,
        name: &CStr,
        args: impl Iterator<Item = &'t CStr> + Clone,
        out: &'s mut [u8],
    ) -> CommandResult<&'s str> {
        let args_str = args.clone().map(|v| v.to_str());
        // Checks that all arguments are valid str first.
        args_str.clone().find(|v| v.is_err()).unwrap_or(Ok(""))?;
        let args_str = args_str.map(|v| v.unwrap());
        let name_str = name.to_str()?;
        let sz = match self.get_var_native(gbl_ops, name_str, args_str, None, false, out).await? {
            Some(sz) => sz,
            None => gbl_ops.fastboot_variable(name, args, out)?,
        };
        Ok(from_utf8(out.get(..sz).ok_or("Invalid variable value size")?)?)
    }

    /// Looks up a Fastboot variable managed natively by GBL and writes its value into `out`.
    ///
    /// When `probe_only` is `true` (used to filter vendor entries in `getvar all`), reserved
    /// variables that are expensive to compute (disk, secure-world, or vendor callback I/O) only
    /// report whether GBL manages them instead of their formatted value, and `dynamic_parts`
    /// avoids re-reading `super`. Cheap variables always return their actual value.
    ///
    /// Returns `Ok(Some(len))` if GBL manages the variable, `Ok(None)` if the variable is not
    /// managed by GBL or the target partition is not found on GBL's disks, or `Err(e)` if GBL
    /// reserves it and the query fails for any other reason.
    async fn get_var_native<'t>(
        &mut self,
        gbl_ops: &mut impl GblOps<'a>,
        name_str: &str,
        args_str: impl Iterator<Item = &'t str> + Clone,
        dynamic_parts: Option<&[RawName]>,
        probe_only: bool,
        out: &mut [u8],
    ) -> CommandResult<Option<usize>> {
        let val = match name_str {
            MAX_DOWNLOAD_SIZE | IS_USERSPACE | VERSION_GBL | MAX_FETCH_SIZE | DEFAULT_BLOCK
            | STREAM_SEGMENT_SIZE => {
                Some(self.get_builtin_var(name_str, out).await?.ok_or(Error::InvalidInput)?)
            }
            SLOT_COUNT => Some(format_slot_count(gbl_ops.get_slot_count()?, out)),
            CURRENT_SLOT => Some(format_current_slot(gbl_ops.get_current_slot()?, out)),
            SLOT_SUCCESSFUL => Some(snprintf!(
                out,
                "{}",
                self.get_fastboot_slot_info(gbl_ops, args_str)?.successful
            )),
            SLOT_UNBOOTABLE => Some(snprintf!(
                out,
                "{}",
                self.get_fastboot_slot_info(gbl_ops, args_str)?.unbootable
            )),
            SLOT_RETRY_COUNT => Some(snprintf!(
                out,
                "{}",
                self.get_fastboot_slot_info(gbl_ops, args_str)?.retry_count
            )),
            HAS_SLOT => self.get_var_has_slot(gbl_ops, args_str, dynamic_parts, out).await?,
            // Reads `vbmeta`.
            FINGERPRINT => Some(match probe_only {
                true => "",
                false => self.get_var_fingerprint(gbl_ops, args_str, out).await?,
            }),
            // Note: Currently `partition-*` only covers GPT and raw block partitions in
            // `self.disks` (not dynamic partitions inside `super`). If `partition-*` is extended
            // to cover `super` dynamic partitions in the future, we may need to check `super`
            // here too.
            PARTITION_START => self.get_var_partition_start(args_str, out)?,
            PARTITION_SIZE => self.get_var_partition_size(gbl_ops, args_str, out)?,
            PARTITION_TYPE => self.get_var_partition_type(gbl_ops, args_str, probe_only, out)?,
            PARTITION_GUID => self.get_var_partition_guid(args_str, out)?,
            BLOCK_DEVICE => Some(self.get_var_block_device(args_str, out)?),
            LOGICAL_BLOCK_SIZE | ERASE_BLOCK_SIZE => {
                self.get_var_block_geometry(name_str, args_str, out)?
            }
            // Queries the secure world via AVB.
            UNLOCKED => Some(match probe_only {
                true => "",
                false => self.get_var_unlocked(gbl_ops, fastboot::LockType::Device, out)?,
            }),
            UNLOCKED_CRITICAL => Some(match probe_only {
                true => "",
                false => self.get_var_unlocked(gbl_ops, fastboot::LockType::Critical, out)?,
            }),
            // Waits for pending `misc` tasks and reads `misc`.
            SNAPSHOT_UPDATE_STATUS => Some(match probe_only {
                true => "",
                false => snprintf!(out, "{}", self.snapshot_merge_status(gbl_ops).await?),
            }),
            _ => None,
        };
        Ok(val.map(str::len))
    }

    /// Entry point for "fastboot getvar all..."
    ///
    /// TODO(b/465769208): Reuse code between `getvar` and `getvar all`.
    pub(crate) async fn get_var_all_internal(
        &mut self,
        gbl_ops: &mut impl GblOps<'a>,
        send: &mut impl VarInfoSender,
    ) -> CommandResult<()> {
        let mut buf = [0u8; GETVAR_RESPONSE_MAX_SIZE];
        self.send_builtin_var(MAX_DOWNLOAD_SIZE, &mut buf, send).await?;
        self.send_builtin_var(IS_USERSPACE, &mut buf, send).await?;
        self.send_builtin_var(VERSION_GBL, &mut buf, send).await?;
        let dynamic_parts = self.get_dynamic_partition_names(gbl_ops).await.unwrap_or_default();
        match gbl_ops.get_slot_count() {
            Ok(slot_count) => {
                send.send_var_info(SLOT_COUNT, [], format_slot_count(slot_count, &mut buf)).await?;

                // Variable may be optional. Continues instead of erroring out.
                match gbl_ops.get_current_slot() {
                    Ok(slot) => {
                        send.send_var_info(CURRENT_SLOT, [], format_current_slot(slot, &mut buf))
                            .await?
                    }
                    Err(e) => gbl_println!(gbl_ops, "Failed to get current_slot {e}"),
                };

                for idx in 0..slot_count {
                    // Variable may be optional. Continues instead of erroring out.
                    let Ok(slot) = gbl_ops.get_slot_info(idx).inspect_err(|e| {
                        gbl_println!(gbl_ops, "Failed to get slot_info for slot {idx}, {e}");
                    }) else {
                        continue;
                    };
                    let FastbootSlotInfo { successful, unbootable, retry_count } = slot.into();
                    let mut suffix_buf = [0u8; 4];
                    let suffix = snprintf!(suffix_buf, "{}", slot.suffix.as_char());
                    send.send_var_info(SLOT_SUCCESSFUL, [suffix], successful).await?;
                    send.send_var_info(SLOT_UNBOOTABLE, [suffix], unbootable).await?;
                    send.send_var_info(SLOT_RETRY_COUNT, [suffix], snprintf!(buf, "{retry_count}"))
                        .await?;
                    match self.get_system_fingerprint_for_slot(gbl_ops, suffix, &mut buf).await {
                        Ok(fp) => {
                            let mut part_buf = [0u8; 16];
                            send.send_var_info(
                                FINGERPRINT,
                                [snprintf!(part_buf, "system_{suffix}")],
                                fp,
                            )
                            .await?;
                        }
                        Err(Error::NotFound) => {}
                        Err(e) => gbl_println!(
                            gbl_ops,
                            "Failed to get fingerprint for slot {suffix}: {e:?}"
                        ),
                    }
                }
                self.get_all_partition_has_slot(gbl_ops, &dynamic_parts, send).await?;
            }
            Err(e) => gbl_println!(
                gbl_ops,
                "Slotting is not supported, failed to get {SLOT_COUNT}: {e}. Slot-related \
                fastboot variables cannot be provided."
            ),
        }
        self.send_builtin_var(MAX_FETCH_SIZE, &mut buf, send).await?;
        self.get_all_block_device(send).await?;
        self.send_builtin_var(DEFAULT_BLOCK, &mut buf, send).await?;
        for var in [LOGICAL_BLOCK_SIZE, ERASE_BLOCK_SIZE] {
            match self.get_var_block_geometry(var, [].into_iter(), &mut buf) {
                Ok(Some(val)) => send.send_var_info(var, [], val).await?,
                Ok(None) => {}
                Err(e) => gbl_println!(gbl_ops, "Failed to get {var}: {e}"),
            }
        }
        self.get_all_partition_vars(gbl_ops, send).await?;

        self.send_builtin_var(STREAM_SEGMENT_SIZE, &mut buf, send).await?;

        match gbl_ops.avb_read_device_status() {
            Ok(device_status) => {
                send.send_var_info(
                    UNLOCKED,
                    [],
                    format_unlocked(&device_status, fastboot::LockType::Device),
                )
                .await?;
                send.send_var_info(
                    UNLOCKED_CRITICAL,
                    [],
                    format_unlocked(&device_status, fastboot::LockType::Critical),
                )
                .await?;
            }
            Err(e) => gbl_println!(gbl_ops, "failed to read lock state: {e}"),
        };

        match self.snapshot_merge_status(gbl_ops).await {
            Ok(status) => {
                send.send_var_info(SNAPSHOT_UPDATE_STATUS, [], status.into()).await?;
            }
            Err(GblFastbootError::Libgbl(Error::Unsupported)) => {}
            Err(e) => gbl_println!(gbl_ops, "snapshot-update-status unavailable: {e}"),
        }

        // Gets platform specific variables
        let tasks = self.tasks;
        let async_task_state = self.data.async_task_state;
        let _ = gbl_ops.fastboot_visit_all_variables(|ops, args, val| {
            if let Some((first, rest_args)) = args.split_first_chunk::<1>() {
                // Needs to split ':' because the interface allows backend to pass ':' concatenated
                // string as a whole.
                let mut split_args =
                    args.iter().map(|s| s.to_str().unwrap_or("?")).flat_map(|s| s.split(':'));
                let var = split_args.next().unwrap_or("?");
                let res = block_on(select(
                    self.get_var_native(ops, var, split_args, Some(&dynamic_parts), true, &mut buf),
                    async {
                        loop {
                            tasks.borrow_mut().poll_all(async_task_state);
                            yield_now().await;
                        }
                    },
                ))
                .0;
                match res {
                    Some(Ok(None)) => {}
                    Some(Err(e)) => {
                        gbl_println!(ops, "Variable {var:?} is reserved by GBL (error: {e}).");
                        return;
                    }
                    _ => {
                        gbl_println!(ops, "Variable {var:?} is reserved by GBL.");
                        return;
                    }
                }
                let name = first[0].to_str().unwrap_or("?");
                let args = rest_args.iter().map(|v| v.to_str().unwrap_or("?"));
                let val = val.to_str().unwrap_or("?");
                // Manually polls async tasks so that we can still get parallelism while
                // running in the context of backend.
                let _ = block_on(select(send.send_var_info(name, args, val), async {
                    loop {
                        tasks.borrow_mut().poll_all(async_task_state);
                        yield_now().await;
                    }
                }))
                .0
                .transpose() // Option<Result<>> -> Result<Option<>>
                .inspect_err(|e| gbl_println!(ops, "Failed to get platform vars: {e}"));
            }
        });
        Ok(())
    }

    /// Gets the max-download-size variable.
    pub(crate) async fn max_download_size(&mut self) -> usize {
        if let Some(buf) = &self.current_download_buffer {
            buf.len()
        } else if let Some(buf) = self.buffer_pool.allocate() {
            buf.len()
        } else {
            let _wait_guard = super::WaitingForAsyncTasksGuard::new(self.data.async_task_state);
            self.buffer_pool.allocate_async().await.len()
        }
    }

    /// Parses and finds the size of the given partition.
    pub(crate) fn partition_size(
        &self,
        gbl_ops: &mut impl GblOps<'a>,
        part: &str,
    ) -> CommandResult<u64> {
        let (part, blk_id, off, sz) = self.parse_partition_arg(part)?;
        // If the user just gives the partition base name, resolve to the current slot.
        let (_, parts) =
            self.resolve_slotted_partitions(gbl_ops, part, blk_id, ResolveMode::CurrentSlot)?;
        // Slotted partition-size only make sense if they are all the same. Because it may be used
        // to copy AVB footer.
        for (_, p) in &parts[1..] {
            let (size, expected) = (p.size()?, parts[0].1.size()?);
            if size != expected {
                return Err(GblFastbootError::PartitionSizeMismatch(expected, size));
            }
        }
        let (start, end) = parts[0].1.sub(off, sz)?;
        Ok(end - start)
    }

    /// "fastboot getvar partition-size"
    fn get_var_partition_size<'s, 't>(
        &self,
        gbl_ops: &mut impl GblOps<'a>,
        mut args: impl Iterator<Item = &'t str> + Clone,
        out: &'s mut [u8],
    ) -> CommandResult<Option<&'s str>> {
        let raw_part = next_arg(&mut args).ok_or("Missing partition")?;
        match self.partition_size(gbl_ops, raw_part) {
            Ok(sz) => Ok(Some(snprintf!(out, "{:#x}", sz))),
            Err(GblFastbootError::Libgbl(Error::PartitionNotFound)) if !raw_part.contains('/') => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// "fastboot getvar partition-type"
    fn get_var_partition_type<'s, 't>(
        &self,
        gbl_ops: &mut impl GblOps<'a>,
        mut args: impl Iterator<Item = &'t str> + Clone,
        probe_only: bool,
        out: &'s mut [u8],
    ) -> CommandResult<Option<&'s str>> {
        let raw_part = next_arg(&mut args).ok_or("Missing partition")?;
        let part = self.parse_partition_arg(raw_part)?.0.ok_or("Missing partition")?;
        match self.find_partition(Some(part), None) {
            Ok(_) | Err(Error::NotUnique) => match probe_only {
                true => Ok(Some("")),
                false => {
                    let part_type = gbl_ops.fastboot_get_partition_type(part)?;
                    Ok(Some(snprintf!(out, "{part_type}")))
                }
            },
            Err(Error::PartitionNotFound) if !raw_part.contains('/') => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// "fastboot getvar partition-guid"
    fn get_var_partition_guid<'s, 't>(
        &self,
        mut args: impl Iterator<Item = &'t str> + Clone,
        out: &'s mut [u8],
    ) -> CommandResult<Option<&'s str>> {
        let raw_part = next_arg(&mut args).ok_or("Missing partition")?;
        let (part, blk_id, _, _) = self.parse_partition_arg(raw_part)?;
        let (_, ptn) = match self.find_partition(part, blk_id) {
            Ok(v) => v,
            Err(Error::PartitionNotFound) if !raw_part.contains('/') => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        match ptn {
            Partition::Gpt(gpt_partition) => {
                Ok(Some(snprintf!(out, "{}", gpt_partition.gpt_entry().guid)))
            }
            _ => Err("Not a GPT partition".into()),
        }
    }

    /// "fastboot getvar partition-start"
    fn get_var_partition_start<'s, 't>(
        &self,
        mut args: impl Iterator<Item = &'t str> + Clone,
        out: &'s mut [u8],
    ) -> CommandResult<Option<&'s str>> {
        let raw_part = next_arg(&mut args).ok_or("Missing partition")?;
        let (part, blk_id, _, _) = self.parse_partition_arg(raw_part)?;
        let (_, ptn) = match self.find_partition(part, blk_id) {
            Ok(v) => v,
            Err(Error::PartitionNotFound) if !raw_part.contains('/') => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        Ok(Some(snprintf!(out, "{:#x}", ptn.absolute_range()?.0)))
    }

    /// Gets all "partition-size/partition-type/partition-guid/partition-start"
    async fn get_all_partition_vars(
        &self,
        gbl_ops: &mut impl GblOps<'a>,
        responder: &mut impl VarInfoSender,
    ) -> CommandResult<()> {
        // Though any sub range of a GPT partition or raw block counts as a partition in GBL
        // Fastboot, for "getvar all" we only enumerate whole range GPT partitions.
        let disks = self.disks;
        // Allocates 36 bytes to fit partition GUID.
        let mut str_buf = [0u8; 36];
        for (idx, blk) in disks.iter().enumerate() {
            for ptn_idx in 0..blk.num_partitions().unwrap_or(0) {
                let ptn = blk.get_partition_by_idx(ptn_idx)?;
                let sz: u64 = ptn.size()?;
                let part = ptn.name()?;
                let part_type = gbl_ops.fastboot_get_partition_type(part)?;

                // Assumes max partition name length of 72 plus max u64 hex string length 18.
                let mut part_id_buf = [0u8; 128];
                // If partition is not unique, append block ID suffix.
                let part = match crate::partition::check_part_unique(disks, part) {
                    Ok(_) => snprintf!(part_id_buf, "{}", part),
                    Err(_) => snprintf!(part_id_buf, "{}/{:x}", part, idx),
                };
                responder
                    .send_var_info(
                        PARTITION_START,
                        [part],
                        snprintf!(str_buf, "{:#x}", ptn.absolute_range()?.0),
                    )
                    .await?;
                responder
                    .send_var_info(PARTITION_SIZE, [part], snprintf!(str_buf, "{:#x}", sz))
                    .await?;
                responder
                    .send_var_info(PARTITION_TYPE, [part], snprintf!(str_buf, "{part_type}"))
                    .await?;
                if let Partition::Gpt(gpt_partition) = &ptn {
                    let guid = gpt_partition.gpt_entry().guid;
                    responder
                        .send_var_info(PARTITION_GUID, [part], snprintf!(str_buf, "{}", guid))
                        .await?;
                }
            }
        }
        Ok(())
    }

    /// Block device related information.
    ///
    /// `fastboot getvar block-device:<id>:total-blocks`
    /// `fastboot getvar block-device:<id>:block-size`
    /// `fastboot getvar block-device:<id>:status`
    fn get_var_block_device<'s, 't>(
        &mut self,
        mut args: impl Iterator<Item = &'t str> + Clone,
        out: &'s mut [u8],
    ) -> CommandResult<&'s str> {
        let id: usize = FromHexStr::try_parse_next(&mut args)
            .map_err(|_| GblFastbootError::from("Missing or invalid block device ID"))?;
        let val_type = next_arg(&mut args).ok_or("Missing value type")?;
        let blk = &self.disks.get(id).ok_or("Invalid block device ID")?;
        let info = blk.block_info();
        let val = match val_type {
            TOTAL_BLOCKS => info.num_blocks,
            BLOCK_SIZE => info.block_size,
            _ => return Err("Invalid type".into()),
        };
        Ok(snprintf!(out, "{:#x}", val))
    }

    /// Gets all "block-device" variables.
    async fn get_all_block_device(&self, responder: &mut impl VarInfoSender) -> CommandResult<()> {
        let mut val = [0u8; 32];
        for (idx, blk) in self.disks.iter().enumerate() {
            let mut id_str = [0u8; 32];
            let id = snprintf!(id_str, "{:x}", idx);
            let info = blk.block_info();
            responder
                .send_var_info(
                    BLOCK_DEVICE,
                    [id, TOTAL_BLOCKS],
                    snprintf!(val, "{:#x}", info.num_blocks),
                )
                .await?;
            responder
                .send_var_info(
                    BLOCK_DEVICE,
                    [id, BLOCK_SIZE],
                    snprintf!(val, "{:#x}", info.block_size),
                )
                .await?;
        }
        Ok(())
    }

    /// "fastboot getvar logical-block-size[:<partition>]"
    /// "fastboot getvar erase-block-size[:<partition>]"
    ///
    /// With a partition argument, reports the value of the block device it resolves to (see
    /// `parse_partition_arg()`). Otherwise, reports the value of the default block device if set,
    /// or the maximum among all block devices.
    ///
    /// Returns `Ok(None)` so that the platform can provide the value if there is no block device,
    /// or if the partition is not found on GBL's disks and the argument has no '/'.
    fn get_var_block_geometry<'s, 't>(
        &self,
        name: &str,
        mut args: impl Iterator<Item = &'t str> + Clone,
        out: &'s mut [u8],
    ) -> CommandResult<Option<&'s str>> {
        let blk_ids = match next_arg(&mut args) {
            Some(raw_part) => {
                let (part, blk_id, _, _) = self.parse_partition_arg(raw_part)?;
                match self.find_partition(part, blk_id) {
                    Ok((blk_id, _)) => blk_id..blk_id + 1,
                    Err(Error::PartitionNotFound) if !raw_part.contains('/') => return Ok(None),
                    Err(e) => return Err(e.into()),
                }
            }
            None => match self.default_block {
                Some(blk_id) => blk_id..blk_id + 1,
                None => 0..self.disks.len(),
            },
        };
        let mut max = None;
        for blk_id in blk_ids {
            let info = self.disks[blk_id].block_info();
            let val = match name {
                LOGICAL_BLOCK_SIZE => info.block_size,
                ERASE_BLOCK_SIZE => info.erase_block_size()?,
                _ => return Err("Invalid block geometry variable".into()),
            };
            max = max.max(Some(val));
        }
        let Some(val) = max else {
            return Ok(None);
        };
        Ok(Some(snprintf!(out, "{:#x}", val)))
    }

    /// "fastboot getvar gbl-default-block"
    fn get_var_default_block<'s>(&mut self, out: &'s mut [u8]) -> CommandResult<&'s str> {
        Ok(match self.default_block {
            Some(v) => snprintf!(out, "{:#x}", v),
            None => snprintf!(out, "None"),
        })
    }

    /// "fastboot getvar stream-segment-size"
    fn get_var_stream_segment_size<'s>(&mut self, out: &'s mut [u8]) -> CommandResult<&'s str> {
        const DEFAULT_SEGMENT_SIZE: u64 = 4096;
        let segment_size_bytes = self
            .disks
            .iter()
            .map(|d| d.block_info().erase_block_size().unwrap_or_default())
            .max()
            .unwrap_or_default();
        let segment_size_bytes = core::cmp::max(segment_size_bytes, DEFAULT_SEGMENT_SIZE);

        Ok(snprintf!(out, "{:#x}", segment_size_bytes))
    }

    /// "fastboot getvar unlocked" and "fastboot getvar unlocked-critical"
    fn get_var_unlocked<'s>(
        &self,
        gbl_ops: &mut impl GblOps<'a>,
        lock_type: fastboot::LockType,
        out: &'s mut [u8],
    ) -> CommandResult<&'s str> {
        let status = gbl_ops.avb_read_device_status().map_err(|_| "failed to read lock state")?;
        Ok(snprintf!(out, "{}", format_unlocked(&status, lock_type)))
    }

    /// "fastboot getvar slot-successful:<slot-suffix>"
    /// "fastboot getvar slot-unbootable:<slot-suffix>"
    /// "fastboot getvar slot-retry-count:<slot-suffix>"
    fn get_fastboot_slot_info<'t>(
        &self,
        gbl_ops: &mut impl GblOps<'a>,
        mut args: impl Iterator<Item = &'t str> + Clone,
    ) -> CommandResult<FastbootSlotInfo> {
        let suffix_str = args.next().ok_or("Missing slot suffix")?;
        if suffix_str.chars().count() != 1 {
            return Err("Slot suffix must be a single character".into());
        }
        let suffix = suffix_str.chars().next().ok_or("Invalid slot")?;
        let slot = slots_iter(gbl_ops)?
            .find(|slot| slot.is_ok() && slot.unwrap().suffix.as_char() == suffix)
            .ok_or("Invalid slot")??;
        Ok(slot.into())
    }

    /// Builds a lookup table that tells us whether a partition has slot or not.
    ///
    /// Returns `Ok(None)` when device slotting is not supported (`get_slot_count()` returns
    /// `Ok(0)`, `Err(Error::Unsupported)`, or `Err(Error::NotFound)` when no boot control protocol
    /// is installed). Other errors from `get_slot_count()` or `get_slot_info()` are propagated.
    async fn get_part_has_slot_table(
        &mut self,
        gbl_ops: &mut impl GblOps<'a>,
        dynamic_parts: Option<&[RawName]>,
    ) -> Result<Option<&[PartHasSlot]>, Error> {
        let Some(slot_suffixes) = SlotSuffixMask::new(gbl_ops)? else {
            return Ok(None);
        };

        let owned_dynamic;
        let dynamic_parts = match dynamic_parts {
            Some(parts) => parts,
            None => {
                owned_dynamic = self.get_dynamic_partition_names(gbl_ops).await.unwrap_or_default();
                &owned_dynamic
            }
        };
        let dynamic_partition_count = dynamic_parts.len();

        // The table size could theoretically be as large as the number of total partitions, so
        // stack allocation would be insufficient. We instead dynamically allocate a memory slice
        // on the boot_buffer scratch pad.
        let disks = self.disks;
        let partition_count: usize =
            disks.iter().map(|b| b.num_partitions().unwrap_or_default()).sum();
        let total_partitions = partition_count + dynamic_partition_count;
        let buf = <[PartHasSlot]>::mut_from_prefix_with_elems(
            self.data.boot_buffer.scratch(),
            total_partitions,
        )
        .map_err(|e| {
            // Converting to `SizeError` statically ensures that no other error is possible.
            let SizeError { .. } = e.into();
            Error::BufferTooSmall(Some(total_partitions * size_of::<PartHasSlot>()))
        })?
        .0;
        let mut part_has_slot = SliceVec::new(buf);
        let gpt_parts = disks.iter().flat_map(|blk| {
            (0..blk.num_partitions().unwrap_or_default()).filter_map(move |idx| {
                blk.get_partition_by_idx(idx)
                    .ok()
                    .and_then(|ptn| RawName::try_from(ptn.name().ok()?).ok())
            })
        });

        let all_parts = gpt_parts.chain(dynamic_parts.iter().copied());
        for raw_part in all_parts {
            let part_name = raw_part.to_str();
            match slot_suffixes.split(part_name) {
                None => match part_has_slot.iter().position(|p| p.0.to_str() == part_name) {
                    None => part_has_slot.push(PartHasSlot(raw_part, PartHasSlot::NO)),
                    Some(pos) => part_has_slot[pos].1 = PartHasSlot::NO,
                },
                Some((name, _)) if part_has_slot.iter().all(|p| p.0.to_str() != name) => {
                    if let Ok(base_name) = name.try_into() {
                        part_has_slot.push(PartHasSlot(base_name, PartHasSlot::YES));
                    }
                }
                _ => {}
            }
        }

        Ok(Some(part_has_slot.into()))
    }

    /// Reads the super partition and extracts dynamic partition names from LP metadata.
    ///
    /// Deliberately returns an empty list if `super` doesn't exist, cannot be read, or has
    /// corrupt/erased LP metadata so that GPT and virtual-partition `has-slot` queries remain
    /// usable during fastboot recovery/unbrick (accepting that a corrupt `super` cannot mask a
    /// conflicting vendor `has-slot` entry for a dynamic partition).
    async fn get_dynamic_partition_names(
        &mut self,
        gbl_ops: &mut impl GblOps<'a>,
    ) -> Result<arrayvec::ArrayVec<RawName, 32>, Error> {
        // 256KB is sufficient to read LP geometry + metadata (primary + backup).
        const SUPER_METADATA_SIZE: usize = 256 * 1024;
        let mut result = arrayvec::ArrayVec::new();

        let Ok((blk_idx, _)) = check_part_unique(self.disks, "super") else {
            return Ok(result);
        };

        let (buffer, _) = <[u8]>::mut_from_prefix_with_elems(
            self.data.boot_buffer.scratch(),
            SUPER_METADATA_SIZE,
        )
        .map_err(|e| {
            // Converting to `SizeError` statically ensures that no other error is possible.
            let SizeError { .. } = e.into();
            Error::BufferTooSmall(Some(SUPER_METADATA_SIZE))
        })?;

        let disk = &self.disks[blk_idx];

        let io;
        loop {
            match disk.partition_io(Some("super")) {
                Ok(pio) => {
                    io = pio;
                    break;
                }
                Err(Error::NotReady) => {
                    // Disk is busy, yield and retry.
                    yield_now().await;
                }
                Err(e) => {
                    gbl_println!(gbl_ops, "Failed to get partition_io for super: {e}");
                    return Ok(result);
                }
            }
        }

        if io.read(0, &mut buffer[..]).await.is_err() {
            gbl_println!(gbl_ops, "Failed to read super partition");
            return Ok(result);
        }

        let mut hasher = Sha256::new();
        let Ok(metadata) = liblp::parse(buffer, &mut hasher) else {
            return Ok(result);
        };

        for raw_name in metadata
            .partitions
            .iter()
            .filter_map(lp_partition_name)
            .filter_map(|name| RawName::try_from(name).ok())
        {
            if result.try_push(raw_name).is_err() {
                gbl_println!(
                    gbl_ops,
                    "Warning: dynamic partition list truncated at {} entries, more partitions exist in super",
                    result.len()
                );
                break;
            }
        }

        Ok(result)
    }

    /// "fastboot getvar has-slot:<partition-name-without-slot-suffix>"
    ///
    /// Reports `no` for every partition when device slotting is unsupported. Otherwise returns
    /// `Ok(None)` if the partition is neither in GBL's has-slot table nor on GBL's disks.
    async fn get_var_has_slot<'t, 's>(
        &mut self,
        gbl_ops: &mut impl GblOps<'a>,
        mut args: impl Iterator<Item = &'t str> + Clone,
        dynamic_parts: Option<&[RawName]>,
        out: &'s mut [u8],
    ) -> CommandResult<Option<&'s str>> {
        let part = next_arg(&mut args).ok_or("Missing partition")?;
        if part.contains('/') {
            return Err("Invalid partition".into());
        }
        let Some(table) = self.get_part_has_slot_table(gbl_ops, dynamic_parts).await? else {
            // Without slotting no partition, virtual or not, can have slots.
            return Ok(Some(snprintf!(out, "no")));
        };
        if let Some(PartHasSlot(_, has_slot)) =
            table.iter().find(|PartHasSlot(name, _)| name.to_str() == part)
        {
            let has_slot = if *has_slot == PartHasSlot::NO { "no" } else { "yes" };
            return Ok(Some(snprintf!(out, "{has_slot}")));
        }
        // Not in the table (e.g. `part` is a slotted name). Only let the vendor answer if the
        // partition doesn't exist on GBL's disks either.
        match self.partition_size(gbl_ops, part) {
            Err(GblFastbootError::Libgbl(Error::PartitionNotFound)) => Ok(None),
            _ => Err(Error::NotFound.into()),
        }
    }

    /// Gets all "has-slot"
    async fn get_all_partition_has_slot(
        &mut self,
        gbl_ops: &mut impl GblOps<'a>,
        dynamic_parts: &[RawName],
        responder: &mut impl VarInfoSender,
    ) -> CommandResult<()> {
        let table = match self.get_part_has_slot_table(gbl_ops, Some(dynamic_parts)).await {
            Ok(Some(table)) => table,
            Ok(None) => return Ok(()),
            Err(e) => {
                gbl_println!(gbl_ops, "Failed to get slot_info for partitions, {e}");
                return Ok(());
            }
        };
        for PartHasSlot(part, has_slot) in table {
            responder
                .send_var_info(
                    HAS_SLOT,
                    [part.to_str()],
                    if *has_slot == PartHasSlot::NO { "no" } else { "yes" },
                )
                .await?;
        }
        Ok(())
    }

    /// Looks up the system fingerprint for `slot_suffix`
    async fn get_system_fingerprint_for_slot<'s>(
        &mut self,
        gbl_ops: &mut impl GblOps<'a>,
        slot_suffix: &str,
        out: &'s mut [u8],
    ) -> Result<&'s str, Error> {
        // Validate that `slot_suffix` corresponds to a valid slot.
        self.get_fastboot_slot_info(gbl_ops, [slot_suffix].into_iter())
            .map_err(|_| Error::InvalidInput)?;
        let mut suffix_buf = [0u8; 8];
        let ab_suffix_str = snprintf!(suffix_buf, "_{slot_suffix}\0");
        let ab_suffix = CStr::from_bytes_with_nul(ab_suffix_str.as_bytes())
            .map_err(|_| "Invalid slot suffix")?;
        // Wait for any pending async I/O tasks to finish before reading vbmeta from disk.
        {
            let _wait_guard = super::WaitingForAsyncTasksGuard::new(self.data.async_task_state);
            while self.tasks.borrow_mut().poll_all(self.data.async_task_state) > 0 {
                yield_now().await;
            }
        }
        let mut avb_ops = GblAvbOps::new(gbl_ops, None, &mut [], false);
        // Allow verification errors regardless of lock state so `fastboot getvar` can still
        // inspect and report the vbmeta properties; structurally invalid or corrupted vbmeta images
        // are still rejected below.
        let res = slot_verify(
            &mut avb_ops,
            &[],
            Some(ab_suffix),
            SlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
            // Hashtree error mode does not matter here since we are not booting anything, only
            // inspecting the vbmeta images.
            HashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
        );
        let verify_data = match &res {
            Ok(data) => data,
            Err(e) => e.verification_data().ok_or(match e {
                SlotVerifyError::Io => Error::BlockIoError,
                SlotVerifyError::Oom => Error::OutOfResources,
                SlotVerifyError::UnsupportedVersion => Error::UnsupportedVersion,
                SlotVerifyError::PublicKeyRejected(_)
                | SlotVerifyError::RollbackIndex(_)
                | SlotVerifyError::Verification(_) => Error::SecurityViolation,
                SlotVerifyError::InvalidArgument
                | SlotVerifyError::InvalidMetadata
                | SlotVerifyError::Internal => Error::NotFound,
            })?,
        };
        for vbmeta in verify_data.vbmeta_data() {
            if !matches!(
                vbmeta.verify_result(),
                Ok(())
                    | Err(VbmetaVerifyError::NotSigned
                        | VbmetaVerifyError::HashMismatch
                        | VbmetaVerifyError::SignatureMismatch)
            ) {
                return Err("Invalid vbmeta".into());
            }
            if let Some(val) = vbmeta.get_property_value(SYSTEM_FINGERPRINT_KEY) {
                let val = from_utf8(val)?;
                if !val.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err("Invalid fingerprint".into());
                }
                if val.len() > out.len() {
                    return Err(Error::BufferTooSmall(Some(val.len())));
                }
                return Ok(snprintf!(out, "{val}"));
            }
        }
        Err(Error::NotFound)
    }

    /// "fastboot getvar fingerprint:<partition-name>"
    /// Currently only supports system partition.
    async fn get_var_fingerprint<'t, 's>(
        &mut self,
        gbl_ops: &mut impl GblOps<'a>,
        mut args: impl Iterator<Item = &'t str> + Clone,
        out: &'s mut [u8],
    ) -> CommandResult<&'s str> {
        let suffix = args
            .next()
            .ok_or("Missing partition")?
            .strip_prefix("system_")
            .ok_or("Invalid partition")?;
        Ok(self.get_system_fingerprint_for_slot(gbl_ops, suffix, out).await?)
    }
}
