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

//! Rust wrapper for `GBL_EFI_FASTBOOT_PROTOCOL`

use crate::{
    efi_call,
    protocol::{Protocol, ProtocolInfo, Requirement},
    versioned_protocol,
};
use arrayvec::ArrayVec;
use core::{
    ffi::{c_void, CStr},
    slice::from_raw_parts,
    str::from_utf8,
};
use efi_types::{
    EfiGuid, EfiStatus, GblEfiFastbootCommandExecResult, GblEfiFastbootMessageType,
    GblEfiFastbootProtocol, Identified, GBL_EFI_FASTBOOT_COMMAND_EXEC_RESULT_DEFAULT_IMPL,
    GBL_EFI_FASTBOOT_PROTOCOL_REVISION,
};
use liberror::{result_to_efi_status, Error, Result};

/// GBL_EFI_FASTBOOT_PROTOCOL
pub struct GblFastbootProtocol;

versioned_protocol!(GblFastbootProtocol, GBL_EFI_FASTBOOT_PROTOCOL_REVISION);

// Note: this is an internal limitation due to the need to allocate
// fixed sized buffers for storing args in the iterator
// and in the wrapper for `GblEfiFastbootProtocol.get_var`.
const MAX_ARGS: usize = 16;

impl ProtocolInfo for GblFastbootProtocol {
    type InterfaceType = GblEfiFastbootProtocol;

    const GUID: EfiGuid = GblEfiFastbootProtocol::GUID;

    const REQUIREMENT: Requirement = Requirement::Optional;

    const METRICS_TAG: Option<&'static str> = Some("gbl_fastboot");
}

impl Protocol<'_, GblFastbootProtocol> {
    /// Wrapper of `GBL_EFI_FASTBOOT_PROTOCOL.get_var`
    pub fn get_var<'a>(
        &self,
        var: &CStr,
        args: impl Iterator<Item = &'a CStr>,
        out: &mut [u8],
    ) -> Result<usize> {
        let mut args_arr = ArrayVec::<_, MAX_ARGS>::new();
        args_arr.try_push(var.as_ptr()).map_err(|_| Error::InvalidInput)?;
        for arg in args {
            args_arr.try_push(arg.as_ptr()).map_err(|_| Error::InvalidInput)?;
        }
        let mut bufsize = out.len();
        // SAFETY:
        // `self.interface_ptr()` points to a valid object established by `Protocol::new()`.
        // No parameters are retained, all parameters outlive the call, and no pointers are Null.
        unsafe {
            efi_call!(
                @bufsize bufsize,
                self.interface().get_var,
                self.interface_ptr(),
                args_arr.len(),
                args_arr.as_ptr() as _,
                &mut bufsize,
                out.as_mut_ptr(),
            )?
        };
        Ok(bufsize)
    }

    /// Wrapper of `GBL_EFI_FASTBOOT_PROTOCOL.get_var_all`
    pub fn get_var_all(&self, mut cb: impl FnMut(&[&CStr], &CStr)) -> Result<()> {
        struct Callback<'a>(&'a mut dyn FnMut(&[&CStr], &CStr));

        /// Callback C function to be passed to the `get_var_all` function.
        ///
        /// # Safety
        ///
        /// * Caller must guarantee that `ctx` points to a valid instance of `Callback`, outlives
        ///   the call, and not being referenced elsewhere.
        /// * Caller must guarantee that `args` points to an array of NULL-terminated strings with
        ///   size `num_args` and outlives the call.
        /// * Caller must guarantee that `val` points to valid NULL-terminated strings and outlives
        ///   the call.
        unsafe extern "efiapi" fn get_var_all_cb(
            ctx: *mut c_void,
            num_args: usize,
            args: *const *const u8,
            val: *const u8,
        ) {
            // SAFETY: By safety requirement of this function, `args` points to an array of
            // NULL-terminated strings of length `num_args`.
            let args = unsafe { from_raw_parts(args, num_args) }
                .iter()
                .map(|v| unsafe { CStr::from_ptr(*v as _) });
            // SAFETY: By requirement of this function, `ctx` points to a `Callback`.
            let cb = unsafe { (ctx as *mut Callback).as_mut() }.unwrap();
            // Checks number of arguments and stores them in an array.
            let mut args_arr = [c""; MAX_ARGS];
            match args_arr.get_mut(..num_args) {
                Some(v) => {
                    v.iter_mut().zip(args).for_each(|(l, r)| *l = r);
                    // SAFETY: By safety requirement of this function `val` points to a
                    // NULL-terminated string.
                    (cb.0)(v, unsafe { CStr::from_ptr(val as _) })
                }
                _ => (cb.0)(&[c"<Number of arguments exceeds limit>"], c""),
            }
        }

        // SAFETY:
        // *`self.interface_ptr()` points to a valid object
        // * established by `Protocol::new()`.
        // * The `ctx` parameter is a valid `Callback` object, outlives the call and is not
        //   referenced elsewhere (declared inline at the parameter site).
        // * By UEFI interface requirement, vendor firmware passes array of C strings to
        //   `get_var_all_cb` that remains valid for the call.
        unsafe {
            efi_call!(
                self.interface().get_var_all,
                self.interface_ptr(),
                &mut Callback(&mut cb) as *mut _ as _,
                Some(get_var_all_cb),
            )?
        };

        Ok(())
    }

    /// Wrapper of `GBL_EFI_FASTBOOT_PROTOCOL.get_staged()`
    pub fn get_staged(&self, out: &mut [u8]) -> Result<(usize, usize)> {
        let mut out_size = out.len();
        let mut out_remains = 0;

        // SAFETY:
        // *`self.interface_ptr()` points to a valid object
        // * established by `Protocol::new()`.
        // * `out`, `out_size` and `out_remains` are for input/output only. They outlive the call
        //   and won't be retained.
        unsafe {
            efi_call!(
                self.interface().get_staged,
                self.interface_ptr(),
                &mut out_size,
                &mut out_remains,
                out.as_mut_ptr(),
            )?;
        }
        Ok((out_size, out_remains))
    }

    /// Wrapper of `GBL_EFI_FASTBOOT_PROTOCOL.command_exec()`
    pub fn command_exec<'a>(
        &self,
        args: impl Iterator<Item = &'a CStr>,
        download: &mut [u8],
        download_used: usize,
        mut sender: impl FnMut(GblEfiFastbootMessageType, &str) -> Result<()>,
    ) -> Result<GblEfiFastbootCommandExecResult> {
        let mut args_arr = ArrayVec::<_, MAX_ARGS>::new();
        for arg in args {
            args_arr.try_push(arg.as_ptr()).map_err(|_| Error::InvalidInput)?;
        }
        let mut out_impl = GBL_EFI_FASTBOOT_COMMAND_EXEC_RESULT_DEFAULT_IMPL;
        struct SenderCtx<'a>(&'a mut dyn FnMut(GblEfiFastbootMessageType, &str) -> Result<()>);

        /// Callback function to be passed to the `command_exec` interface.
        ///
        /// # Safety
        ///
        /// * Caller must guarantee that `ctx` points to a valid instance of `SenderCtx`, outlives
        ///   the call, and is not referenced elsewhere.
        /// * Caller must guarantee that `msg` points to a valid initialized buffer with length
        ///   'msg_len' and outlives the call.
        unsafe extern "efiapi" fn message_sender(
            context: *mut core::ffi::c_void,
            msg_type: GblEfiFastbootMessageType,
            msg_len: usize,
            msg: *const u8,
        ) -> EfiStatus {
            // SAFETY: By safety requirement of this function, `ctx` points to a `SenderCtx`.
            let cb = unsafe { (context as *mut SenderCtx).as_mut() }.unwrap();
            result_to_efi_status((cb.0)(
                msg_type,
                // SAFETY: By safety requirement of this function, `msg` point to a valid
                // initialized buffer of length `msg_len`;
                from_utf8(unsafe { from_raw_parts(msg as _, msg_len) }).unwrap(),
            ))
        }

        // SAFETY:
        // *`self.interface()?` guarantees self.interface is non-null and points to a valid object
        // * established by `Protocol::new()`.
        // * `cmd`, `download` and `out_impl` are for input/output only. They
        //   outlive the call and won't be retained.
        // * The `ctx` parameter is a valid `SenderCtx` object, outlives the call and is not
        //   referenced elsewhere(declared inline at the parameter site).
        // * By UEFI interface requirement, vendor firmware passes valid ASCII string and provides
        //   the correct string length to the callback function.
        unsafe {
            efi_call!(
                self.interface().command_exec,
                self.interface_ptr(),
                args_arr.len(),
                args_arr.as_ptr() as _,
                download.len(),
                download_used,
                download.as_mut_ptr(),
                &mut out_impl,
                Some(message_sender),
                &mut SenderCtx(&mut sender) as *mut _ as _,
            )?;
        }
        Ok(out_impl)
    }

    /// Wrapper of `GBL_EFI_FASTBOOT_PROTOCOL.get_partition_type()`.
    pub fn get_partition_type(&self, part_name: &CStr, part_type: &mut [u8]) -> Result<usize> {
        let mut part_type_len = part_type.len();
        // SAFETY:
        // `self.interface_ptr()` points to a valid object established by `Protocol::new()`.
        // No parameters are retained, all parameters outlive the call, and no pointers are Null.
        unsafe {
            efi_call!(
                @bufsize part_type_len,
                self.interface().get_partition_type,
                self.interface_ptr(),
                part_name.as_ptr() as _,
                &mut part_type_len,
                part_type.as_mut_ptr(),
            )?
        };
        Ok(part_type_len)
    }

    /// Wrapper of `GBL_EFI_FASTBOOT_PROTOCOL.serial_number`
    pub fn serial_number(&self) -> Result<&str> {
        let serial_number = &self.interface().serial_number;
        let null_idx = serial_number.iter().position(|c| *c == 0).unwrap_or(serial_number.len());
        Ok(from_utf8(&serial_number[..null_idx])?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        test::{generate_protocol, run_test},
        EfiEntry,
    };
    use core::{
        ffi::{c_void, CStr},
        slice::from_raw_parts_mut,
    };
    use efi_types::defs::{EfiStatus, GetVarAllCallback, EFI_STATUS_SUCCESS};

    #[test]
    fn test_serial_number() {
        run_test(|image_handle, systab_ptr| {
            // Serial number is shorter than max length and contains non-ASCII unicode.
            let austria = "Österreich";

            let mut fb = GblEfiFastbootProtocol { ..Default::default() };
            fb.serial_number.as_mut_slice()[..austria.len()].copy_from_slice(austria.as_bytes());
            let efi_entry = EfiEntry { image_handle, systab_ptr };

            let protocol = generate_protocol::<GblFastbootProtocol>(&efi_entry, &mut fb);

            // Don't include trailing Null terminators.
            assert_eq!(protocol.serial_number().unwrap().len(), 11);
            assert_eq!(protocol.serial_number().unwrap(), austria);
        });
    }

    #[test]
    fn test_serial_number_max_length() {
        run_test(|image_handle, systab_ptr| {
            let mut fb = GblEfiFastbootProtocol { serial_number: [71u8; 32], ..Default::default() };
            let efi_entry = EfiEntry { image_handle, systab_ptr };

            let protocol = generate_protocol::<GblFastbootProtocol>(&efi_entry, &mut fb);

            assert_eq!(protocol.serial_number().unwrap().len(), 32);
            assert_eq!(protocol.serial_number().unwrap(), "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG");
        });
    }

    #[test]
    fn test_serial_number_invalid_utf8() {
        run_test(|image_handle, systab_ptr| {
            let mut fb = GblEfiFastbootProtocol { serial_number: [0xF8; 32], ..Default::default() };
            let efi_entry = EfiEntry { image_handle, systab_ptr };

            let protocol = generate_protocol::<GblFastbootProtocol>(&efi_entry, &mut fb);

            assert_eq!(protocol.serial_number(), Err(Error::InvalidInput));
        });
    }

    #[test]
    fn test_get_var() {
        /// # Safety
        ///
        /// * Caller must guarantee that `args` points to an array of NULL-terminated strings with
        ///   size `num_args`.
        /// * Caller must guarantee that `out_size` points to a `usize`
        /// * Caller must guarantee that `out` points to a `[u8]`
        unsafe extern "efiapi" fn get_var_test(
            _: *mut GblEfiFastbootProtocol,
            num_args: usize,
            args: *const *const u8,
            out_size: *mut usize,
            out: *mut u8,
        ) -> EfiStatus {
            // SAFETY: By safety requirement of this function, `args` points to an array of
            // NULL-terminated strings with length `num_args`.
            let args = unsafe { from_raw_parts(args, num_args) }
                .iter()
                .map(|v| unsafe { CStr::from_ptr(*v as _) })
                .collect::<Vec<_>>();
            assert_eq!(args, [c"var", c"arg1", c"arg2"]);
            // SAFETY: By safety requirement of this function, `out_size` points to a `usize`;
            let out_size = &mut unsafe { *out_size };
            // SAFETY: By safety requirement of this function, `out` points to a `[u8]`;
            let out = unsafe { from_raw_parts_mut(out, *out_size) };
            out.clone_from_slice(c"val".to_bytes());
            *out_size = c"val".to_bytes().len();
            EFI_STATUS_SUCCESS
        }

        run_test(|image_handle, systab_ptr| {
            let mut fb =
                GblEfiFastbootProtocol { get_var: Some(get_var_test), ..Default::default() };
            let efi_entry = EfiEntry { image_handle, systab_ptr };
            let protocol = generate_protocol::<GblFastbootProtocol>(&efi_entry, &mut fb);
            let mut out = [0u8; 3];
            let args = [c"arg1", c"arg2"];
            assert_eq!(protocol.get_var(c"var", args.iter().copied(), &mut out[..]), Ok(3));
            assert_eq!(&out, b"val");
        });
    }

    #[test]
    fn test_get_var_all() {
        /// # Safety
        ///
        /// * Caller must guarantee that `ctx` points to data needed by function pointer `cb`.
        unsafe extern "efiapi" fn test_get_var_all(
            _: *mut GblEfiFastbootProtocol,
            ctx: *mut c_void,
            cb: GetVarAllCallback,
        ) -> EfiStatus {
            for (args, val) in [
                ([c"foo", c"foo_arg1", c"foo_arg2"], c"foo_val"),
                ([c"bar", c"bar_arg1", c"bar_arg2"], c"bar_val"),
            ] {
                let args = args.map(|v| v.as_ptr());
                // SAFETY:
                // * `args` is an array of NULL-terminated strings. `val` is a NULL-terminated
                //   string.
                // * By safety requirement of this function, `ctx` points to a valid type of data
                //   needed by `cb`.
                unsafe { (cb.unwrap())(ctx, args.len(), args.as_ptr() as _, val.as_ptr() as _) };
            }
            EFI_STATUS_SUCCESS
        }
        run_test(|image_handle, systab_ptr| {
            let mut fb = GblEfiFastbootProtocol {
                get_var_all: Some(test_get_var_all),
                ..Default::default()
            };
            let efi_entry = EfiEntry { image_handle, systab_ptr };
            let protocol = generate_protocol::<GblFastbootProtocol>(&efi_entry, &mut fb);
            let mut out = vec![];
            protocol
                .get_var_all(|args, val| {
                    let args_str =
                        args.iter().map(|v| v.to_str().unwrap()).collect::<Vec<_>>().join(":");
                    out.push(format!("{args_str}: {}", val.to_str().unwrap()))
                })
                .unwrap();
            assert_eq!(out, ["foo:foo_arg1:foo_arg2: foo_val", "bar:bar_arg1:bar_arg2: bar_val",])
        });
    }

    #[test]
    fn test_get_var_all_exceeds_max_arguments() {
        /// # Safety
        ///
        /// * Caller must guarantee that `ctx` points to data needed by function pointer `cb`.
        unsafe extern "efiapi" fn test_get_var_all(
            _: *mut GblEfiFastbootProtocol,
            ctx: *mut c_void,
            cb: GetVarAllCallback,
        ) -> EfiStatus {
            let args = [c"".as_ptr(); MAX_ARGS + 1];
            // SAFETY:
            // * `args` is an array of NULL-terminated strings. `val` is a NULL-terminated
            //   string.
            // * By safety requirement of this function, `ctx` points to a valid type of data
            //   needed by `cb`.
            unsafe { (cb.unwrap())(ctx, args.len(), args.as_ptr() as _, c"".as_ptr() as _) };
            EFI_STATUS_SUCCESS
        }
        run_test(|image_handle, systab_ptr| {
            let mut fb = GblEfiFastbootProtocol {
                get_var_all: Some(test_get_var_all),
                ..Default::default()
            };
            let efi_entry = EfiEntry { image_handle, systab_ptr };
            let protocol = generate_protocol::<GblFastbootProtocol>(&efi_entry, &mut fb);
            let mut out = vec![];
            protocol
                .get_var_all(|args, val| {
                    let args_str =
                        args.iter().map(|v| v.to_str().unwrap()).collect::<Vec<_>>().join(":");
                    out.push(format!("{args_str}: {}", val.to_str().unwrap()))
                })
                .unwrap();
            assert_eq!(out, ["<Number of arguments exceeds limit>: "])
        });
    }
}
