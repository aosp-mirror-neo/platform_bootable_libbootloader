// Copyright 2025, The Android Open Source Project
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

//! EFI backed implementation of GBL profiling framework.
//!
//! Note: profiling support requires the Efi Timestamp Protocol.
//!       If this protocol is not available the profilier will not
//!       crash the bootloader, but all output from the profiling machinery
//!       will only indicate errors.

use crate::protocol::timestamp::TimestampProtocol;
use crate::{efi_println, EfiEntry, Protocol};
use core::time::Duration;
use efi_types::EfiTimestampProperties;
use liberror::{Error, Result};
use libprofile::{ProfileBackend, ProfileTimer, Reporter};

/// EFI backed profiling timer
pub enum EfiProfileTimer<'a> {
    /// The EFI Timestamp protocol is not supported.
    Unsupported,
    /// The EFI Timestamp protocol is supported.
    Supported {
        /// The timestamp at the construction of the timer.
        start: u64,
        /// The timestamp protocol handle.
        ts_proto: Protocol<'a, TimestampProtocol>,
        /// The global EFI entry.
        entry: &'a EfiEntry,
    },
}

impl<'a> EfiProfileTimer<'a> {
    /// Construct a new profile timer that starts at the current timestamp.
    pub fn new(entry: &'a EfiEntry) -> Self {
        let Ok(ts_proto) = entry
            .system_table()
            .boot_services()
            .find_first_and_open::<TimestampProtocol>()
            .inspect_err(|_| {
                // The call to find_first_and_open already logs the absence
                // of the protocol in dev mode.
                #[cfg(not(feature = "gbl_dev"))]
                efi_println!(
                    entry,
                    "Optional protocol not found: {}",
                    libutils::base_type_name::<
                        <TimestampProtocol as crate::protocol::ProtocolInfo>::InterfaceType,
                    >()
                )
            })
        else {
            return Self::Unsupported;
        };

        let Ok(now) = ts_proto
            .get_timestamp()
            .inspect_err(|e| efi_println!(entry, "Error getting timestamp: {}", e))
        else {
            return Self::Unsupported;
        };

        Self::Supported { start: now, ts_proto, entry }
    }

    fn elapsed_helper(&self) -> Result<Duration> {
        let Self::Supported { start, ts_proto, entry } = self else {
            return Err(Error::Unsupported);
        };

        let EfiTimestampProperties { frequency, end_value } = ts_proto
            .get_properties()
            .inspect_err(|e| efi_println!(entry, "Error getting timestamp properties: {}", e))?;
        let now = ts_proto
            .get_timestamp()
            .inspect_err(|e| efi_println!(entry, "Error getting timestamp: {}", e))?;
        let delta = now.overflowing_sub(*start).0 as u128 % (end_value as u128 + 1);
        Ok(Duration::from_millis((delta as u64) * 1000 / frequency))
    }
}

impl<'a> ProfileTimer for EfiProfileTimer<'a> {
    fn elapsed(&self) -> Duration {
        self.elapsed_helper().unwrap_or(Duration::ZERO)
    }
}

/// Profiling reporter that prints to EFI console.
pub struct ConsoleProfileReporter<'a> {
    efi_entry: &'a EfiEntry,
}

impl<'a> ConsoleProfileReporter<'a> {
    /// Create a new console reporter using the EfiEntry.
    pub fn new(efi_entry: &'a EfiEntry) -> Self {
        Self { efi_entry }
    }
}

impl<'a> Reporter for ConsoleProfileReporter<'a> {
    fn report(&self, filename: &'static str, funcname: &'static str, elapsed: Duration) {
        efi_println!(self.efi_entry, "{}:{}: {}ms", filename, funcname, elapsed.as_millis())
    }
}

/// Backend for EFI backed profiling structures.
pub struct EfiProfileBackend<'a> {
    efi_entry: &'a EfiEntry,
}

impl<'a> EfiProfileBackend<'a> {
    /// Make a new profiler backend.
    pub fn new(efi_entry: &'a EfiEntry) -> Self {
        Self { efi_entry }
    }
}

impl ProfileBackend for EfiProfileBackend<'_> {
    fn new_timer(&self) -> impl ProfileTimer {
        EfiProfileTimer::new(self.efi_entry)
    }

    fn reporter(&self) -> impl Reporter {
        ConsoleProfileReporter::new(self.efi_entry)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        protocol::{timestamp::TimestampProtocol, ProtocolInfo},
        test::*,
        DeviceHandle,
    };
    use efi_types::{
        EfiStatus, EfiTimestampProtocol, EFI_STATUS_INVALID_PARAMETER, EFI_STATUS_SUCCESS,
    };
    use libprofile_macros::profile;
    use std::{cell::RefCell, collections::VecDeque};

    thread_local! {
        pub static GET_TIMESTAMP_COUNTER: RefCell<u64> = const { RefCell::new(0) };
    }

    /// Mocks `TimestampProtocol.get_timestamp`
    extern "efiapi" fn get_timestamp() -> u64 {
        GET_TIMESTAMP_COUNTER.with(|c| {
            let mut c = c.borrow_mut();
            let prev = *c;
            *c += 1;
            prev
        }) * 1000
    }

    /// Mocks `TimestampProtocol.get_properties`.
    ///
    /// # SAFETY
    ///
    /// Caller needs to ensure that
    ///
    /// * `props` points to a valid object of type EfiTimestampProperties
    unsafe extern "efiapi" fn get_properties(props: *mut EfiTimestampProperties) -> EfiStatus {
        if !props.is_null() && props.is_aligned() {
            // SAFETY:
            // * just checked that `props` is aligned and not null.
            // * caller is responsible for passing a pointer to a valid
            //   `EfiTimestampProperties`
            unsafe {
                *props = EfiTimestampProperties { frequency: 1000, end_value: 0xFFFFFFFF };
            }
            EFI_STATUS_SUCCESS
        } else {
            EFI_STATUS_INVALID_PARAMETER
        }
    }

    #[profile(backend = EfiProfileBackend::new(efi_entry))]
    fn no_op_profile(efi_entry: &EfiEntry) {}

    #[test]
    fn test_profile_success() {
        run_test(|image_handle, systab_ptr| {
            GET_TIMESTAMP_COUNTER.with(|c| *c.borrow_mut() = 0);

            let efi_entry = EfiEntry { image_handle, systab_ptr };
            let mut ts = EfiTimestampProtocol {
                get_timestamp: Some(get_timestamp),
                get_properties: Some(get_properties),
            };
            let handles: [DeviceHandle; 1] = [1.into()];
            efi_call_traces().with(|trace| {
                let mut trace = trace.borrow_mut();

                trace.locate_handle_trace.outputs =
                    VecDeque::from([handles.into(), handles.into()]);

                let ts_handle = as_efi_handle(&mut ts);
                trace.open_protocol_trace.outputs =
                    VecDeque::from([(ts_handle, EFI_STATUS_SUCCESS)]);
            });

            efi_call_traces().with(|trace| {
                let t = trace.borrow();
                assert_eq!(t.open_protocol_trace.inputs, [])
            });

            no_op_profile(&efi_entry);

            efi_call_traces().with(|trace| {
                let t = trace.borrow();
                assert_eq!(
                    t.open_protocol_trace.inputs,
                    [(1.into(), TimestampProtocol::GUID, image_handle),]
                );

                assert_eq!(GET_TIMESTAMP_COUNTER.with(|c| *c.borrow()), 2);

                let out_str = trace.borrow().console_out_trace.as_single_string();
                assert_eq!(
                    out_str,
                    "external/gbl+/libefi/src/profiling.rs:no_op_profile: 1000ms\r\n"
                );
            });
        });
    }

    #[test]
    fn test_profile_no_protocol() {
        run_test(|image_handle, systab_ptr| {
            let efi_entry = EfiEntry { image_handle, systab_ptr };

            // Just want to verify that no error is generated
            // if the protocol is absent.
            no_op_profile(&efi_entry);

            efi_call_traces().with(|trace| {
                let out_str = trace.borrow().console_out_trace.as_single_string();
                assert!(out_str.starts_with("Optional protocol not found: EfiTimestampProtocol"));
            });
        });
    }

    #[test]
    fn test_profile_no_properties() {
        run_test(|image_handle, systab_ptr| {
            GET_TIMESTAMP_COUNTER.with(|c| *c.borrow_mut() = 0);
            let efi_entry = EfiEntry { image_handle, systab_ptr };

            // Make sure the profiling implementation handles a protocol
            // with a missing `get_properties` method.
            // This is very unlikely if the protocol exists at all,
            // but it is important that the implementation is robust.
            let mut ts =
                EfiTimestampProtocol { get_timestamp: Some(get_timestamp), get_properties: None };
            let handles: [DeviceHandle; 1] = [1.into()];
            efi_call_traces().with(|trace| {
                let mut trace = trace.borrow_mut();

                trace.locate_handle_trace.outputs = VecDeque::from([handles.into()]);

                let ts_handle = as_efi_handle(&mut ts);
                trace.open_protocol_trace.outputs =
                    VecDeque::from([(ts_handle, EFI_STATUS_SUCCESS)]);
            });

            efi_call_traces().with(|trace| {
                let t = trace.borrow();
                assert_eq!(t.open_protocol_trace.inputs, [])
            });

            no_op_profile(&efi_entry);

            efi_call_traces().with(|trace| {
                let out_str = trace.borrow().console_out_trace.as_single_string();
                assert!(out_str.find("Error getting timestamp properties: ").is_some());
            });
        });
    }

    #[test]
    fn test_profile_timestamp_error() {
        run_test(|image_handle, systab_ptr| {
            GET_TIMESTAMP_COUNTER.with(|c| *c.borrow_mut() = 0);
            let efi_entry = EfiEntry { image_handle, systab_ptr };
            let handles: [DeviceHandle; 1] = [1.into()];

            // Make sure the profiling implementation handles a protocol
            // with a missing `get_timestamp` method.
            // This is very unlikely if the protocol exists at all,
            // but it is important that the implementation is robust.
            let mut ts =
                EfiTimestampProtocol { get_timestamp: None, get_properties: Some(get_properties) };
            efi_call_traces().with(|trace| {
                let mut trace = trace.borrow_mut();

                trace.locate_handle_trace.outputs = VecDeque::from([handles.into()]);

                let ts_handle = as_efi_handle(&mut ts);
                trace.open_protocol_trace.outputs =
                    VecDeque::from([(ts_handle, EFI_STATUS_SUCCESS)]);
            });

            efi_call_traces().with(|trace| {
                let t = trace.borrow();
                assert_eq!(t.open_protocol_trace.inputs, [])
            });

            no_op_profile(&efi_entry);

            efi_call_traces().with(|trace| {
                let out_str = trace.borrow().console_out_trace.as_single_string();
                assert!(out_str.starts_with("Error getting timestamp: "));
            });
        });
    }
}
