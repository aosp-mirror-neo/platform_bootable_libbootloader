// Copyright (C) 2026 The Android Open Source Project
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
// limitations under the License.

//! Contains implementation of GblEfiFastbootTransportProtocol by Virtio VSock.

use crate::{
    gbl_vsock_accept, gbl_vsock_close, gbl_vsock_read, gbl_vsock_read_exact, gbl_vsock_write, wait,
};
use alloc::boxed::Box;
use core::{ffi::CStr, future::Future, pin::Pin, time::Duration};
use efi_types::{
    protocol::gbl_efi_fastboot_transport::GblEfiFastbootTransport,
    status::{EfiError, EfiResult},
    GblEfiFastbootRxMode, GBL_EFI_FASTBOOT_RX_MODE_SINGLE_PACKET,
    GBL_EFI_FASTBOOT_TRANSPORT_PROTOCOL_REVISION,
};
use liberror::Error;
use libutils::InfallibleCast;
use spin::{Mutex, Spin};

type MutexGuard<'a, T> = spin::MutexGuard<'a, T, Spin>;

#[derive(Copy, Clone, Debug)]
struct Shared {
    /// Session ID.
    sid: u64,
    /// Remaining bytes of the current packet available to read.
    curr_pkt_len: usize,
    /// Last I/O result.
    last_io_res: Result<usize, Error>,
    /// Session status.
    session_status: Result<(), Error>,
}

impl Shared {
    /// Reads data from the vsock.
    pub fn read(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        // Abort on any error.
        self.last_io_res?;
        if self.curr_pkt_len == 0 {
            return Ok(0);
        }
        self.last_io_res = match gbl_vsock_read(self.sid, out) {
            Err(Error::NotReady) => Ok(0),
            v => v,
        };
        self.curr_pkt_len -= self.last_io_res?;
        self.last_io_res
    }
}

/// Locks `mutex`, yielding to other tasks until the lock is available.
async fn yield_until_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    loop {
        if let Some(guard) = mutex.try_lock() {
            return guard;
        }
        gbl_async::yield_now().await;
    }
}

/// An async process that listens for new connections and reads data.
///
/// Vsock is a stream transport. Because fastboot requires knowing the boundary of packet, we reuse
/// the TCP length-prefixed wire format protocol.
async fn listener_task(port: u32, shared: &Mutex<Shared>) {
    loop {
        // Listens for a new connection.
        let Ok(sid) = gbl_vsock_accept(port, Duration::from_secs(5)).await else {
            continue;
        };
        // Wait until the reader acknowledges the previous session result. This is to prevent
        // caller from treating new session data as a continuation of previous ones.
        while yield_until_lock(shared).await.session_status.is_err() {
            gbl_async::yield_now().await;
        }

        // Perform handshake and reads data.
        let res: Result<(), Error> = async {
            // Handshake
            let mut handshake_buf = [0u8; 4];
            gbl_vsock_read_exact(sid, &mut handshake_buf).await?;
            if &handshake_buf != b"FB01" {
                return Err(Error::ProtocolError);
            }
            wait(|| gbl_vsock_write(sid, &[b"FB01"])).await?;
            // Keep reading for packet
            loop {
                // Aborts if there is io error.
                yield_until_lock(shared).await.last_io_res?;
                // Checks if current packet has been read completely.
                if yield_until_lock(shared).await.curr_pkt_len > 0 {
                    gbl_async::yield_now().await;
                    continue;
                }
                // Reads the length of the next packet.
                let mut curr_pkt_len_prefix = [0u8; 8];
                gbl_vsock_read_exact(sid, &mut curr_pkt_len_prefix).await?;
                let curr_pkt_len = usize::try_from(u64::from_be_bytes(curr_pkt_len_prefix))?;
                yield_until_lock(shared).await.sid = sid;
                yield_until_lock(shared).await.curr_pkt_len = curr_pkt_len;
            }
        }
        .await;
        yield_until_lock(shared).await.session_status = res;
        let _ = wait(|| gbl_vsock_close(sid)).await;
    }
}

/// Fastboot virtio transport protocol.
pub struct FastbootTransport {
    port: u32,
    listener: Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send>>>>,
    shared: Mutex<Shared>,
    description: &'static CStr,
}

impl FastbootTransport {
    /// Creates a new fastboot virtio transport protocol.
    pub const fn new(port: u32, description: &'static CStr) -> Self {
        Self {
            port,
            listener: Mutex::new(None),
            shared: Mutex::new(Shared {
                sid: 0,
                curr_pkt_len: 0,
                last_io_res: Ok(0),
                session_status: Ok(()),
            }),
            description,
        }
    }

    /// Initializes the fastboot virtio transport protocol.
    //
    // We only support static instances. This is currently sufficient for GBL's use cases since
    // protocols to be installed are required to have static life time by
    // `install_prototol_from_rust` from libefi.
    pub fn init(&'static self) -> EfiResult<()> {
        let mut listener = self.listener.try_lock().ok_or(EfiError::NotReady)?;
        if listener.is_some() {
            return Err(EfiError::AlreadyStarted);
        }
        *listener = Some(Box::pin(listener_task(self.port, &self.shared)));
        Ok(())
    }

    /// Polls and updates session status. Returns shared data if not busy.
    fn poll(&self) -> Result<MutexGuard<'_, Shared>, Error> {
        let mut listener = self.listener.try_lock().ok_or(Error::NotReady)?;
        gbl_async::poll(listener.as_mut().ok_or(Error::NotReady)?);
        let mut shared = self.shared.try_lock().ok_or(Error::NotReady)?;
        // Checks and clears previous session status.
        core::mem::replace(&mut shared.session_status, Ok(()))?;
        Ok(shared)
    }
}

impl GblEfiFastbootTransport for FastbootTransport {
    fn revision(&self) -> u64 {
        GBL_EFI_FASTBOOT_TRANSPORT_PROTOCOL_REVISION
    }

    /// Returns a description of the fastboot transport.
    fn description(&self) -> &'static CStr {
        self.description
    }

    /// Starts the transport channel.
    fn start(&self) -> EfiResult<()> {
        Ok(())
    }

    /// Stops the transport interface.
    fn stop(&self) -> EfiResult<()> {
        Ok(())
    }

    /// Receives data from the transport channel.
    fn receive(&self, buffer: &mut [u8], mode: GblEfiFastbootRxMode) -> EfiResult<usize> {
        let mut shared = self.poll()?;
        match mode {
            _ if shared.curr_pkt_len == 0 => Err(EfiError::NotReady),
            GBL_EFI_FASTBOOT_RX_MODE_SINGLE_PACKET => {
                // Single packet mode needs to receive everything.
                let buffer =
                    buffer.get_mut(..shared.curr_pkt_len).ok_or(Error::BufferTooSmall(None))?;
                let mut offset = 0;
                while offset < buffer.len() {
                    offset += shared.read(&mut buffer[offset..])?;
                }
                Ok(buffer.len())
            }
            _ => Ok(shared.read(buffer)?),
        }
    }

    /// Sends data to the transport channel.
    fn send(&self, buffer: &[u8]) -> EfiResult<usize> {
        let length_prefix = u64::to_be_bytes(buffer.len().cast());
        gbl_vsock_write(self.poll()?.sid, &[&length_prefix, buffer])?;
        Ok(buffer.len())
    }

    /// Waits until all pending TX transfers are completed.
    fn flush(&self) -> EfiResult<()> {
        // virtio-drivers vsock send API is blocking. No need to flush.
        Ok(())
    }
}
