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

// Network is only allowed on dev boards.
#![cfg(feature = "gbl_dev")]

use crate::{
    efi,
    utils::{get_device_path, loop_with_timeout},
};
use alloc::{boxed::Box, vec::Vec};
use core::{
    ffi::c_void,
    ops::Deref,
    ptr::{null_mut, NonNull},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use efi::{
    efi_println,
    protocol::{simple_network::SimpleNetworkProtocol, ExclusiveProtocol, Protocol},
    utils::Timeout,
    DeviceHandle, EfiEntry, Event, EventNotify, EventType, Tpl,
};
use efi_types::{
    EfiEvent, EfiMacAddress, EFI_SIMPLE_NETWORK_STATE_INITIALIZED,
    EFI_SIMPLE_NETWORK_STATE_STARTED, EFI_SIMPLE_NETWORK_STATE_STOPPED,
    EFI_TIMER_DELAY_TIMER_PERIODIC,
};
use gbl_async::{yield_now, YieldCounter};
use liberror::{Error, Result};
use libgbl::fastboot::fuchsia_fastboot_mdns_packet;
use libgblutils::arch_timestamp;
use smoltcp::{
    iface::{Config, Interface, SocketSet, SocketStorage},
    phy,
    phy::{Device, DeviceCapabilities, Medium},
    socket::{
        tcp::{ListenError, RecvError, SendError, Socket as TcpSocket, SocketBuffer, State},
        udp::{PacketBuffer, Socket as UdpSocket, UdpMetadata},
    },
    storage::PacketMetadata,
    time::Instant,
    wire::{EthernetAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv6Address},
};

/// Ethernet frame buffer size for frame pool.
const ETHERNET_FRAME_BUFFER_SIZE: usize = 1536;
/// Maximum size of the Ethernet frames that GBL sends and receives, without the frame check
/// sequence: a standard 1500 byte IP MTU plus the 14 byte Ethernet header.
const ETHERNET_MAX_FRAME_SIZE: usize = 1514;
const _: () = assert!(
    ETHERNET_MAX_FRAME_SIZE <= ETHERNET_FRAME_BUFFER_SIZE,
    "Frames must fit in the frame buffers"
);
// Update period for `NETWORK_TIMESTAMP`.
const NETWORK_TIMESTAMP_UPDATE_PERIOD: Duration = Duration::from_millis(50);
// Size of the socket tx/rx application data buffer.
const SOCKET_TX_RX_BUFFER: usize = 256 * 1024;
/// Extra RX buffer space requested from `SimpleNetworkProtocol::initialize` (512 KiB, enough to
/// buffer ~340 full-sized Ethernet frames across bursts while synchronous storage writes are in
/// flight).
const SNP_EXTRA_RX_BUFFER_SIZE: usize = 512 * 1024;

/// Minimum time between polls of the network device while data keeps arriving.
///
/// Frames that arrive in between wait in the device's receive ring, so that a poll processes
/// several of them and smoltcp acknowledges them together. Each transmitted frame, such as an
/// acknowledgement, costs several microseconds of firmware calls, so batching saves CPU time during
/// downloads while still yielding right after each batch when the ring is empty.
const BULK_RECEIVE_POLL_INTERVAL: Duration = Duration::from_micros(100);

/// Maximum time to wait for an in-flight TX buffer to be recycled before resetting the network.
const TX_RECYCLE_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum time to wait for the NIC transmit queue to accept a frame on `Error::NotReady` before
/// dropping it and letting upper-layer protocols retransmit or time out.
const TX_READY_TIMEOUT: Duration = Duration::from_secs(1);

/// Converts smoltcp [RecvError] to unified [Error].
fn recv_to_unified(err: RecvError) -> Error {
    match err {
        RecvError::InvalidState => Error::InvalidState,
        RecvError::Finished => Error::Finished,
    }
}

/// Converts smoltcp [SendError] to unified [Error].
fn send_to_unified(err: SendError) -> Error {
    match err {
        SendError::InvalidState => Error::InvalidState,
    }
}

/// Converts smoltcp [ListenError] to unified [Error].
fn listen_to_unified(err: ListenError) -> Error {
    match err {
        ListenError::InvalidState => Error::InvalidState,
        ListenError::Unaddressable => Error::Unaddressable,
    }
}

/// Brings the simple network protocol to the initialized state and resets it.
///
/// Makes only the calls that are valid in the current state, as EDK2's SnpDxe rejects the others:
/// e.g. it fails `Shutdown()` with `EFI_DEVICE_ERROR` in the started state, which is where
/// `EfiNetworkDevice::drop()` leaves the network. An initialized network is shut down first, which
/// drops its pending transmits and so releases any TX buffers it holds.
fn reset_simple_network<'a>(snp: &Protocol<'a, SimpleNetworkProtocol>) -> Result<()> {
    match snp.mode()?.state {
        EFI_SIMPLE_NETWORK_STATE_STOPPED => snp.start()?,
        EFI_SIMPLE_NETWORK_STATE_STARTED => {}
        EFI_SIMPLE_NETWORK_STATE_INITIALIZED => snp.shutdown()?,
        // EDK2's SnpDxe fails every call in an out-of-spec state.
        _ => return Err(Error::InvalidState),
    }
    // Request extra driver RX buffer space when supported so bursts arriving during synchronous
    // storage writes do not overflow small default UNDI RX rings; fall back to `(0, 0)` if the
    // driver rejects the extra buffer allocation and leaves the interface in `STARTED`.
    if let Err(e) = snp.initialize(SNP_EXTRA_RX_BUFFER_SIZE, 0) {
        if snp.mode()?.state == EFI_SIMPLE_NETWORK_STATE_STARTED {
            snp.initialize(0, 0)?;
        } else {
            return Err(e);
        }
    }
    // `Initialize()` already resets the adapter; keep `Reset(true)` for drivers that implement it
    // (EDK2's SnpDxe rejects `Reset(false)` with `EFI_INVALID_PARAMETER`), while tolerating
    // `EFI_UNSUPPORTED` from drivers such as OVMF's VirtioNetDxe that omit `Reset()`.
    match snp.reset(true) {
        Ok(()) | Err(Error::Unsupported) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Holds an open `SimpleNetworkProtocol`, either exclusively (closing on drop) or shared when
/// firmware denies exclusive access to another agent.
enum NetworkProtocol<'a> {
    /// Exclusively owned protocol guard; calls `CloseProtocol` when dropped.
    Exclusive(ExclusiveProtocol<'a, SimpleNetworkProtocol>),
    /// Shared protocol handle (`BY_HANDLE_PROTOCOL`).
    Shared(Protocol<'a, SimpleNetworkProtocol>),
}

impl<'a> Deref for NetworkProtocol<'a> {
    type Target = Protocol<'a, SimpleNetworkProtocol>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Exclusive(snp) => snp,
            Self::Shared(snp) => snp,
        }
    }
}

/// `EfiNetworkDevice` manages a frame pool and handles receiving/sending network frames.
pub struct EfiNetworkDevice<'a> {
    // Dropped after `EfiNetworkDevice::drop` shuts down the NIC, so `CloseProtocol` on an
    // `ExclusiveProtocol` guard always runs after `shutdown()`.
    protocol: NetworkProtocol<'a>,
    rx_frame: Box<[u8; ETHERNET_FRAME_BUFFER_SIZE]>,
    tx_frames: Vec<TxFrame>,
    efi_entry: &'a EfiEntry,
}

/// A transmit frame buffer in [`EfiNetworkDevice`]'s pool.
struct TxFrame {
    // Safety invariant: Allocated via `Box::into_raw(Box::new([0u8; ETHERNET_FRAME_BUFFER_SIZE]))`
    // in `EfiNetworkDevice::new`, pairwise distinct from every other `TxFrame::buf`, and valid
    // until `EfiNetworkDevice::drop` frees it after shutting down the network protocol. When
    // `!self.in_flight`, the network protocol does not retain or access `self.buf`.
    buf: NonNull<[u8; ETHERNET_FRAME_BUFFER_SIZE]>,
    in_flight: bool,
}

impl<'a> EfiNetworkDevice<'a> {
    /// Creates a new instance. Allocates `extra_tx_frames+1` number of TX frames.
    fn new(protocol: NetworkProtocol<'a>, extra_tx_frames: usize, efi_entry: &'a EfiEntry) -> Self {
        let tx_frames = (0..extra_tx_frames + 1)
            .map(|_| TxFrame {
                buf: NonNull::new(Box::into_raw(Box::new([0u8; ETHERNET_FRAME_BUFFER_SIZE])))
                    .unwrap(),
                in_flight: false,
            })
            .collect();
        Self {
            protocol,
            rx_frame: Box::new([0u8; ETHERNET_FRAME_BUFFER_SIZE]),
            tx_frames,
            efi_entry,
        }
    }
}

impl Drop for EfiNetworkDevice<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.protocol.shutdown()
            && e != Error::NotStarted
        {
            // If shutdown fails, the protocol might still be operating on transmit buffers,
            // which can cause undefined behavior. Thus we need to panic.
            panic!("Failed to shutdown EFI network. {:?}", e);
        }

        // Deallocate TX frames.
        for frame in self.tx_frames.drain(..) {
            // SAFETY:
            // * By `TxFrame::buf`'s safety invariant, `frame.buf` was created via
            //   `Box::into_raw(Box::new([0u8; ETHERNET_FRAME_BUFFER_SIZE]))` with matching layout
            //   and global allocator, and is freed only once here as `drain(..)` removes each
            //   `TxFrame`.
            // * `self.protocol.shutdown()` above returned `Ok(())` or `Error::NotStarted`,
            //   releasing any pending transmit buffers held by the network interface, and `&mut
            //   self` guarantees no `TxToken` borrows `self.tx_frames`.
            drop(unsafe { Box::<[u8; ETHERNET_FRAME_BUFFER_SIZE]>::from_raw(frame.buf.as_ptr()) });
        }
    }
}

// Implements network device trait backend for the `smoltcp` crate.
impl<'a> Device for EfiNetworkDevice<'a> {
    type RxToken<'b>
        = RxToken<'b>
    where
        Self: 'b;
    type TxToken<'b>
        = TxToken<'a, 'b>
    where
        Self: 'b;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut res: DeviceCapabilities = Default::default();
        // smoltcp sizes its frames and advertises its TCP MSS from this value, so it must match
        // standard Ethernet and never exceed the frame buffers.
        res.max_transmission_unit = ETHERNET_MAX_FRAME_SIZE;
        res.medium = Medium::Ethernet;
        res
    }

    fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut recv_size = self.rx_frame.len();
        // Receive the next packet from the device.
        self.protocol
            .receive(None, Some(&mut recv_size), &mut self.rx_frame[..], None, None, None)
            .ok()?;
        match recv_size > 0 {
            true => Some((
                RxToken(&mut self.rx_frame[..recv_size]),
                TxToken {
                    protocol: &self.protocol,
                    tx_frames: &mut self.tx_frames[..],
                    efi_entry: self.efi_entry,
                },
            )),
            _ => None,
        }
    }

    fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            protocol: &self.protocol,
            tx_frames: &mut self.tx_frames[..],
            efi_entry: self.efi_entry,
        })
    }
}

/// In smoltcp, a `RxToken` is used to receive/process a frame when consumed.
pub struct RxToken<'a>(&'a mut [u8]);

impl phy::RxToken for RxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.0)
    }
}

/// In smoltcp, a `TxToken` is used to transmit a frame when consumed.
pub struct TxToken<'a: 'b, 'b> {
    tx_frames: &'b mut [TxFrame],
    protocol: &'b Protocol<'a, SimpleNetworkProtocol>,
    efi_entry: &'a EfiEntry,
}

impl TxToken<'_, '_> {
    /// Polls `get_status` once to dequeue a recycled TX buffer pointer, marking any matching
    /// in-flight pool slot idle. Returns `true` if a non-null pointer was dequeued.
    fn poll_recycled_tx_buffer(&mut self) -> bool {
        let mut ptr: *mut c_void = null_mut();
        let mut interrupt_status = 0u32;
        if self.protocol.get_status(Some(&mut interrupt_status), Some(&mut ptr)).is_err()
            || ptr.is_null()
        {
            return false;
        }
        if let Some(frame) = self
            .tx_frames
            .iter_mut()
            .find(|f| f.in_flight && ptr == f.buf.cast::<c_void>().as_ptr())
        {
            frame.in_flight = false;
        }
        true
    }

    /// Tries to allocate an idle send buffer slot, polling `get_status` to reclaim completed
    /// in-flight buffers and drain stale recycled addresses.
    ///
    /// # Safety-usable invariant
    ///
    /// If this returns `Some(idx)`, then `idx < self.tx_frames.len()` and
    /// `!self.tx_frames[idx].in_flight`.
    fn try_get_buffer(&mut self) -> Option<usize> {
        // UEFI `SimpleNetworkProtocol::GetStatus()` dequeues one recycled TX buffer pointer per
        // call until `ptr` is null, and drivers may retain queued addresses across `Shutdown()` /
        // `Initialize()` or report foreign or duplicate addresses. Drain ready entries up to a
        // bounded poll cap so non-compliant firmware returning non-null pointers indefinitely
        // cannot hang transmission.
        const MAX_TX_RECYCLE_POLLS: usize = 256;

        for _ in 0..MAX_TX_RECYCLE_POLLS {
            if !self.poll_recycled_tx_buffer() {
                break;
            }
        }

        self.tx_frames.iter().position(|f| !f.in_flight)
    }

    /// Acquires an idle TX buffer slot, resetting the network if TX buffer recycling times out.
    ///
    /// # Safety-usable invariant
    ///
    /// The returned `idx` satisfies `idx < self.tx_frames.len()` and
    /// `!self.tx_frames[idx].in_flight`.
    fn acquire_buffer(&mut self) -> usize {
        loop {
            // A transmit buffer is almost always free, so only arm a UEFI timeout timer if none is
            // immediately available.
            if let Some(idx) = self.try_get_buffer() {
                return idx;
            }
            match loop_with_timeout(self.efi_entry, TX_RECYCLE_TIMEOUT, || {
                self.try_get_buffer().ok_or(false)
            }) {
                Ok(Some(idx)) => return idx,
                Ok(None) => {
                    // Some UEFI firmware has internal network services that also recycle buffers,
                    // hijacking ours so they are never returned to us. Shutting down and restarting
                    // the network releases all pending send/receive buffers internally retained.
                    efi_println!(
                        self.efi_entry,
                        "Timeout recycling TX buffers. Resetting network."
                    );
                    // Panics if this fails, as we have effectively lost control over the network's
                    // use of our TX buffers.
                    reset_simple_network(self.protocol).unwrap();
                    for frame in self.tx_frames.iter_mut() {
                        frame.in_flight = false;
                    }
                }
                Err(_) => {} // `loop_with_timeout` failure. Try again.
            }
        }
    }

    /// Transmits the `len`-byte frame in `self.tx_frames[idx]`, retrying up to `TX_READY_TIMEOUT`
    /// on `Error::NotReady` and marking the slot `in_flight` if queued.
    fn transmit_slot(&mut self, idx: usize, len: usize) {
        assert!(!self.tx_frames[idx].in_flight, "TX slot already in flight");
        assert!(len <= ETHERNET_FRAME_BUFFER_SIZE, "TX frame length exceeds buffer");
        let send_buf = NonNull::slice_from_raw_parts(self.tx_frames[idx].buf.cast::<u8>(), len);

        let try_send = |protocol: &Protocol<'_, SimpleNetworkProtocol>| {
            // SAFETY:
            // * `send_buf` points to `len <= ETHERNET_FRAME_BUFFER_SIZE` live, initialized bytes in
            //   `self.tx_frames[idx].buf`, which outlives network shutdown in
            //   `EfiNetworkDevice::drop`.
            // * `!self.tx_frames[idx].in_flight` holds on entry (and remains `false` across any
            //   `Err(Error::NotReady)` retries, as `poll_recycled_tx_buffer` only clears `in_flight`
            //   flags), and `&mut self` ensures no Rust reference aliases `send_buf`.
            // * If `transmit` returns `Ok(())`, `transmit_slot` sets `in_flight = true` before
            //   returning so the buffer is not reused or accessed until `get_status()` recycles it
            //   or `reset_simple_network` / `Drop` shuts down the network.
            unsafe { protocol.transmit(0, send_buf, Default::default(), Default::default(), 0) }
        };

        // Only arm a UEFI timeout timer if the NIC DMA TX queue reports `Error::NotReady`.
        let transmitted = match try_send(self.protocol) {
            Ok(()) => true,
            Err(Error::NotReady) => matches!(
                loop_with_timeout(self.efi_entry, TX_READY_TIMEOUT, || {
                    let _ = self.poll_recycled_tx_buffer();
                    match try_send(self.protocol) {
                        Ok(()) => Ok(true),
                        Err(Error::NotReady) => Err(false),
                        Err(_) => Ok(false),
                    }
                }),
                Ok(Some(true))
            ),
            Err(_) => false,
        };

        if transmitted {
            self.tx_frames[idx].in_flight = true;
        }
    }
}

impl phy::TxToken for TxToken<'_, '_> {
    fn consume<R, F>(mut self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(len <= ETHERNET_FRAME_BUFFER_SIZE, "TX frame length exceeds buffer");
        let idx = self.acquire_buffer();

        let mut send_buf = NonNull::slice_from_raw_parts(self.tx_frames[idx].buf.cast::<u8>(), len);
        // SAFETY:
        // * By `TxFrame::buf`'s safety invariant, `self.tx_frames[idx].buf` points to a live,
        //   initialized `[u8; ETHERNET_FRAME_BUFFER_SIZE]` allocation until
        //   `EfiNetworkDevice::drop` (which cannot run while `self` borrows `&mut self.tx_frames`),
        //   and `len <= ETHERNET_FRAME_BUFFER_SIZE` is checked above.
        // * By `acquire_buffer`'s safety-usable invariant, `!self.tx_frames[idx].in_flight`, so
        //   the network interface does not retain or access this buffer, and all `TxFrame::buf`
        //   allocations are pairwise distinct.
        let result = f(unsafe { send_buf.as_mut() });

        self.transmit_slot(idx, len);
        result
    }
}

/// Find the first available network device with an active link, falling back to the first root
/// network device if no link is detected.
fn find_net_device(efi_entry: &EfiEntry) -> Result<DeviceHandle> {
    let bs = efi_entry.system_table().boot_services();
    let mut candidates: Vec<_> = bs
        .locate_handle_buffer_by_protocol::<SimpleNetworkProtocol>()?
        .handles()
        .iter()
        .filter_map(|handle| {
            let path = get_device_path(efi_entry, *handle).ok()?;
            path.text().is_some().then_some((*handle, path))
        })
        .collect();

    // Sort by device path text lexicographically so parent device paths precede any child virtual
    // network device nodes (e.g., e1000 adds child nodes for IPv4 and IPv6 configuration).
    candidates.sort_by(|(_, a), (_, b)| a.text().cmp(&b.text()));

    // Deduplicate child network device handles whose path starts with the preceding root parent
    // device path. Note that `dedup_by` passes `(child, root)` in reverse slice order.
    candidates.dedup_by(|(_, child), (_, root)| {
        if let (Some(child_text), Some(root_text)) = (child.text(), root.text()) {
            !root_text.is_empty() && child_text.starts_with(root_text)
        } else {
            false
        }
    });

    if candidates.is_empty() {
        return Err(Error::NotFound);
    }

    let first_handle = candidates.first().unwrap().0;

    // Find the first root NIC handle with an active link, falling back to the first root handle.
    let has_active_link = |&handle: &DeviceHandle| {
        bs.open_protocol::<SimpleNetworkProtocol>(handle)
            .and_then(|snp| {
                reset_simple_network(&snp)?;
                // Prod the driver to refresh its cached status (including Mode->MediaPresent).
                // Some UEFI drivers require non-null status/buffer pointers even though they
                // are optional in the spec.
                let mut interrupt_status = 0u32;
                let mut recycle_buffer = null_mut();
                snp.get_status(Some(&mut interrupt_status), Some(&mut recycle_buffer))?;
                let mode = snp.mode()?;
                Ok(!mode.media_present_supported || mode.media_present)
            })
            .unwrap_or(false)
    };
    Ok(candidates.into_iter().map(|(h, _)| h).find(has_active_link).unwrap_or(first_handle))
}

/// Opens the simple network protocol on `handle` exclusively, which makes firmware stop the
/// drivers bound to it. Otherwise these drivers take frames that GBL needs: EDK2's Managed Network
/// driver, for example, polls the device every 10 ms and takes a received frame each time.
///
/// Returns an [`ExclusiveProtocol`] guard (via [`NetworkProtocol::Exclusive`]) that closes the
/// protocol on drop so later sessions can open it exclusively again. If exclusive open fails,
/// warns and falls back to a shared open (`BY_HANDLE_PROTOCOL`).
fn open_simple_network<'a>(
    efi_entry: &'a EfiEntry,
    handle: DeviceHandle,
) -> Result<NetworkProtocol<'a>> {
    let bs = efi_entry.system_table().boot_services();
    // SAFETY:
    // * `EfiGblNetwork::init` drops any previous `EfiGblNetworkInternal` (and its
    //   `SimpleNetworkProtocol` handle) before calling `open_simple_network`, and `find_net_device`
    //   drops all temporary `DevicePathProtocol` and `SimpleNetworkProtocol` handles before
    //   returning `handle`.
    // * No other GBL component holds a live `Protocol` or `RawProtocol` to `SimpleNetworkProtocol`
    //   on `handle` or to any child protocol (such as MNP/ARP/IPv4/IPv6) installed by a network
    //   driver bound `BY_DRIVER` to `(handle, SimpleNetworkProtocol)`.
    match unsafe { bs.open_protocol_exclusive::<SimpleNetworkProtocol>(handle) } {
        Ok(snp) => Ok(NetworkProtocol::Exclusive(snp)),
        Err(e) => {
            efi_println!(
                efi_entry,
                "Warning: Failed to open the network device exclusively: {e}. Firmware may take \
                 received packets",
            );
            bs.open_protocol::<SimpleNetworkProtocol>(handle).map(NetworkProtocol::Shared)
        }
    }
}

/// Derives a link local ethernet mac address and IPv6 address from `EfiMacAddress`.
fn ll_mac_ip6_addr_from_efi_mac(mac: EfiMacAddress) -> (EthernetAddress, IpAddress) {
    let ll_mac_bytes = &mac.addr[..6];
    let mut ip6_bytes = [0u8; 16];
    ip6_bytes[0] = 0xfe;
    ip6_bytes[1] = 0x80;
    ip6_bytes[8] = ll_mac_bytes[0] ^ 2;
    ip6_bytes[9] = ll_mac_bytes[1];
    ip6_bytes[10] = ll_mac_bytes[2];
    ip6_bytes[11] = 0xff;
    ip6_bytes[12] = 0xfe;
    ip6_bytes[13] = ll_mac_bytes[3];
    ip6_bytes[14] = ll_mac_bytes[4];
    ip6_bytes[15] = ll_mac_bytes[5];

    (EthernetAddress::from_bytes(ll_mac_bytes), IpAddress::Ipv6(Ipv6Address::from(ip6_bytes)))
}

/// `EfiTcpSocket` groups together necessary components for performing TCP.
pub struct EfiTcpSocket<'a, 'b> {
    pub(crate) efi_entry: &'a EfiEntry,
    efi_net_dev: &'b mut EfiNetworkDevice<'a>,
    interface: Interface,
    socket_set: SocketSet<'b>,
    io_yield_counter: YieldCounter,
    last_listen_timestamp: Option<u64>,
    _time_update_event: Option<Event<'a, 'b>>,
    timestamp: &'b AtomicU64,
    clock_fn: fn() -> Result<Duration>,
    // The architecture timer's time at the creation of the socket, if the timer is supported.
    clock_epoch: Option<Duration>,
    // Elapsed time on `clock_fn` (relative to `clock_epoch`) of the last poll that received data,
    // while data keeps arriving.
    last_data_poll: Option<Duration>,
    fuchsia_fastboot_mdns_packet: Vec<u8>,
}

impl<'a, 'b> EfiTcpSocket<'a, 'b> {
    /// Resets the socket and starts listening for new TCP connection.
    pub fn listen(&mut self, port: u16) -> Result<()> {
        self.get_socket().abort();
        self.get_socket().listen(port).map_err(listen_to_unified)?;
        self.last_listen_timestamp = Some(self.timestamp(0).as_millis() as u64);
        self.last_data_poll = None;
        Ok(())
    }

    /// Returns the amount of time elapsed since last call to `Self::listen()`. If `listen()` has
    /// never been called, `Duration::MAX` is returned.
    pub fn time_since_last_listen(&mut self) -> Duration {
        self.last_listen_timestamp.map(|v| self.timestamp(v)).unwrap_or(Duration::MAX)
    }

    /// Polls network device.
    pub fn poll(&mut self) {
        self.interface.poll(self.instant(), self.efi_net_dev, &mut self.socket_set);
    }

    /// Gets a reference to the smoltcp socket object.
    pub fn get_socket(&mut self) -> &mut TcpSocket<'b> {
        // We only consider single socket use case for now.
        let handle = self.socket_set.iter().next().unwrap().0;
        self.socket_set.get_mut::<TcpSocket>(handle)
    }

    /// Checks whether a socket connection is established.
    pub fn is_established(&mut self) -> bool {
        self.get_socket().state() == State::Established
    }

    /// Checks whether a socket is closed.
    pub fn is_closed(&mut self) -> bool {
        !self.get_socket().is_open() || self.get_socket().state() == State::CloseWait
    }

    /// Sets the maximum number of bytes to read or write before a force await.
    pub fn set_io_yield_threshold(&mut self, threshold: u64) {
        self.io_yield_counter = YieldCounter::new(threshold)
    }

    /// Receives any non-zero amount of data.
    ///
    /// Returns Ok(0) if `out` is empty;
    pub async fn receive(&mut self, out: &mut [u8], timeout: Duration) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        // During a download, data is usually available right away. Only create the timeout's UEFI
        // timer once there is none.
        let mut timeout_timer = None;
        loop {
            // While data keeps arriving, polls the device at most every
            // `BULK_RECEIVE_POLL_INTERVAL`, if the architecture timer is available. Between polls,
            // draining the buffered TCP stream causes `receive()` to yield right after an RX batch
            // while the NIC RX ring is empty, giving pending async storage tasks a clean window.
            let now = self.clock_now();
            let poll_due = match (self.last_data_poll, now) {
                (Some(last), Some(now)) => now.saturating_sub(last) >= BULK_RECEIVE_POLL_INTERVAL,
                _ => true,
            };
            if poll_due {
                self.poll();
            }

            // Checks for data first: a peer that closes its side may have sent data before.
            if self.get_socket().can_recv() {
                let recv_size = self.get_socket().recv_slice(out).map_err(recv_to_unified)?;
                // Forces a yield to the executor if the data received/sent reaches a certain
                // threshold. This is to prevent the async code from holding up the CPU for too long
                // in case IO speed is high and the executor uses cooperative scheduling.
                self.io_yield_counter.increment(recv_size.try_into().unwrap()).await;
                if recv_size > 0 {
                    if poll_due {
                        self.last_data_poll = now;
                    }
                    return Ok(recv_size);
                }
            } else if self.is_closed() {
                return Err(Error::Disconnected);
            } else if poll_due {
                // The data stopped, at least for now: poll right away until more arrives.
                self.last_data_poll = None;
                if timeout_timer.is_none() {
                    timeout_timer = Some(Timeout::new(self.efi_entry, timeout)?);
                }
                if let Some(timeout_timer) = &timeout_timer
                    && timeout_timer.check()?
                {
                    return Err(Error::Timeout);
                }
            }

            yield_now().await;
        }
    }

    /// Sends exactly `data.len()` number of bytes from `data`.
    pub async fn send_exact(&mut self, data: &[u8], timeout: Duration) -> Result<()> {
        let timer = Timeout::new(self.efi_entry, timeout)?;
        let mut curr = data;
        let mut last_send_queue = self.get_socket().send_queue();
        loop {
            self.poll();
            if curr.is_empty() && self.get_socket().send_queue() == 0 {
                return Ok(());
            } else if self.is_closed() {
                return Err(Error::Disconnected);
            } else if timer.check()? {
                return Err(Error::Timeout);
            }

            let mut has_progress = false;
            // Checks if any data in the queue is sent.
            if self.get_socket().send_queue() != last_send_queue {
                last_send_queue = self.get_socket().send_queue();
                has_progress = true;
            }
            // Checks if there are more data to be queued.
            if self.get_socket().can_send() && !curr.is_empty() {
                let sent = self.get_socket().send_slice(curr).map_err(send_to_unified)?;
                curr = curr.get(sent..).ok_or(Error::BadIndex(sent))?;
                // Forces a yield to the executor if the data received/sent reaches a certain
                // threshold. This is to prevent the async code from holding up the CPU for too long
                // in case IO speed is high and the executor uses cooperative scheduling.
                self.io_yield_counter.increment(sent.try_into().unwrap()).await;
                has_progress |= sent > 0;
            }

            match has_progress {
                true => timer.reset(timeout)?,
                _ => yield_now().await,
            }
        }
    }

    /// Gets the smoltcp `Interface` for this socket.
    pub fn interface(&self) -> &Interface {
        &self.interface
    }

    /// Returns the elapsed duration on the high-resolution clock since socket creation, if
    /// supported.
    fn clock_now(&self) -> Option<Duration> {
        self.clock_epoch.and_then(|epoch| (self.clock_fn)().ok().map(|t| t.saturating_sub(epoch)))
    }

    /// Returns the current time of the network clock since socket creation.
    fn now(&self) -> Duration {
        // Prefers the architecture timer: the timestamp maintained by `_time_update_event` only
        // advances every `NETWORK_TIMESTAMP_UPDATE_PERIOD`, which makes smoltcp's TCP timers, e.g.
        // its delayed ACK, that coarse.
        self.clock_now()
            .unwrap_or_else(|| Duration::from_millis(self.timestamp.load(Ordering::Relaxed)))
    }

    /// Returns the duration elapsed since the `base` timestamp.
    pub fn timestamp(&self, base_in_millis: u64) -> Duration {
        Duration::from_millis((self.now().as_millis() as u64).wrapping_sub(base_in_millis))
    }

    /// Returns a smoltcp time `Instant` value.
    fn instant(&self) -> Instant {
        to_smoltcp_instant(self.now())
    }

    /// Broadcasts Fuchsia Fastboot MDNS service once.
    pub fn broadcast_fuchsia_fastboot_mdns(&mut self) {
        const MDNS_PORT: u16 = 5353;
        const IP6_BROADCAST_ADDR: [u8; 16] =
            [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFB];
        let ip6_broadcast = Ipv6Address::from(IP6_BROADCAST_ADDR);
        let meta = UdpMetadata::from((ip6_broadcast, MDNS_PORT));
        let handle = self.socket_set.iter().nth(1).unwrap().0;
        let socket = self.socket_set.get_mut::<UdpSocket>(handle);
        if !socket.is_open()
            && let Err(e) = socket.bind(IpListenEndpoint { addr: None, port: MDNS_PORT })
        {
            efi_println!(self.efi_entry, "bind error: {:?}", e)
        }
        if socket.can_send()
            && let Err(e) = socket.send_slice(&self.fuchsia_fastboot_mdns_packet, meta)
        {
            efi_println!(self.efi_entry, "UDP send error: {:?}", e)
        }
    }
}

/// Returns a smoltcp time `Instant` value from a `Duration` timestamp.
fn to_smoltcp_instant(ts: Duration) -> Instant {
    Instant::from_micros(i64::try_from(ts.as_micros()).unwrap())
}

/// Internal type that contains net driver interfaces and buffers for creating GBL network and
/// sockets.
///
/// # Lifetimes
///
/// * `'a`: Lifetime of [EfiEntry] borrowed.
/// * `'b`: Lifetime of [SocketStorage<'b>], which eventually refers to Self.
/// * `'c`: Lifetime of [AtomicU64] borrowed.
struct EfiGblNetworkInternal<'a, 'b, 'c> {
    efi_entry: &'a EfiEntry,
    tcp_tx_buffer: Vec<u8>,
    tcp_rx_buffer: Vec<u8>,
    udp_tx_payload_buffer: Vec<u8>,
    udp_rx_payload_buffer: Vec<u8>,
    udp_tx_metadata_buffer: Vec<PacketMetadata<UdpMetadata>>,
    udp_rx_metadata_buffer: Vec<PacketMetadata<UdpMetadata>>,
    socket_storage: [SocketStorage<'b>; 2],
    efi_net_dev: EfiNetworkDevice<'a>,
    timestamp: &'c AtomicU64,
    notify_fn: Option<Box<dyn FnMut(EfiEvent) + Sync + 'c>>,
    notify: Option<EventNotify<'b>>,
}

impl<'a, 'b, 'c> EfiGblNetworkInternal<'a, 'b, 'c> {
    /// Creates a new instance of [EfiGblNetworkInternal].
    fn new(efi_entry: &'a EfiEntry, timestamp: &'c AtomicU64) -> Result<Self> {
        // Creates and initializes simple network protocol.
        let snp_dev = find_net_device(efi_entry)?;
        let snp = open_simple_network(efi_entry, snp_dev)?;
        reset_simple_network(&snp)?;

        // The TCP stack requires ICMP6 solicitation for discovery. Enable promiscuous mode so that
        // all uni/multicast packets can be captured.
        if let Err(e) = snp.set_promiscuous_mode() {
            efi_println!(
                efi_entry,
                "Warning: Failed to set promiscuous mode {e:?}. Device may be undiscoverable",
            )
        }

        Ok(Self {
            efi_entry,
            tcp_tx_buffer: vec![0u8; SOCKET_TX_RX_BUFFER],
            tcp_rx_buffer: vec![0u8; SOCKET_TX_RX_BUFFER],
            udp_tx_payload_buffer: vec![0u8; ETHERNET_FRAME_BUFFER_SIZE],
            udp_rx_payload_buffer: vec![0u8; ETHERNET_FRAME_BUFFER_SIZE],
            udp_tx_metadata_buffer: vec![PacketMetadata::EMPTY; 1],
            udp_rx_metadata_buffer: vec![PacketMetadata::EMPTY; 1],
            socket_storage: Default::default(),
            // Allocates 7(chosen randomly) extra TX frames. Revisits if it is not enough.
            efi_net_dev: EfiNetworkDevice::new(snp, 7, efi_entry),
            timestamp,
            notify_fn: None,
            notify: None,
        })
    }

    /// Creates an instance of [EfiTcpSocket].
    fn create_socket(&'b mut self) -> Result<EfiTcpSocket<'a, 'b>> {
        self.create_socket_with_clock(arch_timestamp)
    }

    /// Creates an instance of [EfiTcpSocket] using `clock_fn` as the high-resolution clock source.
    fn create_socket_with_clock(
        &'b mut self,
        clock_fn: fn() -> Result<Duration>,
    ) -> Result<EfiTcpSocket<'a, 'b>> {
        let clock_epoch = clock_fn().ok();
        let _time_update_event = if clock_epoch.is_none() {
            // Resets network timestamp to 0.
            let _ = self.timestamp.swap(0, Ordering::Relaxed);

            // Initializes notification functions.
            if self.notify_fn.is_none() {
                self.notify_fn = Some(Box::new(|_: EfiEvent| {
                    self.timestamp.fetch_add(
                        NETWORK_TIMESTAMP_UPDATE_PERIOD.as_millis() as u64,
                        Ordering::Relaxed,
                    );
                }));
                self.notify =
                    Some(EventNotify::new(Tpl::Callback, self.notify_fn.as_mut().unwrap()));
            }

            // Creates a timer event for updating the global timestamp.
            let bs = self.efi_entry.system_table().boot_services();
            // SAFETY: the notification callback in `notify_fn` initialized above never allocates,
            // deallocates, or panics.
            let event = unsafe {
                bs.create_event_with_notification(
                    EventType::TimerNotifySignal,
                    self.notify.as_mut().unwrap(),
                )
            }?;
            bs.set_timer(&event, EFI_TIMER_DELAY_TIMER_PERIODIC, NETWORK_TIMESTAMP_UPDATE_PERIOD)?;
            Some(event)
        } else {
            None
        };

        // Gets our MAC address and IPv6 address.
        // We can also consider getting this from vendor configuration.
        let (ll_mac, ll_ip6_addr) =
            ll_mac_ip6_addr_from_efi_mac(self.efi_net_dev.protocol.mode()?.current_address);
        let IpAddress::Ipv6(ll_ip6_addr_v6) = ll_ip6_addr else {
            unreachable!();
        };
        // Configures smoltcp network interface.
        let mut interface = Interface::new(
            Config::new(ll_mac.into()),
            &mut self.efi_net_dev,
            to_smoltcp_instant(Duration::ZERO),
        );
        interface.update_ip_addrs(|ip_addrs| ip_addrs.push(IpCidr::new(ll_ip6_addr, 64)).unwrap());

        // Generates Fuchsia Fastboot MDNS packet.
        let eth_mac = ll_mac.as_bytes();
        let fuchsia_node_name = format!(
            "fuchsia-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}",
            eth_mac[0], eth_mac[1], eth_mac[2], eth_mac[3], eth_mac[4], eth_mac[5]
        );
        let fuchsia_fastboot_mdns_packet =
            fuchsia_fastboot_mdns_packet(fuchsia_node_name.as_str(), &ll_ip6_addr_v6.octets())?
                .into();

        // Creates sockets.
        let mut socket_set = SocketSet::new(&mut self.socket_storage[..]);
        // Creates a TCP socket for fastboot over TCP.
        let tx_socket_buffer = SocketBuffer::new(&mut self.tcp_tx_buffer[..]);
        let rx_socket_buffer = SocketBuffer::new(&mut self.tcp_rx_buffer[..]);
        let mut tcp_socket = TcpSocket::new(rx_socket_buffer, tx_socket_buffer);
        // Fastboot sends short framed responses (e.g. `INFO` followed by `OKAY`); disable Nagle so
        // `OKAY` is never held waiting for the host's delayed ACK of a preceding `INFO`.
        tcp_socket.set_nagle_enabled(false);
        let _ = socket_set.add(tcp_socket);
        // Creates a UDP socket for MDNS broadcast.
        let udp_tx_packet_buffer = PacketBuffer::new(
            &mut self.udp_tx_metadata_buffer[..],
            &mut self.udp_tx_payload_buffer[..],
        );
        let udp_rx_packet_buffer = PacketBuffer::new(
            &mut self.udp_rx_metadata_buffer[..],
            &mut self.udp_rx_payload_buffer[..],
        );
        let udp_socket = UdpSocket::new(udp_rx_packet_buffer, udp_tx_packet_buffer);
        let _ = socket_set.add(udp_socket);
        Ok(EfiTcpSocket {
            efi_entry: self.efi_entry,
            efi_net_dev: &mut self.efi_net_dev,
            interface,
            socket_set,
            io_yield_counter: YieldCounter::new(u64::MAX),
            last_listen_timestamp: None,
            _time_update_event,
            timestamp: self.timestamp,
            clock_fn,
            clock_epoch,
            last_data_poll: None,
            fuchsia_fastboot_mdns_packet,
        })
    }
}

/// The GBL network stack.
///
/// # Lifetimes
///
/// * `'a`: Lifetime of `efi_entry` borrowed.
/// * `'b`: Lifetime of Self.
/// * `'c`: Lifetime of external timestamp borrowed.
#[derive(Default)]
pub struct EfiGblNetwork<'a, 'b, 'c>(Option<EfiGblNetworkInternal<'a, 'b, 'c>>);

impl<'a, 'b, 'c: 'b> EfiGblNetwork<'a, 'b, 'c> {
    /// Initializes GBL network and creates GBL sockets.
    ///
    /// # Args:
    ///
    /// * `efi_entry`: A [EfiEntry].
    /// * `ts`: A reference to an [AtomicU64].
    pub fn init(
        &'b mut self,
        efi_entry: &'a EfiEntry,
        timestamp: &'c AtomicU64,
    ) -> Result<EfiTcpSocket<'a, 'b>> {
        // Drops any existing network first to release the global event notify function.
        self.0 = None;
        self.0 = Some(EfiGblNetworkInternal::new(efi_entry, timestamp)?);
        self.0.as_mut().unwrap().create_socket()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use efi_mocks::{
        protocol::device_path::{DevicePathProtocol, DevicePathText, DevicePathToTextProtocol},
        MockEfi, MockLocatedHandles,
    };
    use efi_types::{
        EfiSimpleNetworkMode, EfiSimpleNetworkState,
        EFI_SIMPLE_NETWORK_STATE_INITIALIZED as INITIALIZED,
        EFI_SIMPLE_NETWORK_STATE_STARTED as STARTED, EFI_SIMPLE_NETWORK_STATE_STOPPED as STOPPED,
    };
    use std::sync::{
        atomic::{AtomicBool, AtomicU32},
        Arc, Mutex,
    };

    fn make_handle(id: usize) -> DeviceHandle {
        DeviceHandle::new(id as _)
    }

    fn make_snp(media_present_supported: bool, media_present: bool) -> SimpleNetworkProtocol {
        let mut snp = SimpleNetworkProtocol::default();
        snp.expect_start().returning(|| Ok(()));
        snp.expect_initialize().returning(|_, _| Ok(()));
        snp.expect_reset().returning(|_| Ok(()));
        snp.expect_get_status_raw().returning(|int_sts, tx_buf| {
            assert!(!int_sts.is_null());
            assert!(!tx_buf.is_null());
            Ok(())
        });
        snp.expect_mode().returning(move || {
            Ok(EfiSimpleNetworkMode {
                media_present_supported,
                media_present,
                ..Default::default()
            })
        });
        snp
    }

    fn setup_device_paths(mock_efi: &mut MockEfi, devices: &[(usize, &'static [u16])]) {
        let ids: Vec<usize> = devices.iter().map(|(id, _)| *id).collect();
        mock_efi
            .boot_services
            .expect_locate_handle_buffer_by_protocol::<SimpleNetworkProtocol>()
            .times(1)
            .return_once(move || {
                Ok(MockLocatedHandles(ids.into_iter().map(make_handle).collect()))
            });

        for &(id, path_u16) in devices {
            mock_efi
                .boot_services
                .expect_open_protocol::<DevicePathProtocol>()
                .times(1)
                .return_once(move |h| {
                    assert_eq!(h, make_handle(id));
                    Ok(DevicePathProtocol::default())
                });
            mock_efi
                .boot_services
                .expect_find_first_and_open::<DevicePathToTextProtocol>()
                .times(1)
                .return_once(move || {
                    let mut path_to_text = DevicePathToTextProtocol::default();
                    path_to_text.expect_convert_device_path_to_text().times(1).return_once(
                        move |_, _, _| {
                            let mut text = DevicePathText::default();
                            text.expect_text().return_const(Some(path_u16));
                            Ok(text)
                        },
                    );
                    Ok(path_to_text)
                });
        }
    }

    const NIC1_PATH: &[u16] = &[b'P' as u16, b'c' as u16, b'i' as u16, b'1' as u16];
    const NIC1_IPV4_PATH: &[u16] = &[
        b'P' as u16,
        b'c' as u16,
        b'i' as u16,
        b'1' as u16,
        b'/' as u16,
        b'I' as u16,
        b'P' as u16,
        b'v' as u16,
        b'4' as u16,
    ];
    const NIC1_IPV6_PATH: &[u16] = &[
        b'P' as u16,
        b'c' as u16,
        b'i' as u16,
        b'1' as u16,
        b'/' as u16,
        b'I' as u16,
        b'P' as u16,
        b'v' as u16,
        b'6' as u16,
    ];
    const NIC2_PATH: &[u16] = &[b'P' as u16, b'c' as u16, b'i' as u16, b'2' as u16];
    const NIC2_IPV4_PATH: &[u16] = &[
        b'P' as u16,
        b'c' as u16,
        b'i' as u16,
        b'2' as u16,
        b'/' as u16,
        b'I' as u16,
        b'P' as u16,
        b'v' as u16,
        b'4' as u16,
    ];

    #[test]
    fn test_find_net_device_ignores_child_paths() {
        let mut mock_efi = MockEfi::new();
        let nic1_ipv6_id = 1;
        let nic1_id = 2;
        let nic1_ipv4_id = 3;

        // Provide handles out of order; child IPv4/IPv6 handles must be deduplicated and never
        // opened for SimpleNetworkProtocol.
        setup_device_paths(
            &mut mock_efi,
            &[(nic1_ipv6_id, NIC1_IPV6_PATH), (nic1_id, NIC1_PATH), (nic1_ipv4_id, NIC1_IPV4_PATH)],
        );

        mock_efi
            .boot_services
            .expect_open_protocol::<SimpleNetworkProtocol>()
            .times(1)
            .return_once(move |h| {
                assert_eq!(h, make_handle(nic1_id));
                Ok(make_snp(true, true))
            });

        let installed = mock_efi.install();
        assert_eq!(find_net_device(installed.entry()), Ok(make_handle(nic1_id)));
    }

    #[test]
    fn test_find_net_device_selects_second_nic_with_media_present() {
        let mut mock_efi = MockEfi::new();
        let nic1_id = 1;
        let nic1_ipv4_id = 2;
        let nic2_id = 3;
        let nic2_ipv4_id = 4;

        setup_device_paths(
            &mut mock_efi,
            &[
                (nic1_ipv4_id, NIC1_IPV4_PATH),
                (nic2_id, NIC2_PATH),
                (nic1_id, NIC1_PATH),
                (nic2_ipv4_id, NIC2_IPV4_PATH),
            ],
        );

        // First root NIC has no link (media_present == false).
        mock_efi
            .boot_services
            .expect_open_protocol::<SimpleNetworkProtocol>()
            .times(1)
            .return_once(move |h| {
                assert_eq!(h, make_handle(nic1_id));
                Ok(make_snp(true, false))
            });

        // Second root NIC has link (media_present == true).
        mock_efi
            .boot_services
            .expect_open_protocol::<SimpleNetworkProtocol>()
            .times(1)
            .return_once(move |h| {
                assert_eq!(h, make_handle(nic2_id));
                Ok(make_snp(true, true))
            });

        let installed = mock_efi.install();
        assert_eq!(find_net_device(installed.entry()), Ok(make_handle(nic2_id)));
    }

    #[test]
    fn test_find_net_device_fallback_to_first_root_nic() {
        let mut mock_efi = MockEfi::new();
        let nic1_id = 1;
        let nic1_ipv6_id = 2;
        let nic2_id = 3;

        setup_device_paths(
            &mut mock_efi,
            &[(nic2_id, NIC2_PATH), (nic1_ipv6_id, NIC1_IPV6_PATH), (nic1_id, NIC1_PATH)],
        );

        // Neither root NIC reports media_present == true.
        mock_efi
            .boot_services
            .expect_open_protocol::<SimpleNetworkProtocol>()
            .times(1)
            .return_once(move |h| {
                assert_eq!(h, make_handle(nic1_id));
                Ok(make_snp(true, false))
            });
        mock_efi
            .boot_services
            .expect_open_protocol::<SimpleNetworkProtocol>()
            .times(1)
            .return_once(move |h| {
                assert_eq!(h, make_handle(nic2_id));
                Ok(make_snp(true, false))
            });

        let installed = mock_efi.install();
        assert_eq!(find_net_device(installed.entry()), Ok(make_handle(nic1_id)));
    }

    #[test]
    fn test_open_simple_network_exclusive_guard_closes_and_reopens() {
        let mut mock_efi = MockEfi::new();

        let held_in_fw = Arc::new(AtomicBool::new(false));
        let held = held_in_fw.clone();
        mock_efi
            .boot_services
            .expect_open_protocol_exclusive::<SimpleNetworkProtocol>()
            .times(2)
            .returning(move |h| {
                assert_eq!(h, make_handle(1));
                if held.swap(true, Ordering::SeqCst) {
                    Err(Error::AccessDenied)
                } else {
                    Ok(ExclusiveProtocol::new(h, SimpleNetworkProtocol::default()))
                }
            });

        let held = held_in_fw.clone();
        mock_efi.boot_services.expect_close_protocol::<SimpleNetworkProtocol>().times(2).returning(
            move |h| {
                assert_eq!(h, make_handle(1));
                assert!(held.swap(false, Ordering::SeqCst));
                Ok(())
            },
        );

        let installed = mock_efi.install();
        let snp1 = open_simple_network(installed.entry(), make_handle(1)).unwrap();
        assert!(matches!(snp1, NetworkProtocol::Exclusive(_)));
        assert!(held_in_fw.load(Ordering::SeqCst));

        // Dropping `snp1` invokes `CloseProtocol`, allowing the next session to open exclusively.
        drop(snp1);
        assert!(!held_in_fw.load(Ordering::SeqCst));

        let snp2 = open_simple_network(installed.entry(), make_handle(1)).unwrap();
        assert!(matches!(snp2, NetworkProtocol::Exclusive(_)));
        assert!(held_in_fw.load(Ordering::SeqCst));
        drop(snp2);
        assert!(!held_in_fw.load(Ordering::SeqCst));
    }

    #[test]
    fn test_open_simple_network_falls_back_to_shared_when_exclusive_fails() {
        let mut mock_efi = MockEfi::new();
        mock_efi
            .boot_services
            .expect_open_protocol_exclusive::<SimpleNetworkProtocol>()
            .times(1)
            .return_once(|_| Err(Error::AccessDenied));
        mock_efi
            .boot_services
            .expect_open_protocol::<SimpleNetworkProtocol>()
            .times(1)
            .return_once(|h| {
                assert_eq!(h, make_handle(1));
                Ok(SimpleNetworkProtocol::default())
            });
        mock_efi.con_out.expect_write_str().returning(|_| Ok(()));

        let installed = mock_efi.install();
        let snp = open_simple_network(installed.entry(), make_handle(1)).unwrap();
        assert!(matches!(snp, NetworkProtocol::Shared(_)));
    }

    #[test]
    fn test_open_simple_network_logs_close_error_on_drop() {
        let mut mock_efi = MockEfi::new();
        mock_efi
            .boot_services
            .expect_open_protocol_exclusive::<SimpleNetworkProtocol>()
            .times(1)
            .return_once(|h| Ok(ExclusiveProtocol::new(h, SimpleNetworkProtocol::default())));
        mock_efi
            .boot_services
            .expect_close_protocol::<SimpleNetworkProtocol>()
            .times(1)
            .return_once(|_| Err(Error::NotFound));

        let logged = Arc::new(Mutex::new(String::new()));
        let logged_clone = logged.clone();
        mock_efi.con_out.expect_write_str().returning(move |s| {
            logged_clone.lock().unwrap().push_str(s);
            Ok(())
        });

        let installed = mock_efi.install();
        let snp = open_simple_network(installed.entry(), make_handle(1)).unwrap();
        drop(snp);

        let msg = logged.lock().unwrap();
        assert!(
            msg.contains("Failed to close exclusive Protocol<"),
            "expected close failure log, got: {msg:?}",
        );
    }

    /// A fake simple network device that follows the UEFI SNP state machine. Calls that are invalid
    /// in the current state fail with the same errors as EDK2's SnpDxe and are counted.
    #[derive(Default)]
    struct FakeSnp {
        state: AtomicU32,
        invalid_calls: AtomicU32,
        resets: AtomicU32,
    }

    impl FakeSnp {
        /// Creates a fake device in `state`.
        fn new(state: EfiSimpleNetworkState) -> Arc<Self> {
            Arc::new(Self { state: AtomicU32::new(state.0), ..Default::default() })
        }

        /// Returns the current state.
        fn state(&self) -> EfiSimpleNetworkState {
            EfiSimpleNetworkState(self.state.load(Ordering::Relaxed))
        }

        /// Returns the number of calls made in a state that does not allow them.
        fn invalid_calls(&self) -> u32 {
            self.invalid_calls.load(Ordering::Relaxed)
        }

        /// Returns the number of successful `Reset()` calls.
        fn resets(&self) -> u32 {
            self.resets.load(Ordering::Relaxed)
        }

        /// Handles a call that is only valid in state `from` by moving to state `to`.
        fn transition(&self, from: EfiSimpleNetworkState, to: EfiSimpleNetworkState) -> Result<()> {
            let state = self.state();
            if state == from {
                self.state.store(to.0, Ordering::Relaxed);
                return Ok(());
            }
            self.invalid_calls.fetch_add(1, Ordering::Relaxed);
            Err(match (from, state) {
                // `Start()`, the only call that is valid in the stopped state.
                (STOPPED, STARTED | INITIALIZED) => Error::AlreadyStarted,
                (_, STOPPED) => Error::NotStarted,
                _ => Error::DeviceError,
            })
        }

        /// Returns a mock protocol instance that operates on this device.
        fn snp(self: &Arc<Self>) -> SimpleNetworkProtocol {
            let mut snp = SimpleNetworkProtocol::default();
            let fake = self.clone();
            snp.expect_start().returning(move || fake.transition(STOPPED, STARTED));
            let fake = self.clone();
            snp.expect_stop().returning(move || fake.transition(STARTED, STOPPED));
            let fake = self.clone();
            snp.expect_initialize().returning(move |_, _| fake.transition(STARTED, INITIALIZED));
            let fake = self.clone();
            snp.expect_shutdown().returning(move || fake.transition(INITIALIZED, STARTED));
            let fake = self.clone();
            snp.expect_reset().returning(move |_| {
                fake.transition(INITIALIZED, INITIALIZED)?;
                fake.resets.fetch_add(1, Ordering::Relaxed);
                Ok(())
            });
            let fake = self.clone();
            snp.expect_mode().returning(move || {
                Ok(EfiSimpleNetworkMode { state: fake.state(), ..Default::default() })
            });
            snp
        }
    }

    /// Checks that `reset_simple_network()` initializes and resets a device in `state` without
    /// making any call that is invalid in the device's current state.
    fn check_reset_simple_network(state: EfiSimpleNetworkState) {
        let fake = FakeSnp::new(state);
        assert_eq!(reset_simple_network(&fake.snp()), Ok(()));
        assert_eq!(fake.state(), INITIALIZED);
        assert_eq!(fake.resets(), 1);
        assert_eq!(fake.invalid_calls(), 0);
    }

    #[test]
    fn test_reset_simple_network_from_stopped() {
        check_reset_simple_network(STOPPED);
    }

    #[test]
    fn test_reset_simple_network_from_started() {
        check_reset_simple_network(STARTED);
    }

    #[test]
    fn test_reset_simple_network_from_initialized() {
        check_reset_simple_network(INITIALIZED);
    }

    #[test]
    fn test_reset_simple_network_rejects_unknown_state() {
        let fake = FakeSnp::new(EfiSimpleNetworkState(3));
        assert_eq!(reset_simple_network(&fake.snp()), Err(Error::InvalidState));
        assert_eq!(fake.invalid_calls(), 0);
    }

    #[test]
    fn test_reset_simple_network_after_network_device_drop() {
        // Each fastboot session drops its `EfiNetworkDevice`, which leaves the network started,
        // and the next session resets it from there.
        let installed = MockEfi::new().install();
        let fake = FakeSnp::new(STOPPED);
        let snp = fake.snp();
        assert_eq!(reset_simple_network(&snp), Ok(()));
        drop(EfiNetworkDevice::new(NetworkProtocol::Shared(snp), 0, installed.entry()));
        assert_eq!(fake.state(), STARTED);

        assert_eq!(reset_simple_network(&fake.snp()), Ok(()));
        assert_eq!(fake.state(), INITIALIZED);
        assert_eq!(fake.invalid_calls(), 0);
    }

    #[test]
    fn test_reset_simple_network_falls_back_when_extra_rx_buffer_unsupported() {
        for err in [Error::OutOfResources, Error::Unsupported, Error::DeviceError] {
            let fake = FakeSnp::new(STARTED);
            let mut snp = SimpleNetworkProtocol::default();
            let fake_mode = fake.clone();
            snp.expect_mode().returning(move || {
                Ok(EfiSimpleNetworkMode { state: fake_mode.state(), ..Default::default() })
            });
            let fake_init = fake.clone();
            snp.expect_initialize().times(1).returning(move |extra_rx, extra_tx| {
                assert_eq!(extra_rx, SNP_EXTRA_RX_BUFFER_SIZE);
                assert_eq!(extra_tx, 0);
                assert_eq!(fake_init.state(), STARTED);
                Err(err)
            });
            let fake_fallback = fake.clone();
            snp.expect_initialize().times(1).returning(move |extra_rx, extra_tx| {
                assert_eq!((extra_rx, extra_tx), (0, 0));
                fake_fallback.transition(STARTED, INITIALIZED)
            });
            let fake_reset = fake.clone();
            snp.expect_reset().times(1).returning(move |_| {
                fake_reset.transition(INITIALIZED, INITIALIZED)?;
                fake_reset.resets.fetch_add(1, Ordering::Relaxed);
                Ok(())
            });

            assert_eq!(reset_simple_network(&snp), Ok(()));
            assert_eq!(fake.state(), INITIALIZED);
            assert_eq!(fake.resets(), 1);
            assert_eq!(fake.invalid_calls(), 0);
        }
    }

    #[test]
    fn test_reset_simple_network_propagates_initialize_error_when_not_started() {
        let fake = FakeSnp::new(STARTED);
        let mut snp = SimpleNetworkProtocol::default();
        let fake_mode = fake.clone();
        snp.expect_mode().returning(move || {
            Ok(EfiSimpleNetworkMode { state: fake_mode.state(), ..Default::default() })
        });
        let fake_init = fake.clone();
        snp.expect_initialize().times(1).returning(move |extra_rx, extra_tx| {
            assert_eq!((extra_rx, extra_tx), (SNP_EXTRA_RX_BUFFER_SIZE, 0));
            let _ = fake_init.transition(STARTED, STOPPED);
            Err(Error::DeviceError)
        });

        assert_eq!(reset_simple_network(&snp), Err(Error::DeviceError));
        assert_eq!(fake.state(), STOPPED);
    }

    #[test]
    fn test_reset_simple_network_tolerates_unsupported_reset_only() {
        for (reset_err, expected) in
            [(Error::Unsupported, Ok(())), (Error::DeviceError, Err(Error::DeviceError))]
        {
            let fake = FakeSnp::new(STARTED);
            let mut snp = SimpleNetworkProtocol::default();
            let fake_mode = fake.clone();
            snp.expect_mode().returning(move || {
                Ok(EfiSimpleNetworkMode { state: fake_mode.state(), ..Default::default() })
            });
            let fake_init = fake.clone();
            snp.expect_initialize()
                .times(1)
                .returning(move |_, _| fake_init.transition(STARTED, INITIALIZED));
            let fake_reset = fake.clone();
            snp.expect_reset().times(1).returning(move |extended_verification| {
                assert!(extended_verification);
                fake_reset.transition(INITIALIZED, INITIALIZED)?;
                Err(reset_err)
            });

            assert_eq!(reset_simple_network(&snp), expected);
            assert_eq!(fake.state(), INITIALIZED);
            assert_eq!(fake.invalid_calls(), 0);
        }
    }

    #[test]
    fn test_network_device_capabilities_standard_ethernet_mtu() {
        let installed = MockEfi::new().install();
        let fake = FakeSnp::new(STOPPED);
        let snp = fake.snp();
        assert_eq!(reset_simple_network(&snp), Ok(()));
        let dev = EfiNetworkDevice::new(NetworkProtocol::Shared(snp), 0, installed.entry());
        assert_eq!(dev.capabilities().max_transmission_unit, ETHERNET_MAX_FRAME_SIZE);
    }

    static FAKE_CLOCK_US: AtomicU64 = AtomicU64::new(0);

    fn fake_clock() -> Result<Duration> {
        Ok(Duration::from_micros(FAKE_CLOCK_US.load(Ordering::Relaxed)))
    }

    fn make_test_network<'a, 'b, 'c>(
        efi_entry: &'a EfiEntry,
        snp: SimpleNetworkProtocol,
        timestamp: &'c AtomicU64,
    ) -> EfiGblNetworkInternal<'a, 'b, 'c> {
        EfiGblNetworkInternal {
            efi_entry,
            tcp_tx_buffer: vec![0u8; SOCKET_TX_RX_BUFFER],
            tcp_rx_buffer: vec![0u8; SOCKET_TX_RX_BUFFER],
            udp_tx_payload_buffer: vec![0u8; ETHERNET_FRAME_BUFFER_SIZE],
            udp_rx_payload_buffer: vec![0u8; ETHERNET_FRAME_BUFFER_SIZE],
            udp_tx_metadata_buffer: vec![PacketMetadata::EMPTY; 1],
            udp_rx_metadata_buffer: vec![PacketMetadata::EMPTY; 1],
            socket_storage: Default::default(),
            efi_net_dev: EfiNetworkDevice::new(NetworkProtocol::Shared(snp), 7, efi_entry),
            timestamp,
            notify_fn: None,
            notify: None,
        }
    }

    #[test]
    fn test_create_socket_with_clock_skips_periodic_timer_and_uses_micros() {
        // `MockEfi` expects 0 calls to `create_event_with_notification` and `set_timer` unless
        // configured, verifying that the periodic UEFI timer is not created when `clock_fn`
        // succeeds.
        let installed = MockEfi::new().install();
        let fake = FakeSnp::new(INITIALIZED);
        let timestamp = AtomicU64::new(0);
        let mut net = make_test_network(installed.entry(), fake.snp(), &timestamp);

        FAKE_CLOCK_US.store(1_000, Ordering::Relaxed);
        let mut socket = net.create_socket_with_clock(fake_clock).unwrap();
        assert!(socket._time_update_event.is_none());
        assert_eq!(socket.clock_epoch, Some(Duration::from_micros(1_000)));
        assert_eq!(socket.instant(), Instant::from_micros(0));

        // Sub-millisecond clock advancement is preserved in `instant()`, while `timestamp()`
        // reports elapsed whole milliseconds.
        FAKE_CLOCK_US.store(2_350, Ordering::Relaxed);
        assert_eq!(socket.instant(), Instant::from_micros(1_350));
        assert_eq!(socket.timestamp(0), Duration::from_millis(1));

        // `listen()` clears `last_data_poll`.
        socket.last_data_poll = Some(Duration::from_micros(500));
        socket.listen(5554).unwrap();
        assert_eq!(socket.last_data_poll, None);
    }

    #[test]
    fn test_socket_receive_batches_polls_with_fake_clock() {
        let installed = MockEfi::new().install();
        let rx_polls = Arc::new(AtomicU32::new(0));
        let rx_polls_clone = rx_polls.clone();
        let mut snp = FakeSnp::new(INITIALIZED).snp();
        snp.expect_receive_raw().returning(move |_, _, _, _, _, _| {
            rx_polls_clone.fetch_add(1, Ordering::Relaxed);
            Err(Error::NotReady)
        });

        let timestamp = AtomicU64::new(0);
        let mut net = make_test_network(installed.entry(), snp, &timestamp);
        FAKE_CLOCK_US.store(10_000, Ordering::Relaxed);
        let mut socket = net.create_socket_with_clock(fake_clock).unwrap();

        // Empty output buffer returns `Ok(0)` immediately without polling.
        assert_eq!(gbl_async::block_on(socket.receive(&mut [], Duration::from_secs(1))), Ok(0));
        assert_eq!(rx_polls.load(Ordering::Relaxed), 0);

        // Within `BULK_RECEIVE_POLL_INTERVAL` (50 us < 100 us), `receive()` skips polling the NIC.
        socket.last_data_poll = Some(Duration::from_micros(100));
        FAKE_CLOCK_US.store(10_150, Ordering::Relaxed);
        let mut buf = [0u8; 16];
        assert_eq!(
            gbl_async::block_on(socket.receive(&mut buf, Duration::from_secs(1))),
            Err(Error::Disconnected)
        );
        assert_eq!(rx_polls.load(Ordering::Relaxed), 0);

        // Once `BULK_RECEIVE_POLL_INTERVAL` (100 us) has elapsed, `receive()` polls the NIC.
        FAKE_CLOCK_US.store(10_200, Ordering::Relaxed);
        assert_eq!(
            gbl_async::block_on(socket.receive(&mut buf, Duration::from_secs(1))),
            Err(Error::Disconnected)
        );
        assert_eq!(rx_polls.load(Ordering::Relaxed), 1);
    }

    fn make_tx_test_snp(
        fake: &Arc<FakeSnp>,
    ) -> (
        SimpleNetworkProtocol,
        Arc<Mutex<std::collections::VecDeque<usize>>>,
        Arc<Mutex<Vec<usize>>>,
    ) {
        let recycled = Arc::new(Mutex::new(std::collections::VecDeque::new()));
        let transmitted = Arc::new(Mutex::new(Vec::new()));
        let mut snp = fake.snp();

        let recycled_status = recycled.clone();
        snp.expect_get_status_raw().returning(move |_, tx_buf| {
            if let Some(addr) = recycled_status.lock().unwrap().pop_front() {
                // SAFETY: `tx_buf` points to the caller's local `ptr` output variable in
                // `SimpleNetworkProtocol::get_status`.
                unsafe { *tx_buf = addr as *mut c_void };
            }
            Ok(())
        });

        let transmitted_tx = transmitted.clone();
        snp.expect_transmit().returning(move |_, buf, _, _, _| {
            transmitted_tx.lock().unwrap().push(buf.cast::<u8>().as_ptr() as usize);
            Ok(())
        });

        (snp, recycled, transmitted)
    }

    #[test]
    fn test_tx_token_reentry_with_stale_recycled_pool_buffer_does_not_alias() {
        use smoltcp::phy::TxToken as _;

        let installed = MockEfi::new().install();
        let fake = FakeSnp::new(INITIALIZED);
        let (snp, recycled, transmitted) = make_tx_test_snp(&fake);
        let mut dev = EfiNetworkDevice::new(NetworkProtocol::Shared(snp), 1, installed.entry());

        // Simulate session re-entry where UEFI pool allocation reused `tx_frames[0]`'s address
        // while the SNP driver's `GetStatus()` queue still holds stale entries from an earlier
        // session.
        let buf0 = dev.tx_frames[0].buf.as_ptr() as usize;
        let buf1 = dev.tx_frames[1].buf.as_ptr() as usize;
        recycled.lock().unwrap().extend([0xdead_beefusize, buf0]);

        // Packet 1 drains the stale entries and puts `buf0` in flight with `[0x11; 4]`.
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0x11; 4]));
        assert_eq!(transmitted.lock().unwrap().as_slice(), &[buf0]);
        assert!(recycled.lock().unwrap().is_empty(), "stale recycled pointers must be drained");

        // Packet 2 arrives before Packet 1 completes (`GetStatus()` returns null): it must use
        // `buf1` rather than handing out `buf0` a second time while `buf0` is in flight.
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0x22; 4]));
        assert_eq!(transmitted.lock().unwrap().as_slice(), &[buf0, buf1]);
        // SAFETY: `buf0` is a live `[u8; ETHERNET_FRAME_BUFFER_SIZE]` owned by `dev` until drop,
        // and no mutable reference to it exists outside `consume`.
        let buf0_payload = unsafe { core::slice::from_raw_parts(buf0 as *const u8, 4) };
        assert_eq!(buf0_payload, &[0x11; 4]);
    }

    #[test]
    fn test_tx_token_ignores_stale_and_duplicate_recycled_buffers() {
        use smoltcp::phy::TxToken as _;

        let installed = MockEfi::new().install();
        let fake = FakeSnp::new(INITIALIZED);
        let (snp, recycled, transmitted) = make_tx_test_snp(&fake);
        let mut dev = EfiNetworkDevice::new(NetworkProtocol::Shared(snp), 1, installed.entry());

        // Packet 1 and Packet 2 allocate the two distinct pool frames `buf0` and `buf1`.
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0x11; 4]));
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0x22; 4]));
        let (buf0, buf1) = {
            let tx = transmitted.lock().unwrap();
            assert_eq!(tx.len(), 2);
            assert_ne!(tx[0], tx[1], "initial transmits must use distinct frame buffers");
            (tx[0], tx[1])
        };

        // `buf0` and `buf1` complete, with a foreign pointer and a duplicate/stale `buf0` queued
        // in `GetStatus()` between them.
        recycled.lock().unwrap().extend([buf0, 0xdead_beefusize, buf0, buf1]);

        // Packet 3 drains ready entries (deduplicating `buf0`) and puts `buf0` in flight with
        // payload `[0x33; 4]`.
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0x33; 4]));
        assert_eq!(transmitted.lock().unwrap()[2], buf0);

        // While Packet 3 is still DMA in-flight in `buf0`, Packet 4 must select `buf1` and leave
        // `buf0`'s in-flight payload intact.
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0x44; 4]));
        assert_eq!(transmitted.lock().unwrap()[3], buf1);
        // SAFETY: `buf0` is a live `[u8; ETHERNET_FRAME_BUFFER_SIZE]` owned by `dev` until drop,
        // and no mutable reference to it exists outside `consume`.
        let buf0_payload = unsafe { core::slice::from_raw_parts(buf0 as *const u8, 4) };
        assert_eq!(buf0_payload, &[0x33; 4]);
    }

    static TIMEOUT_MOCK_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_tx_token_drains_stale_recycled_buffers_across_timeout_reset() {
        use smoltcp::phy::TxToken as _;

        let _timeout_guard = TIMEOUT_MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut mock_efi = MockEfi::new();
        mock_efi.con_out.expect_write_str().returning(|_| Ok(()));
        let installed = mock_efi.install();

        let fake = FakeSnp::new(INITIALIZED);
        let (snp, recycled, transmitted) = make_tx_test_snp(&fake);
        let mut dev = EfiNetworkDevice::new(NetworkProtocol::Shared(snp), 1, installed.entry());
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0x11; 4]));
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0x22; 4]));
        let (buf0, buf1) = {
            let tx = transmitted.lock().unwrap();
            (tx[0], tx[1])
        };

        // Both TX slots are now in flight. Simulate a TX recycle timeout where `Shutdown()` +
        // `Initialize()` inside `reset_simple_network()` leaves stale recycled TX entries
        // (`[0xfeed_face, buf0]`) queued in `GetStatus()`.
        let recycled_on_timeout = recycled.clone();
        let timeout_ctx = Timeout::new_context();
        timeout_ctx.expect().times(1).return_once(move |_, _| {
            let mut timeout = Timeout::default();
            let mut checks = 0;
            timeout.expect_check().returning(move || {
                checks += 1;
                if checks == 1 {
                    Ok(false)
                } else {
                    recycled_on_timeout.lock().unwrap().extend([0xfeed_faceusize, buf0]);
                    Ok(true)
                }
            });
            Ok(timeout)
        });

        // Packet 3 times out, resets the network, drains `[0xfeed_face, buf0]`, and transmits
        // `[0xaa; 4]` using `buf0`.
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0xaa; 4]));
        drop(timeout_ctx);
        assert_eq!(fake.resets(), 1);
        assert_eq!(fake.invalid_calls(), 0);
        assert_eq!(transmitted.lock().unwrap()[2], buf0);
        assert!(
            recycled.lock().unwrap().is_empty(),
            "stale recycled TX pointers must be drained before transmitting",
        );

        // Immediately transmit Packet 4 while Packet 3 (`buf0`) is still in flight (`GetStatus()`
        // returns null). Packet 4 must use `buf1` rather than aliasing `buf0`.
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0xbb; 4]));
        assert_eq!(transmitted.lock().unwrap()[3], buf1);
        // SAFETY: `buf0` is a live `[u8; ETHERNET_FRAME_BUFFER_SIZE]` owned by `dev` until drop,
        // and no mutable reference to it exists outside `consume`.
        let buf0_payload = unsafe { core::slice::from_raw_parts(buf0 as *const u8, 4) };
        assert_eq!(buf0_payload, &[0xaa; 4]);
    }

    #[test]
    fn test_tx_token_transmit_error_keeps_slot_idle_and_bounds_stale_polls() {
        use smoltcp::phy::TxToken as _;

        let installed = MockEfi::new().install();
        let get_status_calls = Arc::new(AtomicU32::new(0));
        let fail_transmit = Arc::new(AtomicBool::new(true));
        let transmitted: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));

        let mut snp = FakeSnp::new(INITIALIZED).snp();
        let calls_clone = get_status_calls.clone();
        snp.expect_get_status_raw().returning(move |_, tx_buf| {
            calls_clone.fetch_add(1, Ordering::Relaxed);
            // Broken firmware endlessly reporting a foreign non-null recycled buffer pointer.
            // SAFETY: `tx_buf` points to the caller's local `ptr` output variable in
            // `SimpleNetworkProtocol::get_status`.
            unsafe { *tx_buf = 0xbad0_c0deusize as *mut c_void };
            Ok(())
        });
        let fail_clone = fail_transmit.clone();
        let transmitted_tx = transmitted.clone();
        snp.expect_transmit().returning(move |_, buf, _, _, _| {
            if fail_clone.swap(false, Ordering::Relaxed) {
                return Err(Error::DeviceError);
            }
            transmitted_tx.lock().unwrap().push(buf.cast::<u8>().as_ptr() as usize);
            Ok(())
        });

        // Single-slot pool (`extra_tx_frames = 0`).
        let mut dev = EfiNetworkDevice::new(NetworkProtocol::Shared(snp), 0, installed.entry());

        // First `transmit` fails with `DeviceError`: the drain loop must terminate after a bounded
        // number of `get_status` polls, and the rejected buffer must remain idle (`!in_flight`).
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0x55; 4]));
        let first_polls = get_status_calls.load(Ordering::Relaxed);
        assert!(
            (1..=256).contains(&first_polls),
            "expected bounded stale get_status polling, got {first_polls}",
        );
        assert!(transmitted.lock().unwrap().is_empty(), "failed transmit must not record success");

        // Second `transmit` immediately reuses the single slot without timing out.
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0x66; 4]));
        assert_eq!(transmitted.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_tx_token_retries_not_ready_until_ready() {
        use smoltcp::phy::TxToken as _;

        let _timeout_guard = TIMEOUT_MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let installed = MockEfi::new().install();
        let fake = FakeSnp::new(INITIALIZED);
        let recycled = Arc::new(Mutex::new(std::collections::VecDeque::<usize>::new()));
        let transmitted = Arc::new(Mutex::new(Vec::<(usize, Vec<u8>)>::new()));
        let attempts = Arc::new(AtomicU32::new(0));

        let mut snp = fake.snp();
        let recycled_status = recycled.clone();
        snp.expect_get_status_raw().returning(move |_, tx_buf| {
            if let Some(addr) = recycled_status.lock().unwrap().pop_front() {
                // SAFETY: `tx_buf` points to the caller's local `ptr` output variable in
                // `SimpleNetworkProtocol::get_status`.
                unsafe { *tx_buf = addr as *mut c_void };
            }
            Ok(())
        });

        let attempts_tx = attempts.clone();
        let recycled_tx = recycled.clone();
        let transmitted_tx = transmitted.clone();
        snp.expect_transmit().returning(move |_, buf, _, _, _| {
            let call = attempts_tx.fetch_add(1, Ordering::Relaxed) + 1;
            // Packet 1 (`call == 1`) succeeds immediately; Packet 2 gets `NotReady` on `call == 2`
            // and `call == 3` (with `buf0` completing on `call == 3`) before succeeding on
            // `call == 4`.
            match call {
                2 => return Err(Error::NotReady),
                3 => {
                    let buf0 = transmitted_tx.lock().unwrap()[0].0;
                    recycled_tx.lock().unwrap().push_back(buf0);
                    return Err(Error::NotReady);
                }
                _ => {}
            }
            // SAFETY: `buf` points to a live `[u8]` slice prepared by `TxToken::consume`.
            let bytes = unsafe { buf.as_ref() }.to_vec();
            transmitted_tx.lock().unwrap().push((buf.cast::<u8>().as_ptr() as usize, bytes));
            Ok(())
        });

        let mut dev = EfiNetworkDevice::new(NetworkProtocol::Shared(snp), 1, installed.entry());
        let buf0 = dev.tx_frames[0].buf.as_ptr() as usize;
        let buf1 = dev.tx_frames[1].buf.as_ptr() as usize;

        // Packet 1 succeeds on the first call without creating a `Timeout`.
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0x11; 4]));
        assert_eq!(attempts.load(Ordering::Relaxed), 1);

        // Packet 2 hits `NotReady` twice, arms a single `Timeout`, reclaims `buf0` during retry
        // polling, and transmits `buf1` on the third attempt with its payload intact.
        let timeout_ctx = Timeout::new_context();
        timeout_ctx.expect().times(1).return_once(|_, _| {
            let mut timeout = Timeout::default();
            timeout.expect_check().times(2).returning(|| Ok(false));
            Ok(timeout)
        });
        let ret = dev.transmit(Instant::ZERO).unwrap().consume(4, |b| {
            b.copy_from_slice(&[0x22; 4]);
            7usize
        });
        drop(timeout_ctx);
        assert_eq!(ret, 7);
        assert_eq!(attempts.load(Ordering::Relaxed), 4);
        {
            let tx = transmitted.lock().unwrap();
            assert_eq!(tx.len(), 2);
            assert_eq!(tx[0], (buf0, vec![0x11; 4]));
            assert_eq!(tx[1], (buf1, vec![0x22; 4]));
        }

        // Packet 3 immediately reuses reclaimed `buf0` while `buf1` stays in flight.
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0x33; 4]));
        assert_eq!(transmitted.lock().unwrap()[2], (buf0, vec![0x33; 4]));
        // SAFETY: `buf1` is a live `[u8; ETHERNET_FRAME_BUFFER_SIZE]` owned by `dev` until drop,
        // and no mutable reference to it exists outside `consume`.
        let buf1_payload = unsafe { core::slice::from_raw_parts(buf1 as *const u8, 4) };
        assert_eq!(buf1_payload, &[0x22; 4]);
    }

    #[test]
    fn test_tx_token_not_ready_timeout_drops_frame_and_keeps_slot_idle() {
        use smoltcp::phy::TxToken as _;

        let _timeout_guard = TIMEOUT_MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let installed = MockEfi::new().install();
        let fake = FakeSnp::new(INITIALIZED);
        let ready = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(AtomicU32::new(0));
        let transmitted = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));

        let mut snp = fake.snp();
        snp.expect_get_status_raw().returning(|_, _| Ok(()));
        let ready_tx = ready.clone();
        let attempts_tx = attempts.clone();
        let transmitted_tx = transmitted.clone();
        snp.expect_transmit().returning(move |_, buf, _, _, _| {
            attempts_tx.fetch_add(1, Ordering::Relaxed);
            if !ready_tx.load(Ordering::Relaxed) {
                return Err(Error::NotReady);
            }
            // SAFETY: `buf` points to a live `[u8]` slice prepared by `TxToken::consume`.
            transmitted_tx.lock().unwrap().push(unsafe { buf.as_ref() }.to_vec());
            Ok(())
        });

        let mut dev = EfiNetworkDevice::new(NetworkProtocol::Shared(snp), 0, installed.entry());

        // `transmit` keeps returning `NotReady` until the retry timer expires on the 3rd check.
        let timeout_ctx = Timeout::new_context();
        timeout_ctx.expect().times(1).return_once(|_, _| {
            let mut timeout = Timeout::default();
            let mut checks = 0;
            timeout.expect_check().times(3).returning(move || {
                checks += 1;
                Ok(checks >= 3)
            });
            Ok(timeout)
        });
        let ret = dev.transmit(Instant::ZERO).unwrap().consume(4, |b| {
            b.copy_from_slice(&[0xaa; 4]);
            42usize
        });
        drop(timeout_ctx);
        assert_eq!(ret, 42);
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
        assert_eq!(fake.resets(), 0);
        assert!(transmitted.lock().unwrap().is_empty(), "timed-out frame must not record transmit");

        // Once the NIC TX ring drains, the single slot is still idle and immediately reusable.
        ready.store(true, Ordering::Relaxed);
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0xbb; 4]));
        assert_eq!(transmitted.lock().unwrap().as_slice(), &[vec![0xbb; 4]]);
    }

    #[test]
    fn test_tx_token_not_ready_stops_immediately_on_non_retryable_error() {
        use smoltcp::phy::TxToken as _;

        let _timeout_guard = TIMEOUT_MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let installed = MockEfi::new().install();
        let attempts = Arc::new(AtomicU32::new(0));
        let mut snp = FakeSnp::new(INITIALIZED).snp();
        snp.expect_get_status_raw().returning(|_, _| Ok(()));
        let attempts_tx = attempts.clone();
        snp.expect_transmit().returning(move |_, _, _, _, _| {
            match attempts_tx.fetch_add(1, Ordering::Relaxed) {
                0 => Err(Error::NotReady),
                1 => Err(Error::DeviceError),
                _ => Ok(()),
            }
        });

        let mut dev = EfiNetworkDevice::new(NetworkProtocol::Shared(snp), 0, installed.entry());

        let timeout_ctx = Timeout::new_context();
        timeout_ctx.expect().times(1).return_once(|_, _| {
            let mut timeout = Timeout::default();
            timeout.expect_check().times(1).returning(|| Ok(false));
            Ok(timeout)
        });
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0xcc; 4]));
        drop(timeout_ctx);
        assert_eq!(attempts.load(Ordering::Relaxed), 2);

        // Slot remained idle (`!in_flight`), so the next transmit reuses it immediately.
        dev.transmit(Instant::ZERO).unwrap().consume(4, |b| b.copy_from_slice(&[0xdd; 4]));
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
    }
}
