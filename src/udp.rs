// SPDX-License-Identifier: GPL-2.0-or-later

//! UDP flows from the namespace to the host, and from the host to the
//! namespace
//!
//! Modelled on udp.c and udp_flow.c in passt:
//!   Copyright (c) 2020-2021 Red Hat GmbH
//!   Author: Stefano Brivio <sbrivio@redhat.com>
//!   Copyright Red Hat, author: David Gibson <david@gibson.dropbear.id.au>
//!
//! # Theory of Operation
//!
//! As in pasta, a flow is a client (address and port) sending to one of our
//! forwarded ports, at one of the addresses we receive on: in the namespace,
//! or on the host for inbound forwarding (-u).  For each flow, we create a
//! socket on the other side, connect()ed to the target, so that it receives
//! replies for this flow only: on the host, or in the namespace, from a pool
//! of sockets created there (see ns.rs).  Datagrams are copied with
//! recvmmsg() and sendmmsg(): splice() doesn't apply to them.
//!
//! pasta sends replies to the client through another flow specific socket,
//! bound to the forwarded port and connect()ed to the client.  Instead,
//! replies go out through the receiving socket for the forwarded port, which
//! is bound to the wildcard address (unless a listening address was given
//! for -u), as sendmsg() with the original destination address of the
//! client's datagrams as source (IP_PKTINFO or IPV6_PKTINFO).  For outbound
//! forwarding, we couldn't create sockets in the namespace anyway, and doing
//! the same for inbound forwarding saves a socket per flow.  Clients see
//! replies come from the address and port they sent to, as with pasta.
//!
//! Unlike in pasta, the socket for the target isn't bound to the source port
//! (or, for outbound flows, address) of the client: the kernel picks them, as
//! for TCP.  For outbound flows, the client's source address is a loopback
//! address in the namespace, which makes no sense as a source for targets
//! that aren't on loopback, and its source port might be in use on the host.
//!
//! Flows expire as in pasta, after UDP_TIMEOUT without datagrams in either
//! direction, or UDP_TIMEOUT_STREAM for flows with more than one datagram on
//! either side and at least one reply.  pasta reads both from the netfilter
//! connection tracking settings, falling back to the same defaults.

use std::collections::HashMap;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::ptr;
use std::time::{Duration, Instant};

use crate::config::{self, Target};
use crate::epoll::{Epoll, Ref};
use crate::log::{debug, info};
use crate::sys::{self, cvt, retry_eintr};

/// Maximum number of datagrams received at once
const BATCH: usize = 32;
/// Receive buffer size per datagram: any IPv4 or IPv6 (non-jumbo) datagram
const MAX_DGRAM: usize = 65536;
/// Expiry of flows without traffic, see module documentation
const UDP_TIMEOUT: Duration = Duration::from_secs(30);
const UDP_TIMEOUT_STREAM: Duration = Duration::from_secs(120);
/// Interval between checks for expired flows
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// Minimum interval between messages about failures to create flows
const ERR_INTERVAL: Duration = Duration::from_secs(1);
/// Space for one IP_PKTINFO or IPV6_PKTINFO control message, as u64s
const CTRL_U64S: usize = 8;

/// Flow lookup key: index of receiving socket, namespace address the client
/// sent to, client address
type Key = (usize, IpAddr, SocketAddr);

struct Flow {
    /// Socket connected to the target: on the host, or in the namespace
    sock: OwnedFd,
    key: Key,
    /// Address of the client, as received, to send replies to
    client: (libc::sockaddr_storage, libc::socklen_t),
    /// Time of the last datagram in either direction
    ts: Instant,
    /// Datagrams from the client (0) and replies (1), saturating
    activity: [u8; 2],
}

impl Flow {
    fn timeout(&self) -> Duration {
        if self.activity[1] > 0 && (self.activity[0] > 1 || self.activity[1] > 1) {
            UDP_TIMEOUT_STREAM
        } else {
            UDP_TIMEOUT
        }
    }

    fn active(&mut self, sidei: usize, now: Instant) {
        self.ts = now;
        self.activity[sidei] = self.activity[sidei].saturating_add(1);
    }
}

/// Buffers for recvmmsg() and sendmmsg()
struct Bufs {
    data: Vec<u8>,
    c: Box<CBufs>,
}

/// Message headers and metadata for Bufs
struct CBufs {
    names: [libc::sockaddr_storage; BATCH],
    ctrl: [[u64; CTRL_U64S]; BATCH],
    iov: [libc::iovec; BATCH],
    hdrs: [libc::mmsghdr; BATCH],
    /// Separate headers for sending, so that we can send parts of a batch
    siov: [libc::iovec; BATCH],
    shdrs: [libc::mmsghdr; BATCH],
}

impl Bufs {
    fn new() -> Box<Self> {
        Box::new(Bufs {
            data: vec![0; BATCH * MAX_DGRAM],
            // SAFETY: All-zero is valid for these C structures (NULL pointers)
            c: Box::new(unsafe { zeroed() }),
        })
    }

    /// Receive up to BATCH datagrams from @fd, with source addresses and
    /// control messages if @meta is set
    ///
    /// Return: number of datagrams received, 0 if none were available
    fn recv(&mut self, fd: RawFd, meta: bool) -> io::Result<usize> {
        for i in 0..BATCH {
            self.c.iov[i] = libc::iovec {
                iov_base: self.data[i * MAX_DGRAM..].as_mut_ptr().cast(),
                iov_len: MAX_DGRAM,
            };
            // SAFETY: All-zero is a valid msghdr
            let mut h: libc::msghdr = unsafe { zeroed() };
            h.msg_iov = &mut self.c.iov[i];
            h.msg_iovlen = 1;
            if meta {
                h.msg_name = (&mut self.c.names[i] as *mut libc::sockaddr_storage).cast();
                h.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
                h.msg_control = self.c.ctrl[i].as_mut_ptr().cast();
                h.msg_controllen = size_of::<[u64; CTRL_U64S]>() as _;
            }
            self.c.hdrs[i] = libc::mmsghdr { msg_hdr: h, msg_len: 0 };
        }
        let (n, err) = retry_eintr(|| {
            // SAFETY: hdrs describe valid buffers, as set up above
            unsafe {
                libc::recvmmsg(fd, self.c.hdrs.as_mut_ptr(), BATCH as _, libc::MSG_DONTWAIT,
                               ptr::null_mut()) as isize
            }
        });
        match n {
            n if n >= 0 => Ok(n as usize),
            _ if err == libc::EAGAIN => Ok(0),
            _ => Err(io::Error::from_raw_os_error(err)),
        }
    }

    /// Payload of received datagram @i, None if it was truncated
    fn payload(&self, i: usize) -> Option<&[u8]> {
        let h = &self.c.hdrs[i];
        if h.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
            return None;
        }
        Some(&self.data[i * MAX_DGRAM..][..h.msg_len as usize])
    }

    /// Source address of received datagram @i, as given by the kernel
    fn name(&self, i: usize) -> (libc::sockaddr_storage, libc::socklen_t) {
        (self.c.names[i], self.c.hdrs[i].msg_hdr.msg_namelen)
    }

    /// Destination address of received datagram @i, from IP(V6)_PKTINFO
    fn dst(&self, i: usize) -> Option<IpAddr> {
        let msg = &self.c.hdrs[i].msg_hdr;
        // SAFETY: The kernel filled in the control buffer, we only walk the
        // headers it wrote, and read payloads of the size their type implies
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(msg);
            while !cmsg.is_null() {
                match ((*cmsg).cmsg_level, (*cmsg).cmsg_type) {
                    (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                        let pi: libc::in6_pktinfo = ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast());
                        let a = Ipv6Addr::from(pi.ipi6_addr.s6_addr);
                        return Some(a.to_ipv4_mapped().map_or(IpAddr::V6(a), IpAddr::V4));
                    }
                    (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                        let pi: libc::in_pktinfo = ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast());
                        return Some(Ipv4Addr::from(u32::from_be(pi.ipi_addr.s_addr)).into());
                    }
                    _ => {}
                }
                cmsg = libc::CMSG_NXTHDR(msg, cmsg);
            }
        }
        None
    }

    /// Send received datagrams @idx on @fd, to @dest from @src if given
    ///
    /// Return: number of datagrams dropped
    fn send(&mut self, fd: RawFd, idx: &[usize],
            dest: Option<&(libc::sockaddr_storage, libc::socklen_t)>,
            src: Option<(IpAddr, bool)>) -> usize {
        let mut name = dest.map(|d| d.0);
        let mut ctrl = [0u64; CTRL_U64S];
        let ctrl_len = src.map_or(0, |(a, v6)| pktinfo(&mut ctrl, a, v6));

        for (j, &i) in idx.iter().enumerate() {
            self.c.siov[j] = libc::iovec {
                iov_base: self.data[i * MAX_DGRAM..].as_mut_ptr().cast(),
                iov_len: self.c.hdrs[i].msg_len as usize,
            };
            // SAFETY: All-zero is a valid msghdr
            let mut h: libc::msghdr = unsafe { zeroed() };
            h.msg_iov = &mut self.c.siov[j];
            h.msg_iovlen = 1;
            if let (Some(n), Some(d)) = (name.as_mut(), dest) {
                h.msg_name = (n as *mut libc::sockaddr_storage).cast();
                h.msg_namelen = d.1;
            }
            if ctrl_len > 0 {
                h.msg_control = ctrl.as_mut_ptr().cast();
                h.msg_controllen = ctrl_len as _;
            }
            self.c.shdrs[j] = libc::mmsghdr { msg_hdr: h, msg_len: 0 };
        }

        let (mut sent, mut dropped) = (0, 0);
        while sent < idx.len() {
            let (n, err) = retry_eintr(|| {
                // SAFETY: shdrs describe valid buffers, as set up above
                unsafe {
                    libc::sendmmsg(fd, self.c.shdrs[sent..].as_mut_ptr(), (idx.len() - sent) as _,
                                   libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as isize
                }
            });
            if n < 0 {
                // Drop the datagram that failed, as the network would
                debug!("UDP: dropping datagram: {}", io::Error::from_raw_os_error(err));
                sent += 1;
                dropped += 1;
            } else {
                sent += n as usize;
            }
        }
        dropped
    }
}

/// Build a control message to send from @addr, on an IPv6 socket if @v6
///
/// Return: length of the control message in @buf
fn pktinfo(buf: &mut [u64; CTRL_U64S], addr: IpAddr, v6: bool) -> usize {
    // SAFETY: All-zero is a valid msghdr
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_control = buf.as_mut_ptr().cast();
    msg.msg_controllen = size_of::<[u64; CTRL_U64S]>() as _;

    // SAFETY: CMSG_SPACE() of either pktinfo structure fits in @buf, and we
    // write one control message of the matching size
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if v6 {
            let a = match addr {
                IpAddr::V4(a) => a.to_ipv6_mapped(),
                IpAddr::V6(a) => a,
            };
            let pi = libc::in6_pktinfo {
                ipi6_addr: libc::in6_addr { s6_addr: a.octets() },
                ipi6_ifindex: 0,
            };
            (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
            (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
            (*cmsg).cmsg_len = libc::CMSG_LEN(size_of_val(&pi) as u32) as _;
            ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast(), pi);
            libc::CMSG_SPACE(size_of_val(&pi) as u32) as usize
        } else {
            let IpAddr::V4(a) = addr else { return 0 };
            let pi = libc::in_pktinfo {
                ipi_ifindex: 0,
                ipi_spec_dst: libc::in_addr { s_addr: u32::from(a).to_be() },
                ipi_addr: libc::in_addr { s_addr: 0 },
            };
            (*cmsg).cmsg_level = libc::IPPROTO_IP;
            (*cmsg).cmsg_type = libc::IP_PKTINFO;
            (*cmsg).cmsg_len = libc::CMSG_LEN(size_of_val(&pi) as u32) as _;
            ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast(), pi);
            libc::CMSG_SPACE(size_of_val(&pi) as u32) as usize
        }
    }
}

/// Receiving socket for a forwarded port, and where datagrams go
pub struct Recv<'a> {
    /// Index of the socket, for flow keys and epoll references
    pub index: usize,
    pub fd: RawFd,
    pub port: u16,
    pub target: &'a Target,
    /// Receiving on the host, target in the namespace
    pub inbound: bool,
}

/// UDP flow table
pub struct Udp {
    flows: Vec<Option<Flow>>,
    free: Vec<usize>,
    map: HashMap<Key, usize>,
    nflows: usize,
    bufs: Option<Box<Bufs>>,
    next_sweep: Instant,
    last_err: Option<Instant>,
}

impl Udp {
    pub fn new() -> Self {
        Udp {
            flows: Vec::new(),
            free: Vec::new(),
            map: HashMap::new(),
            nflows: 0,
            bufs: None,
            next_sweep: Instant::now(),
            last_err: None,
        }
    }

    /// Index of the receiving socket for flow @id, if it exists
    pub fn listener(&self, id: usize) -> Option<usize> {
        self.flows.get(id)?.as_ref().map(|f| f.key.0)
    }

    /// Number of active flows, each using one descriptor
    pub fn nflows(&self) -> usize {
        self.nflows
    }

    /// Log a failure to create a flow, at most once per ERR_INTERVAL
    fn err_ratelimit(&mut self, now: Instant, msg: impl FnOnce() -> String) {
        if self.last_err.is_none_or(|t| now >= t + ERR_INTERVAL) {
            info!("{}", msg());
            self.last_err = Some(now);
        }
    }

    /// Handle datagrams from clients on receiving socket @r.  New flows can be
    /// created as long as @can_add() says there are descriptors left, with
    /// sockets from @new_sock(), for IPv6 if its argument is set
    pub fn recv_clients(&mut self, ep: &Epoll, r: &Recv, can_add: impl Fn(usize) -> bool,
                        mut new_sock: impl FnMut(bool) -> io::Result<OwnedFd>) {
        let mut bufs = self.bufs.take().unwrap_or_else(Bufs::new);
        let n = match bufs.recv(r.fd, true) {
            Ok(n) => n,
            Err(e) => {
                debug!("UDP: cannot receive from {}: {e}", side(r.inbound, 0));
                0
            }
        };
        let now = Instant::now();

        // Forward runs of datagrams for the same flow with one sendmmsg()
        let mut run: Vec<usize> = Vec::with_capacity(BATCH);
        let mut run_flow = None;
        for i in 0..n {
            let flow = self.classify(ep, &bufs, i, r, now, &can_add, &mut new_sock);
            if flow != run_flow || flow.is_none() {
                if let Some(id) = run_flow {
                    self.send_host(&mut bufs, id, &run);
                }
                run.clear();
                run_flow = flow;
            }
            if let Some(id) = flow {
                run.push(i);
                self.flows[id].as_mut().unwrap().active(0, now);
            }
        }
        if let Some(id) = run_flow {
            self.send_host(&mut bufs, id, &run);
        }
        self.bufs = Some(bufs);
    }

    fn send_host(&self, bufs: &mut Bufs, id: usize, idx: &[usize]) {
        let flow = self.flows[id].as_ref().unwrap();
        let dropped = bufs.send(flow.sock.as_raw_fd(), idx, None, None);
        if dropped > 0 {
            debug!("UDP flow {id}: dropped {dropped} datagram(s) to target");
        }
    }

    /// Find or create the flow for datagram @i received on socket @r
    #[allow(clippy::too_many_arguments)]
    fn classify(&mut self, ep: &Epoll, bufs: &Bufs, i: usize, r: &Recv, now: Instant,
                can_add: &impl Fn(usize) -> bool,
                new_sock: &mut impl FnMut(bool) -> io::Result<OwnedFd>) -> Option<usize> {
        bufs.payload(i).or_else(|| {
            debug!("UDP: dropping oversized datagram from {}", side(r.inbound, 0));
            None
        })?;
        let (name, namelen) = bufs.name(i);
        let client = sys::sockaddr_to_ip(&name).filter(|c| c.port() != 0)?;
        let Some(local) = bufs.dst(i) else {
            debug!("UDP: no destination address for datagram from {client}, dropping");
            return None;
        };

        let key = (r.index, local, client);
        if let Some(&id) = self.map.get(&key) {
            return Some(id);
        }

        if !can_add(self.nflows) {
            let n = self.nflows;
            self.err_ratelimit(now, || {
                format!("UDP: too many flows ({n}), dropping datagrams of new ones")
            });
            return None;
        }

        let target = r.target;
        let peers: Vec<SocketAddr> = match target {
            Target::Ip { addr: Some(a), port } => vec![SocketAddr::new(*a, *port)],
            Target::Ip { addr: None, port } => vec![SocketAddr::new(config::auto_addr(local), *port)],
            Target::Host { addrs, .. } => addrs.clone(),
            Target::Unix(_) => unreachable!("Unix domain socket target for UDP"),
        };
        let mut last = None;
        let sock = peers.iter().find_map(|peer| match connect(new_sock, peer) {
            Ok(s) => Some((s, peer)),
            Err(e) => {
                debug!("UDP: cannot connect to {peer}: {e}");
                last = Some(e);
                None
            }
        });
        let Some((sock, peer)) = sock else {
            let e = last.map_or_else(|| "no address".into(), |e| e.to_string());
            self.err_ratelimit(now, || format!("UDP from {client}: cannot connect to {target}: {e}"));
            return None;
        };

        let id = self.free.pop().unwrap_or_else(|| {
            self.flows.push(None);
            self.flows.len() - 1
        });
        if let Err(e) = ep.add(sock.as_raw_fd(), libc::EPOLLIN as u32, Ref::Flow(id)) {
            self.free.push(id);
            self.err_ratelimit(now, || format!("UDP: epoll_ctl(): {e}"));
            return None;
        }
        if crate::log::debug_enabled() {
            let local_sa = SocketAddr::new(local, r.port);
            let src = sys::local_addr(sock.as_raw_fd()).map_or("?".into(), |a| a.to_string());
            debug!("UDP flow {id}: {client} -> {local_sa} {}, {src} -> {peer} {}", side(r.inbound, 0),
                   side(r.inbound, 1));
        }

        if self.nflows == 0 {
            self.next_sweep = now + SWEEP_INTERVAL;
        }
        self.flows[id] = Some(Flow {
            sock,
            key,
            client: (name, namelen),
            ts: now,
            activity: [0, 0],
        });
        self.map.insert(key, id);
        self.nflows += 1;
        Some(id)
    }

    /// Handle replies on the target side socket of flow @id, and send them to
    /// the client from receiving socket @lfd
    pub fn recv_replies(&mut self, id: usize, lfd: RawFd, lfd_v6: bool) {
        let Some(flow) = self.flows.get_mut(id).and_then(Option::as_mut) else { return };
        let bufs = self.bufs.get_or_insert_with(Bufs::new);

        let n = match bufs.recv(flow.sock.as_raw_fd(), false) {
            Ok(n) => n,
            Err(e) => {
                // Typically ECONNREFUSED, from an ICMP error
                debug!("UDP flow {id}: {e}");
                return;
            }
        };
        let idx: Vec<usize> = (0..n).filter(|&i| bufs.payload(i).is_some()).collect();
        if idx.len() < n {
            debug!("UDP flow {id}: dropping oversized datagram(s) from target");
        }
        if idx.is_empty() {
            return;
        }

        flow.active(1, Instant::now());
        let dropped = bufs.send(lfd, &idx, Some(&flow.client), Some((flow.key.1, lfd_v6)));
        if dropped > 0 {
            debug!("UDP flow {id}: dropped {dropped} datagram(s) to client");
        }
    }

    /// Close flows that expired, at most once per SWEEP_INTERVAL
    pub fn expire(&mut self, ep: &Epoll) {
        let now = Instant::now();
        if self.nflows == 0 || now < self.next_sweep {
            return;
        }
        self.next_sweep = now + SWEEP_INTERVAL;

        for id in 0..self.flows.len() {
            let Some(flow) = &self.flows[id] else { continue };
            if now.duration_since(flow.ts) <= flow.timeout() {
                continue;
            }
            debug!("UDP flow {id}: expired");
            ep.delete(flow.sock.as_raw_fd());
            self.map.remove(&flow.key);
            self.flows[id] = None;
            self.free.push(id);
            self.nflows -= 1;
        }
    }

    /// Timeout until the next check for expired flows, if any, in milliseconds
    pub fn timeout(&self) -> Option<i32> {
        (self.nflows > 0).then(|| {
            let wait = self.next_sweep.saturating_duration_since(Instant::now());
            wait.as_micros().div_ceil(1000) as i32
        })
    }
}

/// Where clients (side 0) or targets (side 1) are, for inbound flows or not
fn side(inbound: bool, sidei: usize) -> &'static str {
    if inbound == (sidei == 0) { "on host" } else { "in namespace" }
}

/// Get a UDP socket from @new_sock, and connect it to @peer
fn connect(new_sock: &mut impl FnMut(bool) -> io::Result<OwnedFd>, peer: &SocketAddr)
           -> io::Result<OwnedFd> {
    let s = new_sock(peer.is_ipv6())?;
    let (sa, len) = sys::sockaddr_ip(peer);
    // SAFETY: sa is a valid socket address of length len
    cvt(unsafe { libc::connect(s.as_raw_fd(), (&sa as *const libc::sockaddr_storage).cast(), len) })?;
    Ok(s)
}
