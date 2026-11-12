// SPDX-License-Identifier: GPL-2.0-or-later

//! Spliced connections between a TCP socket and a Unix domain socket
//!
//! Ported from tcp_splice.c in passt:
//!   Copyright (c) 2020-2022 Red Hat GmbH
//!   Author: Stefano Brivio <sbrivio@redhat.com>
//!
//! # Theory of Operation
//!
//! Data is moved between the two sockets of a connection using a pair of
//! splice() syscalls per direction, through an intermediate pipe, without
//! copying it to userspace.  Side 0 is the accepted socket, side 1 is the
//! socket we connect to the target.  Connections are tracked using these
//! events:
//!
//! - SPLICE_CONNECT:       connection accepted, connecting to target
//! - SPLICE_ESTABLISHED:   connection to target established
//! - OUT_WAIT_0:           pipe to accepted socket full, wait for EPOLLOUT
//! - OUT_WAIT_1:           pipe to target socket full, wait for EPOLLOUT
//! - FIN_RCVD_0:           FIN (EPOLLRDHUP) seen from accepted socket
//! - FIN_RCVD_1:           FIN (EPOLLRDHUP) seen from target socket
//! - FIN_SENT_0:           FIN (write shutdown) sent to accepted socket
//! - FIN_SENT_1:           FIN (write shutdown) sent to target socket
//!
//! Unlike tcp_splice.c, EPOLLHUP isn't treated as an error.  A socket reports
//! it once it's shut down in both directions (always the case for a Unix
//! domain socket whose peer closed), even if unread data is still queued on
//! it, and while data from it might still wait in the pipe.  As EPOLLHUP can't
//! be masked, we stop polling that socket instead, and keep draining it when
//! the other side becomes writable (EPOLLOUT), until we read EOF from it.

use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::ptr;

use crate::config::UnixTarget;
use crate::epoll::{Epoll, Ref};
use crate::log::debug;
use crate::sys::{self, cvt, retry_eintr};

const MAX_PIPE_SIZE: usize = 8 * 1024 * 1024;
const PIPE_POOL_SIZE: usize = 32;

const SPLICE_CLOSED: u8 = 0;
const SPLICE_CONNECT: u8 = 1 << 0;
const SPLICE_ESTABLISHED: u8 = 1 << 1;
const fn out_wait(sidei: usize) -> u8 { if sidei != 0 { 1 << 3 } else { 1 << 2 } }
const fn fin_rcvd(sidei: usize) -> u8 { if sidei != 0 { 1 << 5 } else { 1 << 4 } }
const fn fin_sent(sidei: usize) -> u8 { if sidei != 0 { 1 << 7 } else { 1 << 6 } }

/// Display strings for connection events
const EVENT_STR: [&str; 8] = [
    "SPLICE_CONNECT", "SPLICE_ESTABLISHED", "OUT_WAIT_0", "OUT_WAIT_1",
    "FIN_RCVD_0", "FIN_RCVD_1", "FIN_SENT_0", "FIN_SENT_1",
];

const SIDE_STR: [&str; 2] = ["namespace", "host"];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SockKind {
    Tcp,
    Unix,
}

pub struct Pipe {
    r: OwnedFd,
    w: OwnedFd,
}

/// Pool of pre-opened pipes, and usable pipe size
pub struct PipePool {
    pipes: Vec<Pipe>,
    size: usize,
}

impl PipePool {
    pub fn new() -> Self {
        let mut pool = PipePool { pipes: Vec::new(), size: probe_pipe_size() };
        debug!("using pipe size {}", pool.size);
        pool.refill();
        pool
    }

    pub fn size(&self) -> usize {
        self.size
    }

    fn open(&self) -> io::Result<Pipe> {
        let (r, w) = sys::pipe2_nonblock()?;
        if !matches!(sys::set_pipe_size(r.as_fd(), self.size), Ok(s) if s == self.size) {
            debug!("cannot set pipe size to {}", self.size);
        }
        Ok(Pipe { r, w })
    }

    fn take(&mut self) -> io::Result<Pipe> {
        match self.pipes.pop() {
            Some(p) => Ok(p),
            None => self.open(),
        }
    }

    /// Refill pool of pre-opened pipes
    pub fn refill(&mut self) {
        while self.pipes.len() < PIPE_POOL_SIZE {
            match self.open() {
                Ok(p) => self.pipes.push(p),
                Err(_) => break,
            }
        }
    }
}

/// Find usable pipe size, probing downwards from MAX_PIPE_SIZE
fn probe_pipe_size() -> usize {
    let mut size = MAX_PIPE_SIZE;

    while size > 0 {
        let mut ok = 0;
        let mut probe = Vec::with_capacity(PIPE_POOL_SIZE);
        for _ in 0..PIPE_POOL_SIZE {
            let Ok(p) = sys::pipe2_nonblock() else { break };
            let set = sys::set_pipe_size(p.0.as_fd(), size).is_ok();
            probe.push(p);
            if !set {
                break;
            }
            ok += 1;
        }
        if ok == PIPE_POOL_SIZE {
            return size;
        }
        size /= 2;
    }

    MAX_PIPE_SIZE
}

/// A spliced connection
pub struct Conn {
    /// Index in the connection table, used for epoll references and logging
    id: usize,
    s: [Option<OwnedFd>; 2],
    kind: [SockKind; 2],
    /// Pipe for data from side i to side !i
    pipe: [Option<Pipe>; 2],
    /// Bytes currently in each pipe
    pending: [usize; 2],
    events: u8,
    /// Socket on side i reported EPOLLHUP and was removed from epoll
    hup: [bool; 2],
    closing: bool,
}

/// Epoll event mask for given connection events, on side @sidei
fn conn_epoll_events(events: u8, sidei: usize) -> u32 {
    let mut e = 0;

    if events & SPLICE_ESTABLISHED != 0 {
        if events & fin_sent(1 - sidei) == 0 {
            e = (libc::EPOLLIN | libc::EPOLLRDHUP) as u32;
        }
    } else if sidei == 1 && events & SPLICE_CONNECT != 0 {
        e = libc::EPOLLOUT as u32;
    }

    if events & out_wait(sidei) != 0 {
        e |= libc::EPOLLOUT as u32;
    }
    if events & out_wait(1 - sidei) != 0 {
        e &= !(libc::EPOLLIN as u32);
    }

    e
}

impl Conn {
    /// New connection from accepted (TCP) socket @s0
    pub fn new(id: usize, s0: OwnedFd) -> Self {
        if sys::setsockopt_int(s0.as_raw_fd(), libc::SOL_TCP, libc::TCP_QUICKACK, 1).is_err() {
            debug!("conn {id}: failed to set TCP_QUICKACK");
        }
        Conn {
            id,
            s: [Some(s0), None],
            kind: [SockKind::Tcp, SockKind::Unix],
            pipe: [None, None],
            pending: [0; 2],
            events: SPLICE_CLOSED,
            hup: [false; 2],
            closing: false,
        }
    }

    pub fn is_closing(&self) -> bool {
        self.closing
    }

    fn fd(&self, sidei: usize) -> RawFd {
        self.s[sidei].as_ref().map_or(-1, |s| s.as_raw_fd())
    }

    /// Update epoll state from connection events
    fn epoll_ctl(&self, ep: &Epoll) -> io::Result<()> {
        for sidei in (0..2).filter(|&i| !self.hup[i]) {
            let ev = conn_epoll_events(self.events, sidei);
            ep.modify(self.fd(sidei), ev, Ref::Conn(self.id, sidei))?;
        }
        Ok(())
    }

    fn event_log(&self, prefix: &str, ev: u8) {
        if crate::log::debug_enabled() {
            let i = ev.trailing_zeros() as usize;
            debug!("conn {}: {prefix}{}", self.id, EVENT_STR[i]);
        }
    }

    /// Set connection event @ev, update epoll state
    fn set_event(&mut self, ep: &Epoll, ev: u8) {
        if self.events & ev != 0 {
            return;
        }
        self.events |= ev;
        self.event_log("", ev);
        if let Err(e) = self.epoll_ctl(ep) {
            debug!("conn {}: epoll_ctl(): {e}", self.id);
            self.set_closing(ep);
        }
    }

    /// Clear connection event @ev, update epoll state
    fn clear_event(&mut self, ep: &Epoll, ev: u8) {
        if self.events & ev == 0 {
            return;
        }
        self.events &= !ev;
        self.event_log("~", ev);
        if let Err(e) = self.epoll_ctl(ep) {
            debug!("conn {}: epoll_ctl(): {e}", self.id);
            self.set_closing(ep);
        }
    }

    /// Mark connection as closing, stop epoll notifications
    ///
    /// Descriptors are closed when the connection is dropped, which the caller
    /// defers until the end of the current batch of epoll events.
    fn set_closing(&mut self, ep: &Epoll) {
        if self.closing {
            return;
        }
        self.closing = true;
        debug!("conn {}: CLOSING", self.id);
        for sidei in 0..2 {
            if let Some(s) = &self.s[sidei] {
                ep.delete(s.as_raw_fd());
            }
        }
    }

    /// Close connection forcing RST on TCP sides
    pub fn rst(&mut self, ep: &Epoll) {
        if self.closing {
            return;
        }
        for sidei in 0..2 {
            if self.kind[sidei] == SockKind::Tcp
                && let Some(s) = &self.s[sidei]
                && sys::linger0(s.as_raw_fd()).is_err()
            {
                debug!("conn {}: SO_LINGER failed, may not send RST to peer", self.id);
            }
        }
        self.set_closing(ep);
    }

    /// Completion of connect(), or call on immediate success
    fn connect_finish(&mut self, ep: &Epoll, pool: &mut PipePool) -> io::Result<()> {
        for sidei in 0..2 {
            if self.pipe[sidei].is_none() {
                self.pipe[sidei] = Some(pool.take().inspect_err(|e| {
                    debug!("conn {}: cannot create {sidei}->{} pipe: {e}", self.id, 1 - sidei);
                })?);
            }
        }

        self.set_event(ep, SPLICE_ESTABLISHED);
        Ok(())
    }

    /// Create and connect socket to @target
    ///
    /// On error, the caller should reset the connection with rst()
    ///
    /// Return: Ok(false) if the caller should call this again later, because
    ///         the listen backlog of @target is full
    pub fn connect(&mut self, ep: &Epoll, pool: &mut PipePool,
                   target: &UnixTarget) -> io::Result<bool> {
        let (sun, len) = target.sockaddr().map_err(io::Error::other)?;
        if self.s[1].is_none() {
            self.s[1] = Some(sys::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK)?);

            if sys::setsockopt_int(self.fd(0), libc::SOL_TCP, libc::TCP_NODELAY, 1).is_err() {
                debug!("conn {}: failed to set TCP_NODELAY", self.id);
            }
        }
        let raw1 = self.fd(1);

        // SAFETY: sun is a valid socket address of length len
        let rc = unsafe { libc::connect(raw1, (&sun as *const libc::sockaddr_un).cast(), len) };
        let err = if rc < 0 { sys::errno() } else { 0 };

        // A non-blocking connect() to a Unix domain socket with a full backlog
        // fails with EAGAIN, and there's no way to get notified when there's
        // room again: an unconnected socket reports EPOLLOUT | EPOLLHUP right
        // away.  Keep both sockets out of epoll, and let the caller retry.
        if err == libc::EAGAIN {
            return Ok(false);
        }
        if err != 0 && err != libc::EINPROGRESS {
            return Err(io::Error::from_raw_os_error(err));
        }

        ep.add(self.fd(0), 0, Ref::Conn(self.id, 0))?;
        ep.add(raw1, 0, Ref::Conn(self.id, 1))?;

        self.set_event(ep, SPLICE_CONNECT);

        if err == 0 {
            self.connect_finish(ep, pool)?;
        }
        Ok(true)
    }

    /// Forward data in one direction using splice()
    ///
    /// Return: Err(()) if the connection should be reset
    fn forward(&mut self, ep: &Epoll, pipe_size: usize, from: usize) -> Result<(), ()> {
        let to = 1 - from;
        let (src, dst) = (self.fd(from), self.fd(to));
        let Some(pipe) = &self.pipe[from] else { return Ok(()) };
        let (pr, pw) = (pipe.r.as_raw_fd(), pipe.w.as_raw_fd());
        let mut corked = false;

        loop {
            let mut more = 0;

            // SAFETY: splice() with NULL offsets between valid descriptors
            let (readlen, rerr) = retry_eintr(|| unsafe {
                libc::splice(src, ptr::null_mut(), pw, ptr::null_mut(), pipe_size,
                             libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK)
            });

            if readlen < 0 && rerr != libc::EAGAIN {
                debug!("conn {}: splicing from {} socket: {}", self.id, SIDE_STR[from],
                       io::Error::from_raw_os_error(rerr));
                return Err(());
            }

            if readlen <= 0 {
                if readlen == 0 {
                    // EOF
                    self.set_event(ep, fin_rcvd(from));
                }

                // We're either blocked or at EOF on the read side, and there's
                // nothing in the pipe so there's nothing to do write side
                // either.
                if self.pending[from] == 0 {
                    // Setting TCP_NODELAY again flushes data held back by
                    // SPLICE_F_MORE
                    if corked && self.kind[to] == SockKind::Tcp
                        && sys::setsockopt_int(dst, libc::SOL_TCP, libc::TCP_NODELAY, 1).is_err()
                    {
                        debug!("conn {}: failed to push data", self.id);
                    }
                    break;
                }
            } else {
                self.pending[from] += readlen as usize;

                if readlen as usize >= pipe_size * 90 / 100 {
                    more = libc::SPLICE_F_MORE;
                }
            }

            // SAFETY: splice() with NULL offsets between valid descriptors
            let (written, werr) = retry_eintr(|| unsafe {
                libc::splice(pr, ptr::null_mut(), dst, ptr::null_mut(), pipe_size,
                             libc::SPLICE_F_MOVE | more | libc::SPLICE_F_NONBLOCK)
            });

            if written < 0 && werr != libc::EAGAIN {
                debug!("conn {}: splicing to {} socket: {}", self.id, SIDE_STR[to],
                       io::Error::from_raw_os_error(werr));
                return Err(());
            }

            if written < 0 {
                break;
            }

            if written > 0 {
                corked = more != 0;
            }

            self.pending[from] -= written as usize;

            if self.pending[from] == 0 && readlen == 0 {
                // Read side is EOF, and we emptied the pipe.  No more we can
                // do for now.
                break;
            }

            // On EAGAIN from the read side with data in the pipe, the pipe
            // might have been full, not the socket empty: tcp_splice.c stops
            // here and relies on EPOLLIN firing again, but we might not be
            // polling for it (see EPOLLHUP above), so try reading again.
            // With an empty pipe, EAGAIN from the read side ends the loop.
        }

        // We need write-side wakeups if and only if we have data in the pipe
        // to drain.  We can't get them once the target side hung up.
        if self.pending[from] != 0 && self.hup[to] {
            debug!("conn {}: {} socket hung up with data pending", self.id, SIDE_STR[to]);
            return Err(());
        }
        if self.pending[from] != 0 {
            self.set_event(ep, out_wait(to));
        } else {
            self.clear_event(ep, out_wait(to));
        }

        if self.events & fin_rcvd(from) != 0 && self.events & fin_sent(to) == 0
            && self.pending[from] == 0
        {
            // SAFETY: shutdown() has no memory safety preconditions
            if let Err(e) = cvt(unsafe { libc::shutdown(dst, libc::SHUT_WR) }) {
                debug!("conn {}: shutdown() on {} socket: {e}", self.id, SIDE_STR[to]);
                return Err(());
            }
            self.set_event(ep, fin_sent(to));
        }

        Ok(())
    }

    /// Handle epoll @events on socket of side @sidei
    pub fn handle(&mut self, ep: &Epoll, pool: &mut PipePool, sidei: usize, events: u32) {
        if self.closing || self.events == SPLICE_CLOSED {
            return;
        }

        if events & libc::EPOLLERR as u32 != 0 {
            match sys::so_error(self.fd(sidei)) {
                Ok(err) => debug!("conn {}: error event on {} socket: {}", self.id,
                                  SIDE_STR[sidei], io::Error::from_raw_os_error(err)),
                Err(e) => debug!("conn {}: error retrieving SO_ERROR: {e}", self.id),
            }
            return self.rst(ep);
        }

        if self.events == SPLICE_CONNECT {
            if events & libc::EPOLLOUT as u32 == 0 {
                debug!("conn {}: unexpected events {events:#x} during connect", self.id);
                return self.rst(ep);
            }
            if self.connect_finish(ep, pool).is_err() {
                return self.rst(ep);
            }
        }

        let pipe_size = pool.size();

        if events & libc::EPOLLOUT as u32 != 0 && self.forward(ep, pipe_size, 1 - sidei).is_err() {
            return self.rst(ep);
        }

        if events & (libc::EPOLLIN | libc::EPOLLRDHUP) as u32 != 0
            && self.forward(ep, pipe_size, sidei).is_err()
        {
            return self.rst(ep);
        }

        if self.events & (fin_sent(0) | fin_sent(1)) == fin_sent(0) | fin_sent(1) {
            // Clean close, no reset
            return self.set_closing(ep);
        }

        if events & libc::EPOLLHUP as u32 != 0 && !self.hup[sidei] {
            if self.events & out_wait(sidei) != 0 {
                debug!("conn {}: hangup from {} socket with data pending", self.id,
                       SIDE_STR[sidei]);
                return self.rst(ep);
            }

            // Anything left to read from it is drained on EPOLLOUT from the
            // other side, see Theory of Operation
            debug!("conn {}: hangup from {} socket", self.id, SIDE_STR[sidei]);
            self.hup[sidei] = true;
            ep.delete(self.fd(sidei));
        }
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        debug!("conn {}: CLOSED", self.id);
    }
}
