// SPDX-License-Identifier: GPL-2.0-or-later

//! epoll wrapper and encoding of epoll references

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::sys::cvt;

/// What an epoll event refers to, stored in `epoll_event.u64`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ref {
    /// pidfd of the sandboxed child process
    Child,
    /// Listening (TCP) or receiving (UDP) socket in the namespace, by index
    Listener(usize),
    /// Socket of a spliced connection, by connection index and side
    Conn(usize, usize),
    /// Socket of a UDP flow, on the target side, by flow index
    Flow(usize),
    /// signalfd for signals to forward
    Signal,
}

const TAG_SHIFT: u32 = 56;
const TAG_CHILD: u64 = 1;
const TAG_LISTENER: u64 = 2;
const TAG_CONN: u64 = 3;
const TAG_FLOW: u64 = 4;
const TAG_SIGNAL: u64 = 5;

impl Ref {
    fn encode(self) -> u64 {
        match self {
            Ref::Child => TAG_CHILD << TAG_SHIFT,
            Ref::Listener(i) => TAG_LISTENER << TAG_SHIFT | i as u64,
            Ref::Conn(i, sidei) => TAG_CONN << TAG_SHIFT | (i as u64) << 1 | sidei as u64,
            Ref::Flow(i) => TAG_FLOW << TAG_SHIFT | i as u64,
            Ref::Signal => TAG_SIGNAL << TAG_SHIFT,
        }
    }

    fn decode(v: u64) -> Self {
        let payload = v & ((1 << TAG_SHIFT) - 1);
        match v >> TAG_SHIFT {
            TAG_CHILD => Ref::Child,
            TAG_LISTENER => Ref::Listener(payload as usize),
            TAG_CONN => Ref::Conn((payload >> 1) as usize, (payload & 1) as usize),
            TAG_FLOW => Ref::Flow(payload as usize),
            TAG_SIGNAL => Ref::Signal,
            _ => unreachable!("bad epoll reference {v:#x}"),
        }
    }
}

pub struct Epoll(OwnedFd);

impl Epoll {
    pub fn new() -> io::Result<Self> {
        // SAFETY: epoll_create1() has no memory safety preconditions
        let fd = cvt(unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) })?;
        // SAFETY: fd is a freshly created descriptor that nobody else owns
        Ok(Epoll(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    fn ctl(&self, op: i32, fd: RawFd, events: u32, r: Ref) -> io::Result<()> {
        let mut ev = libc::epoll_event {
            events,
            u64: r.encode(),
        };
        // SAFETY: Passing a pointer to a valid epoll_event
        cvt(unsafe { libc::epoll_ctl(self.0.as_raw_fd(), op, fd, &mut ev) }).map(drop)
    }

    pub fn add(&self, fd: RawFd, events: u32, r: Ref) -> io::Result<()> {
        self.ctl(libc::EPOLL_CTL_ADD, fd, events, r)
    }

    pub fn modify(&self, fd: RawFd, events: u32, r: Ref) -> io::Result<()> {
        self.ctl(libc::EPOLL_CTL_MOD, fd, events, r)
    }

    /// Remove @fd from the epoll set, ignoring errors (it might not be in it)
    pub fn delete(&self, fd: RawFd) {
        // SAFETY: A NULL event is allowed for EPOLL_CTL_DEL
        unsafe { libc::epoll_ctl(self.0.as_raw_fd(), libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) };
    }

    /// Wait for events, return (reference, event mask) pairs in @out
    pub fn wait(&self, buf: &mut [libc::epoll_event], timeout_ms: i32,
                out: &mut Vec<(Ref, u32)>) -> io::Result<()> {
        out.clear();
        // SAFETY: buf is a valid array of epoll_event of the given length
        let n = unsafe {
            libc::epoll_wait(self.0.as_raw_fd(), buf.as_mut_ptr(), buf.len() as i32, timeout_ms)
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted { Ok(()) } else { Err(e) };
        }
        for ev in &buf[..n as usize] {
            // Copy out of the (possibly packed) struct before use
            let (data, events) = (ev.u64, ev.events);
            out.push((Ref::decode(data), events));
        }
        Ok(())
    }
}
