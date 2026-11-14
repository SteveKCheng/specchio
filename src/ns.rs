// SPDX-License-Identifier: GPL-2.0-or-later

//! Sockets in the sandbox's network namespace, for forwarding from the host
//!
//! Inbound connections and flows need a socket in the sandbox's network
//! namespace each, created while the command runs.  A socket belongs to the
//! network namespace it was created in, whichever thread uses it later, so we
//! keep pools of sockets created there, as pasta does (tcp_sock_refill_ns()),
//! and refill them from a short-lived thread that enters the namespace, as
//! NS_CALL() does in pasta.  See notes/user-ns.md:
//!
//! - entering the network namespace needs CAP_SYS_ADMIN in our own user
//!   namespace, so we first join the sandbox's user namespace (the one that
//!   owns its network namespace, not the nested one the command might run
//!   in), which is only possible while we're single-threaded
//! - we can't come back to the host's network namespace once we've left it,
//!   so only the short-lived thread enters it
//! - we become non-dumpable first, so that the command, which can be root in
//!   that user namespace, can't ptrace() us or take our descriptors
//!
//! The same applies to network namespaces we attach to (--netns), where the
//! listening sockets for outbound forwarding are also created this way.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::thread;
use std::time::{Duration, Instant};

use crate::config::Proto;
use crate::log::debug;
use crate::sys::{self, cvt};

/// ioctl()s to get the user namespace owning a namespace, and the type of a
/// namespace, see ioctl_ns(2)
const NS_GET_USERNS: libc::c_ulong = 0xb701;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;

/// Sockets kept in each pool, and refill threshold
const POOL_SIZE: usize = 32;
const POOL_LOW: usize = POOL_SIZE / 2;
/// Kinds of sockets: TCP and UDP, IPv4 and IPv6, see kind()
const KINDS: usize = 4;
/// Descriptors held by the pools at most
pub const MAX_FDS: usize = POOL_SIZE * KINDS;
/// Wait between attempts to refill pools after a failure
const REFILL_BACKOFF: Duration = Duration::from_secs(1);
/// Stack size for the thread creating sockets: it does very little
const THREAD_STACK: usize = 256 * 1024;

fn kind(proto: Proto, v6: bool) -> usize {
    usize::from(proto == Proto::Udp) * 2 + usize::from(v6)
}

/// Join the user namespace owning network namespace @netns, so that threads
/// can enter @netns later, unless it's ours already.  Must be called while
/// single-threaded
///
/// Return: error with a description of the step that failed
pub fn join(netns: &OwnedFd) -> Result<(), String> {
    // SAFETY: NS_GET_NSTYPE takes no argument
    match unsafe { libc::ioctl(netns.as_raw_fd(), NS_GET_NSTYPE) } {
        t if t == libc::CLONE_NEWNET => {}
        -1 if crate::sys::errno() != libc::ENOTTY => {
            return Err(format!("cannot get namespace type: {}", io::Error::last_os_error()));
        }
        _ => return Err("not a network namespace".into()),
    }

    // Before joining: we'd be exposed to its processes in the meantime
    // SAFETY: prctl() with integer arguments
    cvt(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) })
        .map_err(|e| format!("cannot make process non-dumpable: {e}"))?;

    // SAFETY: NS_GET_USERNS takes no argument, and returns a new descriptor
    let userns = cvt(unsafe { libc::ioctl(netns.as_raw_fd(), NS_GET_USERNS) }).map_err(|e| {
        // EPERM: owned by an ancestor of our user namespace, or an unrelated one
        format!("cannot get user namespace owning the network namespace: {e}")
    })?;
    // SAFETY: userns was just returned by ioctl() and is owned by nobody else
    let userns = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(userns) });

    // Joining the user namespace we're in fails with EINVAL, and isn't needed
    let ours = std::fs::metadata("/proc/self/ns/user")
        .map_err(|e| format!("cannot read /proc/self/ns/user: {e}"))?;
    let theirs = userns.metadata().map_err(|e| format!("cannot stat user namespace: {e}"))?;
    if (ours.dev(), ours.ino()) == (theirs.dev(), theirs.ino()) {
        debug!("network namespace owned by our user namespace, not joining");
        return Ok(());
    }

    // SAFETY: setns() has no memory safety preconditions
    cvt(unsafe { libc::setns(userns.as_raw_fd(), libc::CLONE_NEWUSER) })
        .map(drop)
        .map_err(|e| format!("cannot join user namespace owning the network namespace: {e}"))
}

/// Run @f in a short-lived thread in network namespace @netns, which join()
/// has made enterable, and return its result
pub fn call<T: Send>(netns: BorrowedFd, f: impl FnOnce() -> T + Send) -> io::Result<T> {
    thread::scope(|s| {
        thread::Builder::new()
            .name("specchio-ns".into())
            .stack_size(THREAD_STACK)
            .spawn_scoped(s, || {
                // SAFETY: setns() has no memory safety preconditions, and only
                // affects this thread, which is about to exit
                cvt(unsafe { libc::setns(netns.as_raw_fd(), libc::CLONE_NEWNET) })?;
                Ok(f())
            })?
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("thread panicked")))
    })
}

/// Pools of sockets created in the sandbox's network namespace
pub struct NsSockets {
    netns: OwnedFd,
    /// Sockets of each kind, see kind()
    pools: [Vec<OwnedFd>; KINDS],
    /// Kinds of sockets we were asked for, and keep pools of
    wanted: [bool; KINDS],
    /// Don't try to refill pools before this, after a failure
    backoff: Option<Instant>,
}

impl NsSockets {
    /// Pools for network namespace @netns, which join() has made enterable
    pub fn new(netns: OwnedFd) -> Self {
        NsSockets { netns, pools: Default::default(), wanted: [false; KINDS], backoff: None }
    }

    /// Take a non-blocking socket for @proto, IPv6 if @v6, from its pool,
    /// filling the pool first if it's empty
    pub fn take(&mut self, proto: Proto, v6: bool) -> io::Result<OwnedFd> {
        let k = kind(proto, v6);
        if self.pools[k].is_empty() {
            let err = self.fill(&[k]).into_iter().next().flatten();
            if self.pools[k].is_empty() {
                return Err(err.unwrap_or_else(|| io::Error::other("no socket created")));
            }
        }
        self.wanted[k] = true;
        Ok(self.pools[k].pop().expect("pool not empty"))
    }

    /// Refill pools in use that are running low, between batches of events
    pub fn refill(&mut self) {
        if self.backoff.is_some_and(|t| Instant::now() < t) {
            return;
        }
        let low: Vec<usize> = (0..KINDS)
            .filter(|&k| self.wanted[k] && self.pools[k].len() < POOL_LOW)
            .collect();
        if low.is_empty() {
            return;
        }
        let errs = self.fill(&low);
        if let Some(e) = errs.into_iter().flatten().next() {
            debug!("cannot refill socket pools for namespace: {e}");
            self.backoff = Some(Instant::now() + REFILL_BACKOFF);
        } else {
            self.backoff = None;
        }
    }

    /// Fill pools of @kinds, from a thread in the sandbox's network namespace
    ///
    /// Return: error for each of @kinds, if its pool couldn't be filled
    fn fill(&mut self, kinds: &[usize]) -> Vec<Option<io::Error>> {
        let need: Vec<(usize, usize)> = kinds.iter()
            .map(|&k| (k, POOL_SIZE - self.pools[k].len()))
            .collect();
        let made = match call(self.netns.as_fd(), || create(&need)) {
            Ok(made) => made,
            Err(e) => {
                let msg = e.to_string();
                return kinds.iter().map(|_| Some(io::Error::other(msg.clone()))).collect();
            }
        };
        let mut errs = Vec::new();
        for ((k, _), (socks, err)) in need.iter().zip(made) {
            self.pools[*k].extend(socks);
            errs.push(err);
        }
        errs
    }
}

/// Create @need (kind, number) sockets, in the thread run by call()
///
/// Return: sockets for each kind, with the error that stopped us if any
fn create(need: &[(usize, usize)]) -> Vec<(Vec<OwnedFd>, Option<io::Error>)> {
    need.iter().map(|&(k, n)| {
        let af = if k & 1 != 0 { libc::AF_INET6 } else { libc::AF_INET };
        let ty = if k & 2 != 0 { libc::SOCK_DGRAM } else { libc::SOCK_STREAM };
        let mut socks = Vec::with_capacity(n);
        for _ in 0..n {
            match sys::socket(af, ty | libc::SOCK_NONBLOCK) {
                Ok(s) => socks.push(s),
                Err(e) => return (socks, Some(e)),
            }
        }
        (socks, None)
    }).collect()
}
