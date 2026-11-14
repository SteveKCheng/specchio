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

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::Proto;
use crate::log::debug;
use crate::sys::{self, cvt};

/// ioctl() to get the user namespace owning a namespace, see ioctl_ns(2)
const NS_GET_USERNS: libc::c_ulong = 0xb701;

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
/// can enter @netns later.  Must be called while single-threaded
pub fn join(netns: &OwnedFd) -> io::Result<()> {
    // Before joining: we'd be exposed to the command in the meantime
    // SAFETY: prctl() with integer arguments
    cvt(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) })?;

    // SAFETY: NS_GET_USERNS takes no argument, and returns a new descriptor
    let userns = cvt(unsafe { libc::ioctl(netns.as_raw_fd(), NS_GET_USERNS) })?;
    // SAFETY: userns was just returned by ioctl() and is owned by nobody else
    let userns = unsafe { OwnedFd::from_raw_fd(userns) };

    // SAFETY: setns() has no memory safety preconditions
    cvt(unsafe { libc::setns(userns.as_raw_fd(), libc::CLONE_NEWUSER) }).map(drop)
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
        let netns = self.netns.as_fd();

        let made = thread::scope(|s| {
            thread::Builder::new()
                .name("specchio-ns".into())
                .stack_size(THREAD_STACK)
                .spawn_scoped(s, || create(netns, &need))
                .map(|t| t.join().unwrap_or_else(|_| Err(io::Error::other("thread panicked"))))
        });

        let made = match made.and_then(|r| r) {
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

/// Body of the thread creating sockets: enter the network namespace
/// @netns, create @need (kind, number) sockets
///
/// Return: sockets for each kind, with the error that stopped us if any
fn create(netns: BorrowedFd, need: &[(usize, usize)])
          -> io::Result<Vec<(Vec<OwnedFd>, Option<io::Error>)>> {
    // SAFETY: setns() has no memory safety preconditions, and only affects
    // this thread, which is about to exit
    cvt(unsafe { libc::setns(netns.as_raw_fd(), libc::CLONE_NEWNET) })?;

    Ok(need.iter().map(|&(k, n)| {
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
    }).collect())
}
