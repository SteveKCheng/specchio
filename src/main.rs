// SPDX-License-Identifier: GPL-2.0-or-later

//! specchio - splice TCP connections out of a loopback-only sandbox
//!
//! A narrow-scoped mirror of pasta (from passt): run a command in new user and
//! network namespaces where only the loopback interface exists, and forward
//! selected TCP ports in there to TCP ports or Unix domain sockets on the
//! host, moving data with splice() only, and selected UDP ports to UDP ports
//! on the host.

mod config;
mod epoll;
mod fdpass;
mod log;
mod sandbox;
mod splice;
mod sys;
mod udp;

use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use config::{Config, Proto, Target};
use epoll::{Epoll, Ref};
use log::{debug, info};
use sandbox::{Listener, Sandbox};
use splice::{Conn, Peer, PipePool};
use udp::Udp;

/// Descriptors reserved for things other than connections and flows
const RESERVED_FDS: usize = 64;
/// Descriptors used per TCP connection: two sockets, two pipes
const FDS_PER_CONN: usize = 6;
/// Descriptors used per UDP flow: one socket
const FDS_PER_FLOW: usize = 1;
/// Maximum epoll events handled per batch
const EPOLL_EVENTS: usize = 128;
/// Retry interval for accepting connections while paused
const PAUSE_RETRY_MS: i32 = 1000;
/// Initial and maximum delay between connect() retries if backlog is full
const CONNECT_RETRY_MIN: Duration = Duration::from_millis(1);
const CONNECT_RETRY_MAX: Duration = Duration::from_millis(100);
/// Give up connecting to a target with a full backlog after this long
const CONNECT_RETRY_TIMEOUT: Duration = Duration::from_secs(5);

/// Pending connect() retry, see Conn::connect()
#[derive(Clone, Copy)]
struct Retry {
    id: usize,
    /// Index of the listener, for its target
    fwd: usize,
    peer: Peer,
    next: Instant,
    delay: Duration,
    deadline: Instant,
}

/// Forwarding state, driven by the main loop
struct Forwarder {
    ep: Epoll,
    pool: PipePool,
    listeners: Vec<Listener>,
    /// Target for each listener
    targets: Vec<Target>,
    /// Connection table, indexed by connection id
    conns: Vec<Option<Conn>>,
    /// Free entries in @conns
    free: Vec<usize>,
    /// Connections to drop at the end of the current batch of events
    defer: Vec<usize>,
    /// Connections waiting to retry connect()
    retries: Vec<Retry>,
    nconns: usize,
    udp: Udp,
    /// Descriptors available for connections and flows
    fd_budget: usize,
    /// TCP listening sockets were removed from epoll, see pause()
    paused: bool,
}

/// Whether @fds more descriptors fit in @budget, with TCP connections and
/// UDP flows using @nconns and @nflows: at least one of either is allowed
fn fds_left(budget: usize, nconns: usize, nflows: usize, fds: usize) -> bool {
    let used = nconns * FDS_PER_CONN + nflows * FDS_PER_FLOW;
    used == 0 || used + fds <= budget
}

impl Forwarder {
    fn tcp_listeners(&self) -> impl Iterator<Item = (usize, &Listener)> {
        self.listeners.iter().enumerate().filter(|(_, l)| l.proto == Proto::Tcp)
    }

    fn conn_fits(&self) -> bool {
        fds_left(self.fd_budget, self.nconns, self.udp.nflows(), FDS_PER_CONN)
    }

    /// Stop accepting connections until resources are available again
    fn pause(&mut self) {
        if self.paused {
            return;
        }
        debug!("pausing new connections ({} active, {} UDP flows)", self.nconns,
               self.udp.nflows());
        for (i, l) in self.tcp_listeners() {
            let _ = self.ep.modify(l.fd.as_raw_fd(), 0, Ref::Listener(i));
        }
        self.paused = true;
    }

    fn resume(&mut self) {
        if !self.paused || !self.conn_fits() {
            return;
        }
        debug!("resuming new connections");
        for (i, l) in self.tcp_listeners() {
            let _ = self.ep.modify(l.fd.as_raw_fd(), libc::EPOLLIN as u32, Ref::Listener(i));
        }
        self.paused = false;
    }

    /// Handle an event on listener @li
    fn listener_event(&mut self, li: usize) {
        let l = &self.listeners[li];
        match l.proto {
            Proto::Tcp => self.accept(li),
            Proto::Udp => {
                let (budget, nconns) = (self.fd_budget, self.nconns);
                self.udp.recv_ns(&self.ep, li, l.fd.as_raw_fd(), l.addr.port(), &self.targets[li],
                                 |nflows| fds_left(budget, nconns, nflows, FDS_PER_FLOW));
            }
        }
    }

    /// Handle replies for UDP flow @id
    fn flow_event(&mut self, id: usize) {
        let Some(li) = self.udp.listener(id) else { return };
        let l = &self.listeners[li];
        self.udp.recv_host(id, l.fd.as_raw_fd(), l.addr.is_ipv6());
    }

    /// Accept all pending connections on listener @li
    fn accept(&mut self, li: usize) {
        loop {
            if !self.conn_fits() {
                return self.pause();
            }

            let lfd = self.listeners[li].fd.as_raw_fd();
            // SAFETY: NULL address pointers are allowed for accept4()
            let s = unsafe {
                libc::accept4(lfd, std::ptr::null_mut(), std::ptr::null_mut(),
                              libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC)
            };
            if s < 0 {
                match sys::errno() {
                    libc::EAGAIN => return,
                    libc::EINTR | libc::ECONNABORTED => continue,
                    libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM => {
                        info!("cannot accept connection: {}", std::io::Error::last_os_error());
                        return self.pause();
                    }
                    _ => {
                        info!("cannot accept connection: {}", std::io::Error::last_os_error());
                        return;
                    }
                }
            }
            // SAFETY: s was just returned by accept4() and is owned by nobody else
            let s = unsafe { std::os::fd::FromRawFd::from_raw_fd(s) };

            let id = self.free.pop().unwrap_or_else(|| {
                self.conns.push(None);
                self.conns.len() - 1
            });
            self.nconns += 1;

            let mut conn = Conn::new(id, li, s);

            match peer(&self.targets[li], &conn) {
                Ok(Some(peer)) => {
                    self.conns[id] = Some(conn);
                    self.connect(id, li, peer, None);
                }
                Ok(None) => unreachable!("no address for first attempt"),
                Err(e) => {
                    info!("conn {id}: cannot connect to {}: {e}", self.targets[li]);
                    conn.rst(&self.ep);
                    self.conns[id] = Some(conn);
                    self.defer.push(id);
                }
            }
        }
    }

    /// Connect connection @id to @peer for listener @fwd, or queue a retry
    fn connect(&mut self, id: usize, fwd: usize, peer: Peer, mut retry: Option<Retry>) {
        let target = &self.targets[fwd];
        let Some(conn) = self.conns[id].as_mut() else { return };

        match conn.connect(&self.ep, &mut self.pool, &peer) {
            Ok(true) => {}
            Ok(false) => {
                let now = Instant::now();
                let r = retry.get_or_insert_with(|| {
                    debug!("conn {id}: listen backlog of {target} full, retrying");
                    Retry {
                        id,
                        fwd,
                        peer,
                        next: now,
                        delay: CONNECT_RETRY_MIN,
                        deadline: now + CONNECT_RETRY_TIMEOUT,
                    }
                });
                if now >= r.deadline {
                    info!("conn {id}: cannot connect to {target}: listen backlog full");
                    conn.rst(&self.ep);
                } else {
                    r.next = now + r.delay;
                    r.delay = (r.delay * 2).min(CONNECT_RETRY_MAX);
                    self.retries.push(*r);
                }
            }
            Err(e) => return self.connect_failed(id, e),
        }

        if conn.is_closing() {
            self.defer.push(id);
        }
    }

    /// connect() failed for connection @id with @e: try the next address of
    /// the target if there is one, reset the connection otherwise
    fn connect_failed(&mut self, id: usize, e: std::io::Error) {
        let Some(conn) = self.conns[id].as_mut() else { return };
        let fwd = conn.fwd();
        let target = &self.targets[fwd];
        let failed = match target {
            Target::Host { addrs, .. } => addrs[conn.attempt()].to_string(),
            _ => target.to_string(),
        };

        conn.connect_reset(&self.ep);
        match peer(target, conn) {
            Ok(Some(next)) => {
                debug!("conn {id}: cannot connect to {failed}: {e}, trying next address");
                self.connect(id, fwd, next, None);
            }
            Ok(None) | Err(_) => {
                info!("conn {id}: cannot connect to {target}: {e}");
                conn.rst(&self.ep);
                self.defer.push(id);
            }
        }
    }

    /// Retry connect() for connections whose retry time has come
    fn retry_connect(&mut self) {
        let now = Instant::now();
        let (due, wait) = std::mem::take(&mut self.retries).into_iter()
            .partition::<Vec<_>, _>(|r| r.next <= now);
        self.retries = wait;
        for r in due {
            self.connect(r.id, r.fwd, r.peer, Some(r));
        }
    }

    /// Timeout for epoll_wait(), in milliseconds
    fn timeout(&self) -> i32 {
        let now = Instant::now();
        let retry = self.retries.iter()
            .map(|r| r.next.saturating_duration_since(now).as_micros().div_ceil(1000) as i32)
            .min();
        let pause = self.paused.then_some(PAUSE_RETRY_MS);
        retry.into_iter().chain(pause).chain(self.udp.timeout()).min().unwrap_or(-1)
    }

    fn conn_event(&mut self, id: usize, sidei: usize, events: u32) {
        let Some(conn) = self.conns.get_mut(id).and_then(Option::as_mut) else { return };
        if let Some(e) = conn.handle(&self.ep, &mut self.pool, sidei, events) {
            return self.connect_failed(id, e);
        }
        if conn.is_closing() {
            self.defer.push(id);
        }
    }

    /// Deferred handling at the end of a batch: free closed connections
    fn deferred(&mut self) {
        for id in std::mem::take(&mut self.defer) {
            if self.conns[id].take().is_some() {
                self.free.push(id);
                self.nconns -= 1;
            }
        }
        self.pool.refill();
        self.resume();
    }
}

/// Find the address to connect to on the host for connection @conn, for
/// its current attempt(): targets given by host name can have several
///
/// Return: None if there are no addresses left to try
fn peer(target: &Target, conn: &Conn) -> std::io::Result<Option<Peer>> {
    if conn.attempt() > 0 && !matches!(target, Target::Host { .. }) {
        return Ok(None);
    }
    let peer = match target {
        Target::Unix(u) => {
            let (sun, len) = u.sockaddr().map_err(std::io::Error::other)?;
            Peer::Unix(sun, len)
        }
        Target::Ip { addr: Some(addr), port } => Peer::Tcp(SocketAddr::new(*addr, *port)),
        Target::Ip { addr: None, port } => {
            // Same (loopback) address as the one connected to in the namespace
            let local = sys::local_addr(conn.fd(0))?;
            Peer::Tcp(SocketAddr::new(local.ip(), *port))
        }
        Target::Host { addrs, .. } => match addrs.get(conn.attempt()) {
            Some(a) => Peer::Tcp(*a),
            None => return Ok(None),
        },
    };

    if conn.attempt() == 0 {
        match &peer {
            Peer::Tcp(a) => debug!("conn {}: accepted, connecting to {a}", conn.id()),
            Peer::Unix(..) => debug!("conn {}: accepted, connecting to {target}", conn.id()),
        }
    }
    Ok(Some(peer))
}


fn run(mut cfg: Config) -> Result<u8, String> {
    cfg.resolve()?;

    // One socket in the namespace per forwarded port
    let (ports, targets): (Vec<_>, Vec<_>) = cfg.forwards.iter()
        .flat_map(|f| f.ports().map(move |(port, target)| ((f.proto, port), target)))
        .unzip();

    let (nofile_orig, nofile) = sys::raise_nofile()
        .map_err(|e| format!("cannot get file descriptor limit: {e}"))?;
    if ports.len() + RESERVED_FDS > nofile {
        return Err(format!("too many forwarded ports ({}) for the open file limit ({nofile})",
                           ports.len()));
    }

    let Sandbox { pid, pidfd, listeners } = sandbox::spawn(&cfg.command, &ports, cfg.root, &nofile_orig)
        .map_err(|e| format!("cannot start sandbox: {e}"))?;

    // The command has its copies of whatever we inherited: drop ours
    let keep: Vec<_> = listeners.iter().map(|l| l.fd.as_raw_fd())
        .chain([pidfd.as_raw_fd()])
        .collect();
    match sys::drop_inherited(&keep) {
        // close_range() needs Linux 5.9: carry on, as pasta does
        Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {
            info!("can't use close_range(), inherited files stay open");
        }
        r => r.map_err(|e| format!("cannot close inherited files: {e}"))?,
    }

    // Like a shell waiting for a foreground job, leave terminal-generated
    // signals to the command: if we terminate, so does the command.
    // SAFETY: Setting signal dispositions to SIG_IGN
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }

    let ep = Epoll::new().map_err(|e| format!("cannot create epoll descriptor: {e}"))?;
    ep.add(pidfd.as_raw_fd(), libc::EPOLLIN as u32, Ref::Child)
        .map_err(|e| format!("epoll_ctl(): {e}"))?;
    for (i, l) in listeners.iter().enumerate() {
        ep.add(l.fd.as_raw_fd(), libc::EPOLLIN as u32, Ref::Listener(i))
            .map_err(|e| format!("epoll_ctl(): {e}"))?;
    }
    if let Some(l) = listeners.first() {
        let any = if l.addr.is_ipv6() { "[::]" } else { "0.0.0.0" };
        for f in &cfg.forwards {
            debug!("forwarding {f}, from {any} (lo) in namespace");
        }
    }

    let fd_budget = nofile.saturating_sub(RESERVED_FDS + listeners.len());
    debug!("maximum {} TCP connections, or {} UDP flows", (fd_budget / FDS_PER_CONN).max(1),
           (fd_budget / FDS_PER_FLOW).max(1));

    let mut fwd = Forwarder {
        ep,
        pool: PipePool::new(),
        listeners,
        targets,
        conns: Vec::new(),
        free: Vec::new(),
        defer: Vec::new(),
        retries: Vec::new(),
        nconns: 0,
        udp: Udp::new(),
        fd_budget,
        paused: false,
    };

    // SAFETY: All-zero is a valid epoll_event
    let mut buf = [unsafe { std::mem::zeroed::<libc::epoll_event>() }; EPOLL_EVENTS];
    let mut events = Vec::with_capacity(EPOLL_EVENTS);

    loop {
        fwd.ep.wait(&mut buf, fwd.timeout(), &mut events)
            .map_err(|e| format!("epoll_wait(): {e}"))?;

        for &(r, ev) in &events {
            match r {
                Ref::Child => {
                    let code = sandbox::reap(pid);
                    debug!("command exited with status {code}");
                    return Ok(code as u8);
                }
                Ref::Listener(i) => fwd.listener_event(i),
                Ref::Conn(id, sidei) => fwd.conn_event(id, sidei, ev),
                Ref::Flow(id) => fwd.flow_event(id),
            }
        }

        fwd.retry_connect();
        fwd.udp.expire(&fwd.ep);
        fwd.deferred();
    }
}

fn main() -> ExitCode {
    let cfg = match config::parse(std::env::args_os().skip(1)) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => return ExitCode::SUCCESS,
        Err(e) => {
            info!("{e}");
            eprintln!("Try 'specchio --help' for more information.");
            return ExitCode::FAILURE;
        }
    };
    log::set_debug(cfg.debug);

    match run(cfg) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            info!("{e}");
            ExitCode::FAILURE
        }
    }
}
