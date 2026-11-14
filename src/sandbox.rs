// SPDX-License-Identifier: GPL-2.0-or-later

//! Creation of the sandbox namespaces and of listening sockets inside them
//!
//! A socket stays in the network namespace it was created in, whoever holds
//! its descriptor later.  So instead of entering the sandbox namespace from
//! the parent (as pasta does with setns()), the child sets everything up
//! before exec()ing the command:
//!
//! 1. unshare() new user and network namespaces, and map the original UID and
//!    GID to root, so that the child gets CAP_NET_ADMIN over the new network
//!    namespace
//! 2. bring up the loopback interface, and let unprivileged processes bind
//!    any port and use ping sockets in the namespace
//! 3. create the listening sockets (TCP) and receiving sockets (UDP) for all
//!    forwarded ports
//! 4. unless asked to keep root, unshare() a nested user namespace mapping the
//!    original UID and GID to root of the first one, so that the command runs
//!    with its original IDs, and without capabilities once it's exec()ed
//! 5. send the sockets to the parent with SCM_RIGHTS over a socketpair, in
//!    batches, followed by a descriptor for the network namespace if the
//!    parent needs to create sockets there later (inbound forwarding)
//! 6. wait for the parent to be ready, close everything and exec() the command
//!
//! For outbound forwarding only, the parent never needs any capability, or to
//! enter any namespace.  For inbound forwarding, it joins the sandbox's user
//! namespace before letting the child go on, see ns.rs.

use std::ffi::{CString, OsString};
use std::io::{self, Write as _};
use std::mem::zeroed;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;

use crate::config::{Bind, Proto};
use crate::fdpass;
use crate::log::info;
use crate::sys::{self, cvt};

/// Message tags on the setup channel
const MSG_OK: u8 = b'K';
const MSG_ERR: u8 = b'E';

/// Listening (TCP) or receiving (UDP) socket, in the sandbox, or on the host
/// for inbound forwarding
pub struct Listener {
    pub fd: OwnedFd,
    pub addr: SocketAddr,
    pub proto: Proto,
    pub inbound: bool,
}

pub struct Sandbox {
    pub pid: libc::pid_t,
    pub pidfd: OwnedFd,
    pub listeners: Vec<Listener>,
    /// Network namespace, joinable from a thread, if requested
    pub netns: Option<OwnedFd>,
}

/// Start @command in a new sandbox, with a socket for each of @ports, in order
///
/// @root: run the command as root in the sandbox's user namespace, instead of
///        with the original user and group IDs
/// @nofile is the original RLIMIT_NOFILE, restored for the command
/// @netns: join the sandbox's user namespace, and return a descriptor for its
///         network namespace, so that threads can create sockets there
/// @sigmask is the original signal mask, restored for the command
pub fn spawn(command: &[OsString], ports: &[(Proto, u16)], root: bool, nofile: &libc::rlimit,
             netns: bool, sigmask: &libc::sigset_t) -> io::Result<Sandbox> {
    // Prepare everything that allocates before fork()
    let argv: Vec<CString> = command.iter()
        .map(|a| CString::new(a.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|_| io::Error::other("NUL byte in command argument"))?;
    let mut argvp: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argvp.push(std::ptr::null());

    let mut sv = [-1; 2];
    // SAFETY: sv is a valid array of two c_ints
    cvt(unsafe {
        libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0,
                         sv.as_mut_ptr())
    })?;
    // SAFETY: Both descriptors were just created and are owned by nobody else
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };

    // SAFETY: get*id() can't fail
    let (uid, gid, ppid) = unsafe { (libc::getuid(), libc::getgid(), libc::getpid()) };

    // SAFETY: We're single-threaded, so the child can do anything we can
    let pid = cvt(unsafe { libc::fork() })?;
    if pid == 0 {
        drop(ours);
        child(theirs, uid, gid, ppid, ports, root, netns, nofile, sigmask, &argvp);
    }
    drop(theirs);

    // The child doesn't run the command until we say so: on errors, make sure
    // it's gone.  It also exits by itself if we do
    let parent = || -> io::Result<Sandbox> {
        let mut fds = recv_sockets(&ours, ports.len() + usize::from(netns))?;
        let netns = if netns { fds.pop() } else { None };
        let listeners = fds.into_iter().zip(ports)
            .map(|(fd, &(proto, _))| {
                let addr = sys::local_addr(fd.as_raw_fd())?;
                Ok(Listener { fd, addr, proto, inbound: false })
            })
            .collect::<io::Result<_>>()?;

        if let Some(netns) = &netns {
            crate::ns::join(netns).map_err(io::Error::other)?;
        }

        // The child is not reaped yet, so the PID can't be reused
        let pidfd = sys::pidfd_open(pid)?;

        fdpass::send(ours.as_fd(), &[MSG_OK], &[])?;
        Ok(Sandbox { pid, pidfd, listeners, netns })
    };

    parent().inspect_err(|_| {
        // SAFETY: Signalling our own unreaped child
        unsafe { libc::kill(pid, libc::SIGKILL) };
        reap(pid);
    })
}

/// Receive @n sockets from the child, in batches of at most fdpass::MAX_FDS
fn recv_sockets(sock: &OwnedFd, n: usize) -> io::Result<Vec<OwnedFd>> {
    let mut all = Vec::with_capacity(n);
    loop {
        let mut buf = [0u8; 4096];
        let (len, fds) = fdpass::recv(sock.as_fd(), &mut buf)?;
        match &buf[..len] {
            [MSG_OK] => {}
            [MSG_ERR, why @ ..] => {
                return Err(io::Error::other(String::from_utf8_lossy(why).into_owned()));
            }
            [] => return Err(io::Error::other("sandbox setup failed")),
            _ => return Err(io::Error::other("malformed message from sandbox")),
        }
        if (fds.is_empty() && n > 0) || all.len() + fds.len() > n {
            return Err(io::Error::other("malformed message from sandbox"));
        }
        all.extend(fds);
        if all.len() == n {
            return Ok(all);
        }
    }
}

/// Wait for child @pid to terminate, return the exit code to use for it
pub fn reap(pid: libc::pid_t) -> i32 {
    let mut status = 0;
    loop {
        // SAFETY: Passing a pointer to a valid c_int
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r >= 0 || sys::errno() != libc::EINTR {
            break;
        }
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

/// Body of the child process: set up the sandbox, report back, wait for the
/// parent, exec()
#[allow(clippy::too_many_arguments)]
fn child(sock: OwnedFd, uid: libc::uid_t, gid: libc::gid_t, ppid: libc::pid_t,
         ports: &[(Proto, u16)], root: bool, netns: bool, nofile: &libc::rlimit,
         sigmask: &libc::sigset_t, argv: &[*const libc::c_char]) -> ! {
    match child_setup(uid, gid, ppid, ports, root, netns) {
        Ok(fds) => {
            let raw: Vec<RawFd> = fds.iter().map(|f| f.as_raw_fd()).collect();
            // At least one message, even without sockets
            for batch in raw.chunks(fdpass::MAX_FDS).chain(raw.is_empty().then_some(&[][..])) {
                if fdpass::send(sock.as_fd(), &[MSG_OK], batch).is_err() {
                    // SAFETY: Leaving without running any destructors is fine
                    unsafe { libc::_exit(1) };
                }
            }
            // The command must not get hold of the listening sockets
            drop(fds);

            // Wait for the parent: nothing (EOF) if it failed or exited
            let mut buf = [0u8; 1];
            if !matches!(fdpass::recv(sock.as_fd(), &mut buf), Ok((1, _))) || buf[0] != MSG_OK {
                // SAFETY: Leaving without running any destructors is fine
                unsafe { libc::_exit(1) };
            }
        }
        Err(why) => {
            let mut msg = vec![MSG_ERR];
            msg.extend_from_slice(why.as_bytes());
            let _ = fdpass::send(sock.as_fd(), &msg, &[]);
            // SAFETY: Leaving without running any destructors is fine
            unsafe { libc::_exit(1) };
        }
    }
    drop(sock);

    // SAFETY: Restoring signal dispositions, mask and limits for the command:
    // Rust ignores SIGPIPE by default, and that would be inherited across
    // exec(), as would the signals blocked for forwarding
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        crate::signals::restore(sigmask);
        libc::setrlimit(libc::RLIMIT_NOFILE, nofile);
        libc::execvp(argv[0], argv.as_ptr());
    }

    let e = io::Error::last_os_error();
    // SAFETY: argv[0] is a valid NUL-terminated string
    let cmd = unsafe { std::ffi::CStr::from_ptr(argv[0]) };
    eprintln!("specchio: cannot execute {}: {e}", cmd.to_string_lossy());
    // SAFETY: Leaving without running any destructors is fine
    unsafe { libc::_exit(127) }
}

/// Set up namespaces and sockets in the child
///
/// Return: sockets for the parent, followed by the network namespace if
///         @netns is set, or error string
fn child_setup(uid: libc::uid_t, gid: libc::gid_t, ppid: libc::pid_t,
               ports: &[(Proto, u16)], root: bool, netns: bool)
               -> Result<Vec<OwnedFd>, String> {
    // SAFETY: unshare() has no memory safety preconditions
    cvt(unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) })
        .map_err(|e| format!("cannot create namespaces: {e}"))?;
    map_ids(uid, 0, gid, 0)?;

    // Die with the parent, and check we didn't miss it exiting already.
    // Neither unshare() nor the ID maps clear the parent death signal
    // SAFETY: prctl() with integer arguments, getppid() can't fail
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        if libc::getppid() != ppid {
            libc::_exit(1);
        }
    }

    loopback_up().map_err(|e| format!("cannot bring up loopback interface: {e}"))?;

    // Ports below 1024 and ping sockets need no privileges in here: the
    // command wouldn't have them otherwise.  These settings are per network
    // namespace, and we're root in the user namespace owning it.  As kernel
    // group IDs, "0 0" is the original group ID: the only one mapped here.
    // Losing them isn't worth failing for, as on kernels without them
    for (path, value) in [("/proc/sys/net/ipv4/ip_unprivileged_port_start", "0"),
                          ("/proc/sys/net/ipv4/ping_group_range", "0 0")] {
        if let Err(e) = write_proc(path, value) {
            info!("cannot write {path} in namespace: {e}");
        }
    }

    let mut fds: Vec<OwnedFd> = ports.iter()
        .map(|&(proto, port)| listen(proto, port).map_err(|e| {
            format!("cannot listen on {} port {port} in namespace: {e}", proto.name())
        }))
        .collect::<Result<_, _>>()?;

    if netns {
        let ns = std::fs::File::open("/proc/self/ns/net")
            .map_err(|e| format!("cannot open /proc/self/ns/net: {e}"))?;
        fds.push(ns.into());
    }

    // Drop "fake root" for the command: in a nested user namespace, map the
    // original IDs to root of the sandbox's user namespace, which we are now.
    // Once exec()ed as a user other than root there, the command has no
    // capabilities, in either user namespace.  This doesn't affect the
    // parent death signal.  Nothing to do if we started as root
    if !root && uid != 0 {
        // SAFETY: unshare() has no memory safety preconditions
        cvt(unsafe { libc::unshare(libc::CLONE_NEWUSER) })
            .map_err(|e| format!("cannot create nested user namespace (try --root): {e}"))?;
        map_ids(0, uid, 0, gid)?;
    }

    Ok(fds)
}

/// Map @outside_uid and @outside_gid to @inside_uid and @inside_gid in the
/// user namespace we just created: the only mapping we can write unprivileged
fn map_ids(outside_uid: libc::uid_t, inside_uid: libc::uid_t,
           outside_gid: libc::gid_t, inside_gid: libc::gid_t) -> Result<(), String> {
    // Unprivileged processes must disable setgroups() before writing gid_map.
    // In a nested user namespace, it's already disabled, and stays so
    match write_proc("/proc/self/setgroups", "deny") {
        Err(e) if e.kind() != io::ErrorKind::NotFound => {
            return Err(format!("cannot write /proc/self/setgroups: {e}"));
        }
        _ => {}
    }
    write_proc("/proc/self/uid_map", &format!("{inside_uid} {outside_uid} 1"))
        .map_err(|e| format!("cannot write /proc/self/uid_map: {e}"))?;
    write_proc("/proc/self/gid_map", &format!("{inside_gid} {outside_gid} 1"))
        .map_err(|e| format!("cannot write /proc/self/gid_map: {e}"))
}

fn write_proc(path: &str, content: &str) -> io::Result<()> {
    std::fs::OpenOptions::new().write(true).open(path)?.write_all(content.as_bytes())
}

/// Set the IFF_UP flag on the loopback interface
pub fn loopback_up() -> io::Result<()> {
    let s = sys::socket(libc::AF_INET, libc::SOCK_DGRAM)?;
    // SAFETY: All-zero is a valid ifreq
    let mut ifr: libc::ifreq = unsafe { zeroed() };
    for (dst, src) in ifr.ifr_name.iter_mut().zip(b"lo") {
        *dst = *src as libc::c_char;
    }
    // SAFETY: SIOCGIFFLAGS and SIOCSIFFLAGS take a pointer to struct ifreq
    unsafe {
        cvt(libc::ioctl(s.as_raw_fd(), libc::SIOCGIFFLAGS, &mut ifr))?;
        ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        cvt(libc::ioctl(s.as_raw_fd(), libc::SIOCSIFFLAGS, &ifr))?;
    }
    Ok(())
}

/// Create a non-blocking socket listening (TCP) or receiving (UDP) on @port,
/// on the loopback interface, dual-stack if IPv6 is available, like pasta
/// does for -T and -U
pub fn listen(proto: Proto, port: u16) -> io::Result<OwnedFd> {
    listen_any(proto, port, Some("lo"))
}

/// Create a non-blocking socket listening (TCP) or receiving (UDP) on @port
/// on all addresses, dual-stack if IPv6 is available, on device @dev if given
fn listen_any(proto: Proto, port: u16, dev: Option<&str>) -> io::Result<OwnedFd> {
    match listen_on(proto, &SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port), false, dev) {
        Err(e) if matches!(e.raw_os_error(), Some(libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL)) => {
            listen_on(proto, &SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port), false, dev)
        }
        r => r,
    }
}

/// Create a non-blocking socket listening (TCP) or receiving (UDP) on @port
/// on the host, at @bind, for inbound forwarding, like pasta does for -t, -u
pub fn listen_host(proto: Proto, bind: &Bind, port: u16) -> io::Result<Listener> {
    let dev = bind.ifname.as_deref();
    let fd = match bind.addr {
        None => listen_any(proto, port, dev)?,
        // An unspecified IPv6 address is IPv6 only, as opposed to no address
        Some(a) => listen_on(proto, &SocketAddr::new(a, port), true, dev)?,
    };
    let addr = sys::local_addr(fd.as_raw_fd())?;
    Ok(Listener { fd, addr, proto, inbound: true })
}

/// Create a socket listening on @addr, IPv6 only if @v6only, on @dev if given
fn listen_on(proto: Proto, addr: &SocketAddr, v6only: bool, dev: Option<&str>)
             -> io::Result<OwnedFd> {
    let af = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let ty = match proto {
        Proto::Tcp => libc::SOCK_STREAM,
        Proto::Udp => libc::SOCK_DGRAM,
    };
    let s = sys::socket(af, ty | libc::SOCK_NONBLOCK)?;
    let fd = s.as_raw_fd();

    match proto {
        Proto::Tcp => sys::setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?,
        // Not SO_REUSEADDR: another process (in the namespace, the command)
        // could bind the same port with it, and take datagrams from us.  We
        // need the destination address of datagrams, to reply from it (see
        // udp.rs)
        Proto::Udp if addr.is_ipv6() => {
            sys::setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1)?;
        }
        Proto::Udp => sys::setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1)?,
    }
    if addr.is_ipv6() {
        sys::setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, i32::from(v6only))?;
    }

    // In the namespace, only lo exists now, but the command could add
    // interfaces with --root: don't accept connections from those
    if let Some(dev) = dev {
        // SAFETY: Passing a valid buffer and its length
        cvt(unsafe {
            libc::setsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_BINDTODEVICE,
                             dev.as_ptr().cast(), dev.len() as libc::socklen_t)
        })?;
    }

    let (sa, len) = sys::sockaddr_ip(addr);
    // SAFETY: sa is a valid socket address of length len
    cvt(unsafe { libc::bind(s.as_raw_fd(), (&sa as *const libc::sockaddr_storage).cast(), len) })?;
    if proto == Proto::Tcp {
        // SAFETY: listen() has no memory safety preconditions
        cvt(unsafe { libc::listen(s.as_raw_fd(), libc::SOMAXCONN) })?;
    }
    Ok(s)
}
