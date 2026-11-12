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
//! 2. bring up the loopback interface
//! 3. create the listening sockets for all forwards
//! 4. send them to the parent with SCM_RIGHTS over a socketpair
//! 5. close everything and exec() the command
//!
//! The parent never needs any capability, or to enter any namespace.

use std::ffi::CString;
use std::io::{self, Write as _};
use std::mem::zeroed;
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;

use crate::config::{Bind, Config};
use crate::fdpass;
use crate::log::debug;
use crate::sys::{self, cvt};

/// Message tags on the setup channel
const MSG_OK: u8 = b'K';
const MSG_ERR: u8 = b'E';

/// Listening socket inside the sandbox
pub struct Listener {
    pub fd: OwnedFd,
    pub addr: SocketAddr,
    /// Index of the forward in `Config::forwards`
    pub fwd: usize,
}

pub struct Sandbox {
    pub pid: libc::pid_t,
    pub pidfd: OwnedFd,
    pub listeners: Vec<Listener>,
}

/// Start @cfg.command in a new sandbox, with listening sockets for forwards
///
/// @nofile is the original RLIMIT_NOFILE, restored for the command
pub fn spawn(cfg: &Config, nofile: &libc::rlimit) -> io::Result<Sandbox> {
    let binds: Vec<(usize, Bind)> = cfg.forwards.iter().enumerate()
        .flat_map(|(i, f)| f.binds.iter().map(move |b| (i, *b)))
        .collect();

    // Prepare everything that allocates before fork()
    let argv: Vec<CString> = cfg.command.iter()
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
        child(theirs, uid, gid, ppid, &binds, nofile, &argvp);
    }
    drop(theirs);

    let mut buf = [0u8; 4096];
    let (n, fds) = fdpass::recv(ours.as_fd(), &mut buf)?;
    let msg = &buf[..n];

    if msg.first() != Some(&MSG_OK) {
        reap(pid);
        return Err(match msg {
            [MSG_ERR, why @ ..] => io::Error::other(String::from_utf8_lossy(why).into_owned()),
            _ => io::Error::other("sandbox setup failed"),
        });
    }

    // One status byte per bind: did it succeed?  Descriptors follow in order.
    let status = &msg[1..];
    if status.len() != binds.len() || fds.len() != status.iter().filter(|&&s| s != 0).count() {
        reap(pid);
        return Err(io::Error::other("malformed message from sandbox"));
    }
    let mut fds = fds.into_iter();
    let mut listeners = Vec::new();
    for (&(fwd, bind), &ok) in binds.iter().zip(status) {
        if ok != 0 {
            listeners.push(Listener { fd: fds.next().unwrap(), addr: bind.addr, fwd });
        } else {
            debug!("couldn't listen on {} in namespace, skipping", bind.addr);
        }
    }

    // SAFETY: pidfd_open() has no memory safety preconditions.  The child is
    // not reaped yet, so the PID can't be reused.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if pidfd < 0 {
        let e = io::Error::last_os_error();
        // SAFETY: Signalling our own unreaped child
        unsafe { libc::kill(pid, libc::SIGKILL) };
        reap(pid);
        return Err(e);
    }
    // SAFETY: pidfd was just created and is owned by nobody else
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };

    Ok(Sandbox { pid, pidfd, listeners })
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

/// Body of the child process: set up the sandbox, report back, exec()
fn child(sock: OwnedFd, uid: libc::uid_t, gid: libc::gid_t, ppid: libc::pid_t,
         binds: &[(usize, Bind)], nofile: &libc::rlimit,
         argv: &[*const libc::c_char]) -> ! {
    match child_setup(uid, gid, ppid, binds) {
        Ok((msg, fds)) => {
            let raw: Vec<RawFd> = fds.iter().map(|f| f.as_raw_fd()).collect();
            if fdpass::send(sock.as_fd(), &msg, &raw).is_err() {
                // SAFETY: Leaving without running any destructors is fine
                unsafe { libc::_exit(1) };
            }
            // The command must not get hold of the listening sockets
            drop(fds);
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

    // SAFETY: Restoring signal dispositions and limits for the command: Rust
    // ignores SIGPIPE by default, and that would be inherited across exec()
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
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

/// Set up namespaces and listening sockets in the child
///
/// Return: message for the parent and descriptors to attach, or error string
fn child_setup(uid: libc::uid_t, gid: libc::gid_t, ppid: libc::pid_t,
               binds: &[(usize, Bind)]) -> Result<(Vec<u8>, Vec<OwnedFd>), String> {
    // SAFETY: unshare() has no memory safety preconditions
    cvt(unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) })
        .map_err(|e| format!("cannot create namespaces: {e}"))?;

    // Unprivileged processes must disable setgroups() before writing gid_map
    match write_proc("/proc/self/setgroups", "deny") {
        Err(e) if e.kind() != io::ErrorKind::NotFound => {
            return Err(format!("cannot write /proc/self/setgroups: {e}"));
        }
        _ => {}
    }
    write_proc("/proc/self/uid_map", &format!("0 {uid} 1"))
        .map_err(|e| format!("cannot write /proc/self/uid_map: {e}"))?;
    write_proc("/proc/self/gid_map", &format!("0 {gid} 1"))
        .map_err(|e| format!("cannot write /proc/self/gid_map: {e}"))?;

    // Credentials changed in unshare(), which clears the parent death signal:
    // set it only now, then check we didn't miss the parent exiting already
    // SAFETY: prctl() with integer arguments, getppid() can't fail
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        if libc::getppid() != ppid {
            libc::_exit(1);
        }
    }

    loopback_up().map_err(|e| format!("cannot bring up loopback interface: {e}"))?;

    let mut msg = vec![MSG_OK];
    let mut fds = Vec::new();
    for (_, bind) in binds {
        match listen(&bind.addr) {
            Ok(fd) => {
                msg.push(1);
                fds.push(fd);
            }
            Err(_) if bind.best_effort => msg.push(0),
            Err(e) => return Err(format!("cannot listen on {} in namespace: {e}", bind.addr)),
        }
    }

    Ok((msg, fds))
}

fn write_proc(path: &str, content: &str) -> io::Result<()> {
    std::fs::OpenOptions::new().write(true).open(path)?.write_all(content.as_bytes())
}

/// Set the IFF_UP flag on the loopback interface
fn loopback_up() -> io::Result<()> {
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

/// Create a non-blocking TCP socket listening on @addr
fn listen(addr: &SocketAddr) -> io::Result<OwnedFd> {
    let af = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let s = sys::socket(af, libc::SOCK_STREAM | libc::SOCK_NONBLOCK)?;

    sys::setsockopt_int(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    if addr.is_ipv6() {
        sys::setsockopt_int(s.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1)?;
    }

    let (sa, len) = sys::sockaddr_ip(addr);
    // SAFETY: sa is a valid socket address of length len
    cvt(unsafe { libc::bind(s.as_raw_fd(), (&sa as *const libc::sockaddr_storage).cast(), len) })?;
    // SAFETY: listen() has no memory safety preconditions
    cvt(unsafe { libc::listen(s.as_raw_fd(), libc::SOMAXCONN) })?;
    Ok(s)
}
