// SPDX-License-Identifier: GPL-2.0-or-later

//! Thin wrappers around libc calls

use std::io;
use std::mem::{size_of, zeroed};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

/// Turn a C-style `-1` return value into an `io::Error` from `errno`
pub fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

pub fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Call `f` until it no longer fails with `EINTR`, return value and errno
pub fn retry_eintr(mut f: impl FnMut() -> isize) -> (isize, i32) {
    loop {
        let ret = f();
        if ret >= 0 {
            return (ret, 0);
        }
        let err = errno();
        if err != libc::EINTR {
            return (ret, err);
        }
    }
}

pub fn setsockopt_int(fd: RawFd, level: i32, name: i32, val: i32) -> io::Result<()> {
    // SAFETY: Passing a pointer to a valid c_int and its size
    cvt(unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&val as *const i32).cast(),
            size_of::<i32>() as libc::socklen_t,
        )
    })
    .map(drop)
}

/// Read and clear the pending error on a socket (`SO_ERROR`)
pub fn so_error(fd: RawFd) -> io::Result<i32> {
    let mut err: i32 = 0;
    let mut len = size_of::<i32>() as libc::socklen_t;
    // SAFETY: Passing a pointer to a valid c_int and its size
    cvt(unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut err as *mut i32).cast(),
            &mut len,
        )
    })?;
    Ok(err)
}

/// Set `SO_LINGER` with 0 timeout, so that `close()` sends an RST
pub fn linger0(fd: RawFd) -> io::Result<()> {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: Passing a pointer to a valid struct linger and its size
    cvt(unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&linger as *const libc::linger).cast(),
            size_of::<libc::linger>() as libc::socklen_t,
        )
    })
    .map(drop)
}

pub fn socket(domain: i32, ty: i32) -> io::Result<OwnedFd> {
    // SAFETY: socket() has no memory safety preconditions
    let fd = cvt(unsafe { libc::socket(domain, ty | libc::SOCK_CLOEXEC, 0) })?;
    // SAFETY: fd is a freshly created descriptor that nobody else owns
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Build a `sockaddr_storage` from an IP socket address
pub fn sockaddr_ip(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: All-zero is a valid sockaddr_storage
    let mut ss: libc::sockaddr_storage = unsafe { zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            // SAFETY: sockaddr_storage is large and aligned enough for sockaddr_in
            let sin = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = a.port().to_be();
            sin.sin_addr.s_addr = u32::from(*a.ip()).to_be();
            size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            // SAFETY: sockaddr_storage is large and aligned enough for sockaddr_in6
            let sin6 = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = a.port().to_be();
            sin6.sin6_addr.s6_addr = a.ip().octets();
            sin6.sin6_scope_id = a.scope_id();
            size_of::<libc::sockaddr_in6>()
        }
    };
    (ss, len as libc::socklen_t)
}

/// Create a non-blocking pipe, return (read end, write end)
pub fn pipe2_nonblock() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: fds is a valid array of two c_ints
    cvt(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) })?;
    // SAFETY: Both descriptors were just created and are owned by nobody else
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Set pipe buffer size, return the size actually set
pub fn set_pipe_size(fd: BorrowedFd, size: usize) -> io::Result<usize> {
    // SAFETY: F_SETPIPE_SZ takes an integer argument
    let ret = cvt(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETPIPE_SZ, size as libc::c_int) })?;
    Ok(ret as usize)
}

/// Raise the soft limit on open files to the hard limit, return the old limit
pub fn raise_nofile() -> io::Result<(libc::rlimit, usize)> {
    // SAFETY: All-zero is a valid rlimit
    let mut old: libc::rlimit = unsafe { zeroed() };
    // SAFETY: Passing a pointer to a valid rlimit
    cvt(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut old) })?;
    let new = libc::rlimit {
        rlim_cur: old.rlim_max,
        rlim_max: old.rlim_max,
    };
    // SAFETY: Passing a pointer to a valid rlimit
    let cur = if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new) } == 0 {
        new.rlim_cur
    } else {
        old.rlim_cur
    };
    Ok((old, cur.min(i32::MAX as libc::rlim_t) as usize))
}
