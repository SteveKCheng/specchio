// SPDX-License-Identifier: GPL-2.0-or-later

//! Passing file descriptors over Unix domain sockets (SCM_RIGHTS)

use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{BorrowedFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;

/// Maximum number of descriptors in one message (SCM_MAX_FD in the kernel)
pub const MAX_FDS: usize = 253;

fn cmsg_space(nfds: usize) -> usize {
    // SAFETY: CMSG_SPACE() is a pure computation
    unsafe { libc::CMSG_SPACE((nfds * size_of::<RawFd>()) as u32) as usize }
}

/// Send @data with @fds attached as a single message on @sock
pub fn send(sock: BorrowedFd, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
    assert!(fds.len() <= MAX_FDS);

    // u64 elements keep the control buffer aligned for struct cmsghdr
    let mut cbuf = vec![0u64; cmsg_space(fds.len()).div_ceil(8)];
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut _,
        iov_len: data.len(),
    };
    // SAFETY: All-zero is a valid msghdr
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    if !fds.is_empty() {
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = cmsg_space(fds.len()) as _;

        // SAFETY: The control buffer has room for one cmsghdr carrying all
        // descriptors, as computed by CMSG_SPACE()
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(size_of_val(fds) as u32) as _;
            ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(cmsg).cast(), fds.len());
        }
    }

    // SAFETY: msg points to valid buffers for its whole lifetime here
    let n = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receive one message into @buf, return its length and attached descriptors
pub fn recv(sock: BorrowedFd, buf: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    let mut cbuf = vec![0u64; cmsg_space(MAX_FDS).div_ceil(8)];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: All-zero is a valid msghdr
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_space(MAX_FDS) as _;

    let n = loop {
        // SAFETY: msg points to valid buffers for its whole lifetime here
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n >= 0 {
            break n as usize;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    };

    let mut fds = Vec::new();
    // SAFETY: The kernel filled in msg_control/msg_controllen; we only walk
    // the headers it wrote, and take ownership of descriptors it gave us
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let payload = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                for i in 0..payload / size_of::<RawFd>() {
                    fds.push(OwnedFd::from_raw_fd(ptr::read_unaligned(data.add(i))));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    if msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
        return Err(io::Error::other("truncated message on setup channel"));
    }

    Ok((n, fds))
}
