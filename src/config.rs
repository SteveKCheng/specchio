// SPDX-License-Identifier: GPL-2.0-or-later

//! Command line parsing

use std::ffi::OsString;
use std::fmt;
use std::mem::{offset_of, size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

pub const USAGE: &str = "\
Usage: specchio [OPTION]... [--] [COMMAND [ARG]...]

Run COMMAND (default: $SHELL) in new user and network namespaces with only a
loopback interface, splicing TCP connections to forwarded ports in the
namespace to Unix domain sockets on the host.

Options:
  -T, --tcp-ns SPEC   Forward TCP port from namespace to host Unix socket
                      SPEC is [ADDR/]PORT:TARGET
                        ADDR    address to listen on in the namespace;
                                default: 127.0.0.1 and ::1 (if available)
                        TARGET  /path/to/socket, or @name for an abstract
                                socket (relative paths are made absolute)
                      can be given multiple times
  -d, --debug         Print debugging messages
  -h, --help          Display this help message and exit
      --version       Show version and exit

Example:
  specchio -T 3128:/run/user/1000/proxy.sock -- \\
      env https_proxy=http://127.0.0.1:3128 curl https://example.com/
";

/// Host side Unix domain socket to connect to
#[derive(Clone, Debug)]
pub enum UnixTarget {
    /// Filesystem path
    Path(PathBuf),
    /// Linux abstract namespace name (without leading NUL)
    Abstract(Vec<u8>),
}

impl UnixTarget {
    fn parse(s: &[u8]) -> Result<Self, String> {
        let t = match s {
            [] => return Err("empty target".into()),
            [b'@', name @ ..] => UnixTarget::Abstract(name.to_vec()),
            _ => {
                let p = PathBuf::from(OsString::from_vec(s.to_vec()));
                let p = if p.is_absolute() {
                    p
                } else {
                    std::env::current_dir()
                        .map_err(|e| format!("cannot get current directory: {e}"))?
                        .join(p)
                };
                UnixTarget::Path(p)
            }
        };
        t.sockaddr().map(|_| t)
    }

    /// Build the `sockaddr_un` for this target
    pub fn sockaddr(&self) -> Result<(libc::sockaddr_un, libc::socklen_t), String> {
        // SAFETY: All-zero is a valid sockaddr_un
        let mut sun: libc::sockaddr_un = unsafe { zeroed() };
        sun.sun_family = libc::AF_UNIX as libc::sa_family_t;

        let (bytes, offset, extra) = match self {
            // Abstract: leading NUL, name, no terminator
            UnixTarget::Abstract(name) => (name.as_slice(), 1, 0),
            // Path: name, NUL terminator
            UnixTarget::Path(p) => (p.as_os_str().as_bytes(), 0, 1),
        };
        if offset + bytes.len() + extra > sun.sun_path.len() {
            return Err(format!("socket name too long: {self}"));
        }
        for (dst, src) in sun.sun_path[offset..].iter_mut().zip(bytes) {
            *dst = *src as libc::c_char;
        }

        let len = offset_of!(libc::sockaddr_un, sun_path) + offset + bytes.len() + extra;
        debug_assert!(len <= size_of::<libc::sockaddr_un>());
        Ok((sun, len as libc::socklen_t))
    }
}

impl fmt::Display for UnixTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UnixTarget::Path(p) => write!(f, "{}", p.display()),
            UnixTarget::Abstract(n) => write!(f, "@{}", String::from_utf8_lossy(n)),
        }
    }
}

/// Address to listen on in the namespace
#[derive(Clone, Copy, Debug)]
pub struct Bind {
    pub addr: SocketAddr,
    /// Don't fail if we can't bind (used for the default ::1)
    pub best_effort: bool,
}

/// One port forwarding specification
#[derive(Clone, Debug)]
pub struct Forward {
    pub binds: Vec<Bind>,
    pub target: UnixTarget,
}

#[derive(Debug)]
pub struct Config {
    pub forwards: Vec<Forward>,
    pub debug: bool,
    pub command: Vec<OsString>,
}

/// Parse a forwarding specification: [ADDR/]PORT:TARGET
fn parse_forward(spec: &[u8]) -> Result<Forward, String> {
    let bad = |why: &str| format!("invalid forwarding spec '{}': {why}",
                                  String::from_utf8_lossy(spec));

    // The target may contain both '/' and ':', and an IPv6 address contains
    // ':', so: if everything before the first ':' is a port number, there's
    // no address.  Otherwise the address ends at the first '/'.
    let colon = spec.iter().position(|&b| b == b':').ok_or_else(|| bad("missing ':'"))?;
    let (addr, rest) = if colon > 0 && spec[..colon].iter().all(u8::is_ascii_digit) {
        (None, spec)
    } else {
        let slash = spec.iter().position(|&b| b == b'/').ok_or_else(|| bad("missing '/'"))?;
        let a = std::str::from_utf8(&spec[..slash]).map_err(|_| bad("bad address"))?;
        let a = a.strip_prefix('[').and_then(|a| a.strip_suffix(']')).unwrap_or(a);
        (Some(a.parse::<IpAddr>().map_err(|e| bad(&e.to_string()))?), &spec[slash + 1..])
    };

    let colon = rest.iter().position(|&b| b == b':').ok_or_else(|| bad("missing ':'"))?;
    let port: u16 = std::str::from_utf8(&rest[..colon])
        .ok()
        .and_then(|p| p.parse().ok())
        .filter(|&p| p != 0)
        .ok_or_else(|| bad("bad port"))?;
    let target = UnixTarget::parse(&rest[colon + 1..]).map_err(|e| bad(&e))?;

    let binds = match addr {
        Some(a) => vec![Bind { addr: SocketAddr::new(a, port), best_effort: false }],
        None => vec![
            Bind { addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port), best_effort: false },
            Bind { addr: SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port), best_effort: true },
        ],
    };

    Ok(Forward { binds, target })
}

/// Parse command line arguments (not including argv[0])
///
/// Return: Ok(None) if the program should exit successfully (--help etc.)
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Option<Config>, String> {
    let mut args = args.into_iter();
    let mut cfg = Config { forwards: Vec::new(), debug: false, command: Vec::new() };

    while let Some(arg) = args.next() {
        let a = arg.as_bytes();
        match a {
            b"--" => break,
            b"-h" | b"--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            b"--version" => {
                println!("specchio {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            b"-d" | b"--debug" => cfg.debug = true,
            b"-T" | b"--tcp-ns" => {
                let v = args.next().ok_or("option requires an argument: --tcp-ns")?;
                cfg.forwards.push(parse_forward(v.as_bytes())?);
            }
            _ if a.starts_with(b"--tcp-ns=") => {
                cfg.forwards.push(parse_forward(&a[b"--tcp-ns=".len()..])?);
            }
            _ if a.starts_with(b"-T") => cfg.forwards.push(parse_forward(&a[2..])?),
            _ if a.starts_with(b"-") && a.len() > 1 => {
                return Err(format!("unrecognised option: {}", arg.to_string_lossy()));
            }
            _ => {
                cfg.command.push(arg);
                break;
            }
        }
    }
    cfg.command.extend(args);

    if cfg.command.is_empty() {
        cfg.command.push(std::env::var_os("SHELL").unwrap_or_else(|| "/bin/sh".into()));
    }

    let nbinds: usize = cfg.forwards.iter().map(|f| f.binds.len()).sum();
    if nbinds > crate::fdpass::MAX_FDS {
        return Err(format!("too many listening sockets (maximum {})", crate::fdpass::MAX_FDS));
    }

    Ok(Some(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_only() {
        let f = parse_forward(b"3128:/run/proxy.sock").unwrap();
        assert_eq!(f.binds.len(), 2);
        assert_eq!(f.binds[0].addr, "127.0.0.1:3128".parse().unwrap());
        assert!(matches!(f.target, UnixTarget::Path(ref p) if p == "/run/proxy.sock"));
    }

    #[test]
    fn with_address() {
        let f = parse_forward(b"::1/8080:@proxy:x").unwrap();
        assert_eq!(f.binds.len(), 1);
        assert_eq!(f.binds[0].addr, "[::1]:8080".parse().unwrap());
        assert!(matches!(f.target, UnixTarget::Abstract(ref n) if n == b"proxy:x"));

        let f = parse_forward(b"[::1]/8080:/a").unwrap();
        assert_eq!(f.binds[0].addr, "[::1]:8080".parse().unwrap());
        let f = parse_forward(b"127.0.0.2/1:/a/b:c").unwrap();
        assert_eq!(f.binds[0].addr, "127.0.0.2:1".parse().unwrap());
    }

    #[test]
    fn invalid() {
        assert!(parse_forward(b"3128").is_err());
        assert!(parse_forward(b"0:/a").is_err());
        assert!(parse_forward(b"70000:/a").is_err());
        assert!(parse_forward(b"3128:").is_err());
        assert!(parse_forward(b"foo/3128:/a").is_err());
        let long = format!("1:/{}", "x".repeat(200));
        assert!(parse_forward(long.as_bytes()).is_err());
    }
}
