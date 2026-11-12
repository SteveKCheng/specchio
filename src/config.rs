// SPDX-License-Identifier: GPL-2.0-or-later

//! Command line parsing

use std::ffi::OsString;
use std::fmt;
use std::mem::{offset_of, size_of, zeroed};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

pub const USAGE: &str = "\
Usage: specchio [OPTION]... [--] [COMMAND [ARG]...]

Run COMMAND (default: $SHELL) in new user and network namespaces with only a
loopback interface, splicing TCP connections to forwarded ports in the
namespace to TCP ports or Unix domain sockets on the host.

Options:
  -T, --tcp-ns SPEC   Forward a TCP port from the namespace to the host, as
                      with pasta(1), connections to any loopback address in
                      the namespace.  SPEC can be:
                        none          don't forward anything
                        PORT[:TARGET]
                      where TARGET is one of:
                        TOPORT        same loopback address on the host as
                                      the one connected to in the namespace,
                                      port TOPORT (default: PORT)
                        TOADDR[/TOPORT]
                                      address of a host interface
                        /path/to/socket, ./relative/path, @abstract-name
                                      Unix domain socket on the host
                      can be given multiple times
  -d, --debug         Print debugging messages
  -h, --help          Display this help message and exit
      --version       Show version and exit

Examples:
  specchio -T 3128:/run/user/1000/proxy.sock -- \\
      env https_proxy=http://127.0.0.1:3128 curl https://example.com/
  specchio -T 8080 -T 5432:192.0.2.1/5433 -- my-agent
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

/// Where to connect to on the host
#[derive(Clone, Debug)]
pub enum Target {
    /// TCP port, at @addr, or at the address connected to in the namespace
    Tcp { addr: Option<IpAddr>, port: u16 },
    Unix(UnixTarget),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Target::Tcp { addr: Some(a), port } => write!(f, "{}", SocketAddr::new(*a, *port)),
            Target::Tcp { addr: None, port } => write!(f, "port {port} on loopback"),
            Target::Unix(u) => write!(f, "{u}"),
        }
    }
}

/// One port forwarding specification
#[derive(Clone, Debug)]
pub struct Forward {
    /// Port to listen on in the namespace, on any loopback address
    pub port: u16,
    pub target: Target,
}

#[derive(Debug)]
pub struct Config {
    pub forwards: Vec<Forward>,
    pub debug: bool,
    pub command: Vec<OsString>,
}

fn parse_port(s: &[u8]) -> Option<u16> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(s).ok()?.parse().ok().filter(|&p| p != 0)
}

fn parse_ip(s: &[u8]) -> Option<IpAddr> {
    std::str::from_utf8(s).ok()?.parse().ok()
}

/// Parse a forwarding specification, see USAGE
///
/// Return: None for "none"
fn parse_forward(spec: &[u8]) -> Result<Option<Forward>, String> {
    let bad = |why: &str| format!("invalid port specifier '{}': {why}",
                                  String::from_utf8_lossy(spec));

    if spec == b"none" {
        return Ok(None);
    }

    let (port, target) = match spec.iter().position(|&b| b == b':') {
        Some(colon) => (&spec[..colon], Some(&spec[colon + 1..])),
        None => (spec, None),
    };

    let Some(port) = parse_port(port) else {
        // pasta's error for [ADDRESS[%IFNAME]/]PORT with -T, otherwise a guess
        if port.contains(&b'/') || port.contains(&b'%') || parse_ip(port).is_some() {
            return Err(bad("listening address not allowed for -T"));
        }
        if port.contains(&b'-') || port.contains(&b',') || port.starts_with(b"~")
            || port == b"all" || port == b"auto"
        {
            return Err(bad("only single ports are supported"));
        }
        return Err(bad("bad port"));
    };

    let target = match target {
        None => Target::Tcp { addr: None, port },
        Some([]) => return Err(bad("empty target")),
        Some(t @ ([b'/' | b'@', ..] | [b'.', b'/', ..] | [b'.', b'.', b'/', ..])) => {
            Target::Unix(UnixTarget::parse(t).map_err(|e| bad(&e))?)
        }
        Some(t) => {
            let (addr, toport) = match t.iter().position(|&b| b == b'/') {
                Some(slash) => {
                    let toport = parse_port(&t[slash + 1..]).ok_or_else(|| bad("bad target port"))?;
                    (Some(&t[..slash]), toport)
                }
                None if t.iter().all(u8::is_ascii_digit) => {
                    (None, parse_port(t).ok_or_else(|| bad("bad target port"))?)
                }
                None => (Some(t), port),
            };
            let addr = match addr {
                Some(a) => Some(parse_ip(a).ok_or_else(|| {
                    bad("target must be a port, an IP address, or a Unix socket path \
                         starting with '/', './', '../' or '@'")
                })?),
                None => None,
            };
            // Unspecified target address means automatic, as with pasta
            Target::Tcp { addr: addr.filter(|a| !a.is_unspecified()), port: toport }
        }
    };

    Ok(Some(Forward { port, target }))
}

/// Handle one --tcp-ns option, @none tracks whether "none" was given
fn tcp_ns(cfg: &mut Config, none: &mut bool, spec: &[u8]) -> Result<(), String> {
    match parse_forward(spec)? {
        None => *none = true,
        Some(f) => {
            if let Some(prev) = cfg.forwards.iter().find(|p| p.port == f.port) {
                return Err(format!("port {} forwarded twice: to {} and to {}", f.port,
                                   prev.target, f.target));
            }
            cfg.forwards.push(f);
        }
    }
    if *none && !cfg.forwards.is_empty() {
        return Err("-T none conflicts with other -T options".into());
    }
    Ok(())
}

/// Parse command line arguments (not including argv[0])
///
/// Return: Ok(None) if the program should exit successfully (--help etc.)
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Option<Config>, String> {
    let mut args = args.into_iter();
    let mut cfg = Config { forwards: Vec::new(), debug: false, command: Vec::new() };
    let mut none = false;

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
                tcp_ns(&mut cfg, &mut none, v.as_bytes())?;
            }
            _ if a.starts_with(b"--tcp-ns=") => {
                tcp_ns(&mut cfg, &mut none, &a[b"--tcp-ns=".len()..])?;
            }
            _ if a.starts_with(b"-T") => tcp_ns(&mut cfg, &mut none, &a[2..])?,
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

    if cfg.forwards.len() > crate::fdpass::MAX_FDS {
        return Err(format!("too many listening sockets (maximum {})", crate::fdpass::MAX_FDS));
    }

    Ok(Some(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fwd(spec: &str) -> Forward {
        parse_forward(spec.as_bytes()).unwrap().unwrap()
    }

    fn tcp(spec: &str) -> (u16, Option<IpAddr>, u16) {
        match fwd(spec) {
            Forward { port, target: Target::Tcp { addr, port: to } } => (port, addr, to),
            f => panic!("not a TCP target: {f:?}"),
        }
    }

    #[test]
    fn pasta_syntax() {
        assert!(parse_forward(b"none").unwrap().is_none());
        assert_eq!(tcp("8080"), (8080, None, 8080));
        assert_eq!(tcp("8080:9090"), (8080, None, 9090));
        assert_eq!(tcp("8080:192.0.2.1"), (8080, Some("192.0.2.1".parse().unwrap()), 8080));
        assert_eq!(tcp("8080:192.0.2.1/80"), (8080, Some("192.0.2.1".parse().unwrap()), 80));
        assert_eq!(tcp("8080:::1"), (8080, Some("::1".parse().unwrap()), 8080));
        assert_eq!(tcp("8080:2001:db8::1/80"), (8080, Some("2001:db8::1".parse().unwrap()), 80));
        assert_eq!(tcp("8080:0.0.0.0/80"), (8080, None, 80));
    }

    #[test]
    fn unix_targets() {
        let f = fwd("3128:/run/proxy.sock");
        assert_eq!(f.port, 3128);
        assert!(matches!(f.target, Target::Unix(UnixTarget::Path(ref p)) if p == "/run/proxy.sock"));
        let f = fwd("3128:@proxy:x/y");
        assert!(matches!(f.target, Target::Unix(UnixTarget::Abstract(ref n)) if n == b"proxy:x/y"));
        let f = fwd("3128:./proxy.sock");
        assert!(matches!(f.target, Target::Unix(UnixTarget::Path(ref p)) if p.is_absolute()));
    }

    #[test]
    fn invalid() {
        for spec in ["", "0", "70000", "8080:", "8080:0", "8080:x", "8080:proxy.sock",
                     "8080:192.0.2.1/", "8080:192.0.2.1/x", "8080:[::1]/80",
                     "127.0.0.1/8080", "::1/8080:/a", "%lo/8080", "80-90", "80,81",
                     "~80", "all", "auto"] {
            assert!(parse_forward(spec.as_bytes()).is_err(), "'{spec}' should be invalid");
        }
        let long = format!("1:/{}", "x".repeat(200));
        assert!(parse_forward(long.as_bytes()).is_err());
    }

    #[test]
    fn options() {
        let args = |a: &[&str]| parse(a.iter().map(OsString::from));
        let cfg = args(&["-T", "80", "-T443:8443", "--tcp-ns=22", "--", "true"]).unwrap().unwrap();
        assert_eq!(cfg.forwards.len(), 3);
        assert_eq!(cfg.command, ["true"]);
        assert!(args(&["-T", "none", "true"]).unwrap().unwrap().forwards.is_empty());
        assert!(args(&["-T", "none", "-T", "80"]).is_err());
        assert!(args(&["-T", "80", "-T", "80:81"]).is_err());
    }
}
