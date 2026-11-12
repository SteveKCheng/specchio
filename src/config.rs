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
  -t, --tcp-ports none
  -u, --udp-ports none
  -U, --udp-ns none   Accepted for compatibility with pasta(1): no inbound
                      or UDP forwarding is supported yet
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

/// Find "auto" in a port specifier: [ADDR/]auto,...
///
/// Return: an error message if found
fn wildcard(spec: &[u8]) -> Option<String> {
    for chunk in spec.split(|&b| b == b',') {
        let rest = match chunk.iter().position(|&b| b == b'/') {
            Some(slash) => &chunk[slash + 1..],
            None => chunk,
        };
        let keyword = rest.split(|&b| b == b':').next().unwrap_or(rest);
        if keyword == b"auto" {
            return Some(format!("'{}' isn't supported, by design: forward ports explicitly",
                                String::from_utf8_lossy(keyword)));
        }
    }
    None
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
    if let Some(why) = wildcard(spec) {
        return Err(bad(&why));
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
            || port == b"all"
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

/// Handle one --tcp-ns option
fn tcp_ns(cfg: &mut Config, spec: &[u8]) -> Result<(), String> {
    match parse_forward(spec)? {
        // As in pasta, "none" only conflicts with rules given before it
        None if !cfg.forwards.is_empty() => {
            return Err("-T none conflicts with previous options".into());
        }
        None => {}
        Some(f) => {
            if let Some(prev) = cfg.forwards.iter().find(|p| p.port == f.port) {
                return Err(format!("port {} forwarded twice: to {} and to {}", f.port,
                                   prev.target, f.target));
            }
            cfg.forwards.push(f);
        }
    }
    Ok(())
}

/// Options taking a port forwarding specifier, as in pasta
#[derive(Clone, Copy, PartialEq, Eq)]
enum PortOpt {
    TcpNs,
    TcpPorts,
    UdpPorts,
    UdpNs,
}

const PORT_OPTS: [(u8, &str, PortOpt); 4] = [
    (b'T', "tcp-ns", PortOpt::TcpNs),
    (b't', "tcp-ports", PortOpt::TcpPorts),
    (b'u', "udp-ports", PortOpt::UdpPorts),
    (b'U', "udp-ns", PortOpt::UdpNs),
];

impl PortOpt {
    fn long(self) -> &'static str {
        PORT_OPTS.iter().find(|(_, _, o)| *o == self).map_or("", |(_, l, _)| l)
    }
}

/// Match @arg against an option with a value: -X VALUE, -XVALUE, --name VALUE
/// or --name=VALUE, taking VALUE from @args if needed
///
/// Return: None if @arg isn't this option, its value otherwise, or an error if
///         the value is missing
fn opt_value(arg: &[u8], short: u8, long: &str, args: &mut impl Iterator<Item = OsString>)
             -> Option<Result<Vec<u8>, String>> {
    let value = match arg {
        [b'-', c] if *c == short => None,
        [b'-', c, v @ ..] if *c == short => Some(v.to_vec()),
        [b'-', b'-', rest @ ..] if rest == long.as_bytes() => None,
        [b'-', b'-', rest @ ..] if rest.starts_with(long.as_bytes())
            && rest.get(long.len()) == Some(&b'=') => Some(rest[long.len() + 1..].to_vec()),
        _ => return None,
    };
    Some(match value {
        Some(v) => Ok(v),
        None => args.next().map(|v| v.into_vec())
            .ok_or_else(|| format!("option requires an argument: --{long}")),
    })
}

/// Match @arg against options taking a port specifier, see opt_value()
fn port_opt(arg: &[u8], args: &mut impl Iterator<Item = OsString>)
            -> Option<Result<(PortOpt, Vec<u8>), String>> {
    PORT_OPTS.iter().find_map(|&(short, long, opt)| {
        opt_value(arg, short, long, args).map(|v| v.map(|v| (opt, v)))
    })
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
            _ if let Some(r) = port_opt(a, &mut args) => match r? {
                (PortOpt::TcpNs, spec) => tcp_ns(&mut cfg, &spec)?,
                // No-ops for now, only "none" is accepted
                (_, spec) if spec == b"none" => {}
                (opt, spec) => {
                    let why = wildcard(&spec).unwrap_or_else(|| "not supported yet".into());
                    return Err(format!("invalid --{} '{}': {why}", opt.long(),
                                       String::from_utf8_lossy(&spec)));
                }
            },
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
        assert_eq!(args(&["-T", "none", "-T", "80"]).unwrap().unwrap().forwards.len(), 1);
        assert!(args(&["-T", "80", "-T", "none"]).is_err());
        assert!(args(&["-T", "80", "-T", "80:81"]).is_err());
        assert!(args(&["-T"]).is_err());
    }

    #[test]
    fn none_options() {
        let args = |a: &[&str]| parse(a.iter().map(OsString::from));
        let cfg = args(&["-t", "none", "-unone", "--udp-ns", "none", "--tcp-ports=none",
                         "--udp-ports=none", "-Unone", "-T", "none", "--tcp-ns=none", "true"])
            .unwrap().unwrap();
        assert!(cfg.forwards.is_empty());
        assert_eq!(cfg.command, ["true"]);

        let cfg = args(&["-t", "none", "-T", "8080", "-U", "none", "true"]).unwrap().unwrap();
        assert_eq!(cfg.forwards.len(), 1);

        for bad in [&["-t", "80"][..], &["-u", "53"], &["--udp-ns=53"], &["-U"], &["--tcp-ports"],
                    &["--tcp-portsnone"]] {
            assert!(args(bad).is_err(), "{bad:?} should be invalid");
        }
    }

    #[test]
    fn auto() {
        for spec in ["auto", "::1/auto", "8000-8010,auto"] {
            for opt in ["-T", "-t", "-u", "-U"] {
                let e = parse([opt, spec].iter().map(OsString::from)).unwrap_err();
                assert!(e.contains("by design"), "{opt} {spec}: {e}");
            }
        }
    }
}
