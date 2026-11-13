// SPDX-License-Identifier: GPL-2.0-or-later

//! Command line parsing

use std::ffi::OsString;
use std::fmt;
use std::mem::{offset_of, size_of, zeroed};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
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
                                      IP address, port TOPORT (default: PORT)
                        HOSTNAME[/TOPORT]
                                      host name, resolved once at start-up
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
  specchio -T 2222:build.lan/22 -- ssh -p 2222 127.0.0.1
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
    /// TCP port on host @name, with @addrs filled in by Config::resolve()
    Host { name: String, port: u16, addrs: Vec<SocketAddr> },
    Unix(UnixTarget),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Target::Tcp { addr: Some(a), port } => write!(f, "{}", SocketAddr::new(*a, *port)),
            Target::Tcp { addr: None, port } => write!(f, "port {port} on loopback"),
            Target::Host { name, port, .. } => write!(f, "{name}:{port}"),
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

/// Check that @s looks like a host name: dot-separated labels of letters,
/// digits, '-' and '_' (seen in practice), optionally ending with a dot
fn parse_hostname(s: &[u8]) -> Option<String> {
    let name = s.strip_suffix(b".").unwrap_or(s);
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let label_ok = |l: &[u8]| {
        (1..=63).contains(&l.len()) && !l.starts_with(b"-") && !l.ends_with(b"-")
            && l.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if !name.split(|&b| b == b'.').all(label_ok) {
        return None;
    }
    // A numeric last label means a mistyped IPv4 address, not a name: don't
    // let getaddrinfo() make one of it (inet_aton() takes "10.1" or "0x7f.1")
    let last = name.rsplit(|&b| b == b'.').next()?;
    if last.iter().all(u8::is_ascii_digit) {
        return None;
    }
    String::from_utf8(s.to_vec()).ok()
}

/// Find "auto" or "all" in a port specifier: [ADDR/]{auto,all[:TOADDR]},...
///
/// Return: an error message if found
fn wildcard(spec: &[u8]) -> Option<String> {
    for chunk in spec.split(|&b| b == b',') {
        let rest = match chunk.iter().position(|&b| b == b'/') {
            Some(slash) => &chunk[slash + 1..],
            None => chunk,
        };
        let keyword = rest.split(|&b| b == b':').next().unwrap_or(rest);
        if keyword == b"auto" || keyword == b"all" {
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
        if port.contains(&b'-') || port.contains(&b',') || port.starts_with(b"~") {
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
            match addr.map(|a| (a, parse_ip(a))) {
                // Unspecified target address means automatic, as with pasta
                Some((_, Some(a))) if !a.is_unspecified() => {
                    Target::Tcp { addr: Some(a), port: toport }
                }
                None | Some((_, Some(_))) => Target::Tcp { addr: None, port: toport },
                Some((a, None)) => Target::Host {
                    name: parse_hostname(a).ok_or_else(|| {
                        bad("target must be a port, an IP address, a host name, or a Unix \
                             socket path starting with '/', './', '../' or '@'")
                    })?,
                    port: toport,
                    addrs: Vec::new(),
                },
            }
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

impl Config {
    /// Resolve host name targets, once: blocking is fine before we start
    pub fn resolve(&mut self) -> Result<(), String> {
        for f in &mut self.forwards {
            let Target::Host { name, port, addrs } = &mut f.target else { continue };
            let res = (name.as_str(), *port).to_socket_addrs();
            let mut found: Vec<SocketAddr> = res.map_err(|e| {
                // A Unix socket in the current directory, without "./"?
                let hint = if std::path::Path::new(name.as_str()).exists() {
                    format!(" (for the Unix socket in the current directory, use './{name}')")
                } else {
                    String::new()
                };
                format!("cannot resolve '{name}': {e}{hint}")
            })?.collect();
            // Keep getaddrinfo()'s order (RFC 6724 and gai.conf), drop duplicates
            let mut seen = Vec::new();
            found.retain(|a| { let new = !seen.contains(a); seen.push(*a); new });
            if found.is_empty() {
                return Err(format!("cannot resolve '{name}': no addresses"));
            }
            *addrs = found;
        }
        Ok(())
    }
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
    fn host_targets() {
        let host = |spec: &str| match fwd(spec) {
            Forward { port, target: Target::Host { name, port: to, addrs } } => {
                assert!(addrs.is_empty());
                (port, name, to)
            }
            f => panic!("not a host target: {f:?}"),
        };
        assert_eq!(host("2222:build.lan/22"), (2222, "build.lan".into(), 22));
        assert_eq!(host("8080:example.com"), (8080, "example.com".into(), 8080));
        assert_eq!(host("8080:example.com."), (8080, "example.com.".into(), 8080));
        assert_eq!(host("22:x"), (22, "x".into(), 22));
        assert_eq!(host("22:proxy.sock"), (22, "proxy.sock".into(), 22));
        assert_eq!(host("22:_srv.a-b.1x/23"), (22, "_srv.a-b.1x".into(), 23));
        assert!(parse_forward(format!("1:{}.a", "x".repeat(64)).as_bytes()).is_err());
    }

    #[test]
    fn resolve_localhost() {
        let mut cfg = Config { forwards: vec![fwd("8080:localhost/80"), fwd("80:192.0.2.1")],
                               debug: false, command: Vec::new() };
        cfg.resolve().unwrap();
        let Target::Host { addrs, .. } = &cfg.forwards[0].target else { panic!() };
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.ip().is_loopback() && a.port() == 80));
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
        for spec in ["", "0", "70000", "8080:", "8080:0", "8080:x!", "8080:-x", "8080:a..b",
                     "8080:.a", "8080:a-.b", "8080:1.2.3", "8080:300.1.1.1", "8080:0x7f.1",
                     "8080:a.b/x", "8080:a b", "8080:192.0.2.1/", "8080:192.0.2.1/x",
                     "8080:[::1]/80",
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
    fn wildcards() {
        for spec in ["auto", "::1/auto", "8000-8010,auto", "all", "all:192.0.2.1",
                     "127.0.0.6/all:192.0.2.6", "::1/all", "~80,all"] {
            for opt in ["-T", "-t", "-u", "-U"] {
                let e = parse([opt, spec].iter().map(OsString::from)).unwrap_err();
                assert!(e.contains("by design"), "{opt} {spec}: {e}");
            }
        }
    }
}
