// SPDX-License-Identifier: GPL-2.0-or-later

//! Command line parsing

use std::ffi::OsString;
use std::fmt;
use std::mem::{offset_of, size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

pub const USAGE: &str = "\
Usage: specchio [OPTION]... [--] [COMMAND [ARG]...]
       specchio [OPTION]... --netns PATH|NAME
       specchio [OPTION]... [--] PID

Run COMMAND (default: $SHELL) in new user and network namespaces with only a
loopback interface, forwarding TCP connections and UDP datagrams to chosen
ports in the namespace to ports or Unix domain sockets on the host, and from
chosen ports on the host to ports in the namespace.

Options:
  -T, --out-tcp SPEC, --tcp-ns SPEC
                      Forward TCP ports from the namespace to the host
                      (outbound), as with pasta(1), connections to any
                      loopback address in the namespace.  SPEC can be:
                        none          don't forward anything
                        a comma-separated list of:
                          PORTS[:TARGET]
                          ~PORTS      except these ports (applies to the
                                      whole list, which can't consist of
                                      exclusions only)
                      where PORTS is PORT or FIRST-LAST, and TARGET is one of:
                        TOPORTS       same loopback address on the host as
                                      the one connected to in the namespace,
                                      ports TOPORTS (default: PORTS)
                        TOADDR[/TOPORTS]
                                      IP address, ports TOPORTS
                        HOSTNAME[/TOPORTS]
                                      host name, resolved once at start-up
                        /path/to/socket, ./relative/path, @abstract-name
                                      Unix domain socket on the host, for all
                                      PORTS
                      TOPORTS is a port, or a range of the same length as
                      PORTS.  Can be given multiple times
  -U, --out-udp SPEC, --udp-ns SPEC
                      Forward UDP ports from the namespace to the host
                      (outbound), as with pasta(1).  SPEC as for -T, except
                      that Unix domain socket targets aren't supported
  -t, --in-tcp SPEC, --tcp-ports SPEC
                      Forward TCP ports from the host to the namespace
                      (inbound), as with pasta(1).  SPEC can be:
                        none          don't forward anything
                        [ADDR][%IFNAME]/LIST
                        LIST          listen on host address ADDR (default:
                                      all, IPv4 and IPv6), and only on
                                      interface IFNAME if given
                      where LIST is as for -T, except that TARGET is one of:
                        TOPORTS       loopback address in the namespace: the
                                      one connected to on the host if it's a
                                      loopback address, 127.0.0.1 or ::1
                                      otherwise, ports TOPORTS
                        TOADDR[/TOPORTS]
                                      IP address in the namespace
                      Can be given multiple times
  -u, --in-udp SPEC, --udp-ports SPEC
                      Forward UDP ports from the host to the namespace
                      (inbound), as with pasta(1).  SPEC as for -t
                      --tcp-ns, --udp-ns, --tcp-ports and --udp-ports are
                      pasta's names for these options
      --netns PATH|NAME
                      Instead of running COMMAND, forward ports from and to
                      an existing network namespace, at PATH, or at
                      /run/netns/NAME, joining the user namespace that owns
                      it, and run until terminated.  Its loopback interface
                      is brought up, nothing else is changed.  With PID
                      instead of COMMAND, the same for the network namespace
                      of process PID, until it exits
      --root          Run COMMAND as root in the new user namespace, which
                      can configure the network namespace.  By default,
                      COMMAND runs with the user and group IDs specchio was
                      started with, without capabilities
  -d, --debug         Print debugging messages
  -h, --help          Display this help message and exit
      --version       Show version and exit

Examples:
  specchio -T 3128:/run/user/1000/proxy.sock -- \\
      env https_proxy=http://127.0.0.1:3128 curl https://example.com/
  specchio -T 8080,8443 -T 5432:192.0.2.1/5433 -- my-agent
  specchio -T 2222:build.lan/22 -- ssh -p 2222 127.0.0.1
  specchio -T 8000-8099,~8080 -U 53:127.0.0.53 -- my-agent
  specchio -t 127.0.0.1/8080:80 -- python3 -m http.server 80
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

/// Transport protocol of a forward
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        }
    }

    /// Option for forwards of this protocol, inbound or not
    fn opt(self, inbound: bool) -> &'static str {
        match (self, inbound) {
            (Proto::Tcp, false) => "-T",
            (Proto::Udp, false) => "-U",
            (Proto::Tcp, true) => "-t",
            (Proto::Udp, true) => "-u",
        }
    }
}

/// Where to connect to: on the host, or in the namespace for inbound forwards
#[derive(Clone, Debug)]
pub enum Target {
    /// IP port, at @addr, or at a loopback address, see auto_addr()
    Ip { addr: Option<IpAddr>, port: u16 },
    /// Port on host @name, with @addrs filled in by Config::resolve()
    Host { name: String, port: u16, addrs: Vec<SocketAddr> },
    Unix(UnixTarget),
}

impl Target {
    /// The same target, for the port @delta after the first one of a range
    fn shifted(&self, delta: u16) -> Target {
        match self {
            Target::Ip { addr, port } => Target::Ip { addr: *addr, port: port + delta },
            Target::Host { name, port, addrs } => Target::Host {
                name: name.clone(),
                port: port + delta,
                addrs: addrs.iter().map(|a| SocketAddr::new(a.ip(), a.port() + delta)).collect(),
            },
            Target::Unix(u) => Target::Unix(u.clone()),
        }
    }

    /// Describe the target for a range of @n ports after the first one
    fn describe(&self, n: u16) -> String {
        let ports = |p: u16| if n == 0 { p.to_string() } else { format!("{p}-{}", p + n) };
        match self {
            Target::Ip { addr: Some(IpAddr::V6(a)), port } => format!("[{a}]:{}", ports(*port)),
            Target::Ip { addr: Some(a), port } => format!("{a}:{}", ports(*port)),
            Target::Ip { addr: None, port } => format!("port {} on loopback", ports(*port)),
            Target::Host { name, port, .. } => format!("{name}:{}", ports(*port)),
            Target::Unix(u) => u.to_string(),
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.describe(0))
    }
}

/// Target address for Target::Ip without an address: @local, the address a
/// client connected or sent to, if it's a loopback address, the loopback
/// address of the same version otherwise
pub fn auto_addr(local: IpAddr) -> IpAddr {
    match local {
        a if a.is_loopback() => a,
        IpAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
        IpAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
    }
}

/// Where to listen on the host, for inbound forwards
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bind {
    /// Address, None for all addresses (IPv4 and IPv6)
    pub addr: Option<IpAddr>,
    /// Interface name, for SO_BINDTODEVICE
    pub ifname: Option<String>,
}

impl Bind {
    /// Whether the same port could be bound with @self and @other
    fn overlaps(&self, other: &Bind) -> bool {
        match (self.addr, other.addr) {
            (None, _) | (_, None) => true,
            (Some(a), Some(b)) if a.is_unspecified() || b.is_unspecified() => {
                a.is_ipv4() == b.is_ipv4()
            }
            (Some(a), Some(b)) => a == b,
        }
    }
}

impl fmt::Display for Bind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.addr {
            None => f.write_str("*")?,
            Some(IpAddr::V6(a)) => write!(f, "[{a}]")?,
            Some(a) => write!(f, "{a}")?,
        }
        match &self.ifname {
            Some(i) => write!(f, "%{i}"),
            None => Ok(()),
        }
    }
}

/// One forwarding rule: a range of ports to listen on, and its target
#[derive(Clone, Debug)]
pub struct Forward {
    pub proto: Proto,
    /// From the host to the namespace (-t, -u): listen on the host, at
    /// @bind, and connect in the namespace.  Otherwise, listen on any
    /// loopback address in the namespace, and connect on the host
    pub inbound: bool,
    pub bind: Bind,
    pub first: u16,
    pub last: u16,
    /// Target, with the port for @first: further ports map to further ones
    pub target: Target,
}

impl Forward {
    /// Each port of the rule, with its target
    pub fn ports(&self) -> impl Iterator<Item = (u16, Target)> + '_ {
        (self.first..=self.last).map(|p| (p, self.target.shifted(p - self.first)))
    }
}

impl fmt::Display for Forward {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let n = self.last - self.first;
        if n == 0 {
            write!(f, "{} port {}", self.proto.name(), self.first)?;
        } else {
            write!(f, "{} ports {}-{}", self.proto.name(), self.first, self.last)?;
        }
        let (from, to) = if self.inbound { ("host", "namespace") } else { ("namespace", "host") };
        write!(f, " in {from} to {} in {to}", self.target.describe(n))
    }
}

#[derive(Debug)]
pub struct Config {
    pub forwards: Vec<Forward>,
    /// Keep the command root in the sandbox's user namespace
    pub root: bool,
    pub debug: bool,
    /// Attach to this network namespace instead of running a command
    pub netns: Option<PathBuf>,
    /// Attach to the network namespace of this process, until it exits
    pub pid: Option<libc::pid_t>,
    /// Command to run, empty if attaching to a network namespace
    pub command: Vec<OsString>,
}

/// Directory of named network namespaces, as with ip-netns(8) and pasta
const NETNS_RUN_DIR: &str = "/run/netns";


fn parse_port(s: &[u8]) -> Option<u16> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(s).ok()?.parse().ok().filter(|&p| p != 0)
}

/// Parse a port range, FIRST[-LAST], into (FIRST, LAST)
fn parse_range(s: &[u8]) -> Option<(u16, u16)> {
    let (first, last) = match s.iter().position(|&b| b == b'-') {
        Some(dash) => (parse_port(&s[..dash])?, parse_port(&s[dash + 1..])?),
        None => (parse_port(s)?, parse_port(s)?),
    };
    (first <= last).then_some((first, last))
}

/// Parse an IP address, optionally in brackets, as pasta allows
fn parse_ip(s: &[u8]) -> Option<IpAddr> {
    let s = s.strip_prefix(b"[").and_then(|s| s.strip_suffix(b"]")).unwrap_or(s);
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

/// Parse an included chunk of a port specifier: FIRST[-LAST][:TARGET]
///
/// Return: (first, last, target for first port), or an error message
fn parse_chunk(proto: Proto, inbound: bool, chunk: &[u8]) -> Result<(u16, u16, Target), String> {
    let (ports, target) = match chunk.iter().position(|&b| b == b':') {
        Some(colon) => (&chunk[..colon], Some(&chunk[colon + 1..])),
        None => (chunk, None),
    };

    let Some((first, last)) = parse_range(ports) else {
        // pasta's error for [ADDRESS[%IFNAME]/]PORT with -T, otherwise a guess
        if !inbound
            && (ports.contains(&b'/') || ports.contains(&b'%') || parse_ip(ports).is_some())
        {
            return Err(format!("listening address not allowed for {}", proto.opt(inbound)));
        }
        return Err("bad port or port range".into());
    };
    let n = last - first;

    // Target port range, for a range of the same length as the forwarded one
    let to_range = |s: &[u8]| match parse_range(s) {
        Some((tfirst, tlast)) if tlast - tfirst == n => Ok(tfirst),
        Some(_) => Err("target port range must be as long as the forwarded one".to_string()),
        None => Err("bad target port or port range".to_string()),
    };

    let target = match target {
        None => Target::Ip { addr: None, port: first },
        Some([]) => return Err("empty target".into()),
        Some(t @ ([b'/' | b'@', ..] | [b'.', b'/', ..] | [b'.', b'.', b'/', ..])) => {
            if proto == Proto::Udp || inbound {
                return Err(format!("Unix domain socket targets aren't supported for {}",
                                   proto.opt(inbound)));
            }
            Target::Unix(UnixTarget::parse(t)?)
        }
        Some(t) => {
            let (addr, toport) = match t.iter().position(|&b| b == b'/') {
                Some(slash) => (Some(&t[..slash]), to_range(&t[slash + 1..])?),
                None if t.iter().all(|&b| b.is_ascii_digit() || b == b'-') => (None, to_range(t)?),
                None => (Some(t), first),
            };
            match addr.map(|a| (a, parse_ip(a))) {
                // Unspecified target address means automatic, as with pasta
                Some((_, Some(a))) if !a.is_unspecified() => Target::Ip { addr: Some(a), port: toport },
                None | Some((_, Some(_))) => Target::Ip { addr: None, port: toport },
                Some(_) if inbound => {
                    return Err(format!("target must be a port or an IP address in the \
                                        namespace for {}", proto.opt(inbound)));
                }
                Some((a, None)) => Target::Host {
                    name: parse_hostname(a).ok_or("target must be a port, an IP address, a host \
                        name, or a Unix socket path starting with '/', './', '../' or '@'")?,
                    port: toport,
                    addrs: Vec::new(),
                },
            }
        }
    };

    Ok((first, last, target))
}

/// Parse the listening address of an inbound forwarding specification,
/// [ADDR][%IFNAME]/ or *[%IFNAME]/, as parse_addrifname() in pasta does
///
/// Return: listening address and rest of @spec, None if @spec has no
///         listening address, or an error message
fn parse_bind(spec: &[u8]) -> Result<Option<(Bind, &[u8])>, String> {
    let Some(slash) = spec.iter().position(|&b| b == b'/') else { return Ok(None) };
    let (prefix, rest) = (&spec[..slash], &spec[slash + 1..]);
    let (addr, ifname) = match prefix.iter().position(|&b| b == b'%') {
        Some(pct) => (&prefix[..pct], Some(&prefix[pct + 1..])),
        None => (prefix, None),
    };

    let addr = match addr {
        [] | b"*" => None,
        a => match parse_ip(a) {
            Some(a) => Some(a),
            // Otherwise, the slash might be in a target (PORTS:ADDR/PORTS)
            None if prefix.contains(&b':') => return Ok(None),
            None => return Err("bad listening address".into()),
        },
    };
    let ifname = match ifname {
        None => None,
        // Anything but '/' and white space, as in pasta, and not a path
        Some(i) if (1..libc::IFNAMSIZ).contains(&i.len()) && i != b"." && i != b".."
            && !i.iter().any(u8::is_ascii_whitespace) =>
        {
            Some(String::from_utf8(i.to_vec()).map_err(|_| "bad interface name")?)
        }
        Some(_) => return Err("bad interface name".into()),
    };
    Ok(Some((Bind { addr, ifname }, rest)))
}

/// Parse a forwarding specification for -T, -U, -t or -u, see USAGE: a
/// comma-separated list of ports or port ranges with targets, and of excluded
/// ports or port ranges (~FIRST[-LAST]), which apply to the whole list, after
/// a listening address for -t and -u
///
/// Return: None for "none", forwarding rules otherwise
fn parse_forwards(proto: Proto, inbound: bool, spec: &[u8])
                  -> Result<Option<Vec<Forward>>, String> {
    let bad = |why: &str| format!("invalid port specifier '{}': {why}",
                                  String::from_utf8_lossy(spec));

    if spec == b"none" {
        return Ok(None);
    }
    if let Some(why) = wildcard(spec) {
        return Err(bad(&why));
    }

    let (bind, list) = match inbound {
        true => parse_bind(spec).map_err(|e| bad(&e))?.unwrap_or((Bind::default(), spec)),
        false => (Bind::default(), spec),
    };

    let mut excluded = Vec::new();
    let mut included = Vec::new();
    for chunk in list.split(|&b| b == b',') {
        match chunk {
            [b'~', range @ ..] => {
                excluded.push(parse_range(range).ok_or_else(|| bad("bad excluded port range"))?);
            }
            _ => included.push(parse_chunk(proto, inbound, chunk).map_err(|e| bad(&e))?),
        }
    }
    if included.is_empty() {
        // pasta forwards all (non-ephemeral) ports except the excluded ones
        return Err(bad("only exclusions means all other ports, which isn't supported, by \
                        design: forward ports explicitly"));
    }

    let is_excluded = |p: u16| excluded.iter().any(|&(first, last)| (first..=last).contains(&p));
    let mut forwards = Vec::new();
    for (first, last, target) in included {
        // Split the range around excluded ports, as fwd_rule_range_except() does
        let mut port = u32::from(first);
        while port <= u32::from(last) {
            if is_excluded(port as u16) {
                port += 1;
                continue;
            }
            let base = port as u16;
            while port < u32::from(last) && !is_excluded(port as u16 + 1) {
                port += 1;
            }
            forwards.push(Forward { proto, inbound, bind: bind.clone(), first: base,
                                    last: port as u16, target: target.shifted(base - first) });
            port += 1;
        }
    }

    Ok(Some(forwards))
}

/// Handle one option taking a port forwarding specifier
fn add_forwards(cfg: &mut Config, opt: PortOpt, spec: &[u8]) -> Result<(), String> {
    let (proto, inbound) = opt.kind();
    match parse_forwards(proto, inbound, spec)? {
        // As in pasta, "none" only conflicts with rules given before it
        None if cfg.forwards.iter().any(|f| f.proto == proto && f.inbound == inbound) => {
            return Err(format!("{} none conflicts with previous options",
                               proto.opt(inbound)));
        }
        None => {}
        Some(forwards) => {
            for f in forwards {
                let prev = cfg.forwards.iter().find(|p| {
                    p.proto == proto && p.inbound == inbound && p.bind.overlaps(&f.bind)
                        && p.first <= f.last && f.first <= p.last
                });
                if let Some(prev) = prev {
                    let port = f.first.max(prev.first);
                    let side = if inbound { "host" } else { "namespace" };
                    return Err(format!("{} port {port} in {side} forwarded twice: to {} and \
                                        to {}", proto.name(), prev.target.describe(0),
                                       f.target.describe(0)));
                }
                cfg.forwards.push(f);
            }
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

/// Short option, long options: ours, then pasta's
const PORT_OPTS: [(u8, [&str; 2], PortOpt); 4] = [
    (b'T', ["out-tcp", "tcp-ns"], PortOpt::TcpNs),
    (b't', ["in-tcp", "tcp-ports"], PortOpt::TcpPorts),
    (b'u', ["in-udp", "udp-ports"], PortOpt::UdpPorts),
    (b'U', ["out-udp", "udp-ns"], PortOpt::UdpNs),
];

impl PortOpt {
    /// Protocol, and whether forwards are inbound
    fn kind(self) -> (Proto, bool) {
        match self {
            PortOpt::TcpNs => (Proto::Tcp, false),
            PortOpt::UdpNs => (Proto::Udp, false),
            PortOpt::TcpPorts => (Proto::Tcp, true),
            PortOpt::UdpPorts => (Proto::Udp, true),
        }
    }
}

/// Match @arg against an option with a value: -X VALUE, -XVALUE, --name VALUE
/// or --name=VALUE, for any of the names @longs, taking VALUE from @args if
/// needed
///
/// Return: None if @arg isn't this option, its value otherwise, or an error if
///         the value is missing
fn opt_value(arg: &[u8], short: Option<u8>, longs: &[&str],
             args: &mut impl Iterator<Item = OsString>) -> Option<Result<Vec<u8>, String>> {
    let value = match arg {
        [b'-', c] if Some(*c) == short => None,
        [b'-', c, v @ ..] if Some(*c) == short => Some(v.to_vec()),
        [b'-', b'-', rest @ ..] => longs.iter().find_map(|long| {
            match rest.strip_prefix(long.as_bytes())? {
                [] => Some(None),
                [b'=', v @ ..] => Some(Some(v.to_vec())),
                _ => None,
            }
        })?,
        _ => return None,
    };
    Some(match value {
        Some(v) => Ok(v),
        None => args.next().map(|v| v.into_vec()).ok_or_else(|| {
            format!("option requires an argument: {}", String::from_utf8_lossy(arg))
        }),
    })
}

/// Match @arg against options taking a port specifier, see opt_value()
fn port_opt(arg: &[u8], args: &mut impl Iterator<Item = OsString>)
            -> Option<Result<(PortOpt, Vec<u8>), String>> {
    PORT_OPTS.iter().find_map(|&(short, longs, opt)| {
        opt_value(arg, Some(short), &longs, args).map(|v| v.map(|v| (opt, v)))
    })
}

/// Parse command line arguments (not including argv[0])
///
/// Return: Ok(None) if the program should exit successfully (--help etc.)
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Option<Config>, String> {
    let mut args = args.into_iter();
    let mut cfg = Config { forwards: Vec::new(), root: false, debug: false, netns: None, pid: None,
                           command: Vec::new() };

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
            b"--root" => cfg.root = true,
            _ if let Some(v) = opt_value(a, None, &["netns"], &mut args) => {
                let v = PathBuf::from(OsString::from_vec(v?));
                // A name, without '/', or a path, as in pasta
                cfg.netns = Some(match v.as_os_str().as_bytes() {
                    [] => return Err("empty --netns".into()),
                    b if !b.contains(&b'/') => PathBuf::from(NETNS_RUN_DIR).join(v),
                    _ => v,
                });
            }
            _ if let Some(r) = port_opt(a, &mut args) => {
                let (opt, spec) = r?;
                add_forwards(&mut cfg, opt, &spec)?;
            }
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

    // A lone number is a PID, as in pasta
    if let [arg] = cfg.command.as_slice()
        && let a = arg.as_bytes()
        && !a.is_empty() && a.iter().all(u8::is_ascii_digit)
    {
        let pid = std::str::from_utf8(a).ok().and_then(|p| p.parse().ok())
            .filter(|&p: &libc::pid_t| p > 0)
            .ok_or_else(|| format!("invalid PID: {}", arg.to_string_lossy()))?;
        if cfg.netns.is_some() {
            return Err("both --netns and a PID given".into());
        }
        cfg.pid = Some(pid);
        cfg.command.clear();
    }

    if cfg.netns.is_some() || cfg.pid.is_some() {
        if !cfg.command.is_empty() {
            return Err("both --netns and a command given".into());
        }
        if cfg.root {
            return Err("--root is for running a command, not for attaching".into());
        }
    } else if cfg.command.is_empty() {
        cfg.command.push(std::env::var_os("SHELL").unwrap_or_else(|| "/bin/sh".into()));
    }

    Ok(Some(cfg))
}

impl Config {
    /// Resolve host name targets, once: blocking is fine before we start
    pub fn resolve(&mut self) -> Result<(), String> {
        let mut cache: Vec<(String, Vec<IpAddr>)> = Vec::new();
        for f in &mut self.forwards {
            let Target::Host { name, port, addrs } = &mut f.target else { continue };
            let ips = match cache.iter().find(|(n, _)| n == name) {
                Some((_, ips)) => ips,
                None => {
                    let ips = lookup(name)?;
                    let list: Vec<_> = ips.iter().map(IpAddr::to_string).collect();
                    crate::log::debug!("{name} resolves to {}", list.join(", "));
                    cache.push((name.clone(), ips));
                    &cache.last().unwrap().1
                }
            };
            *addrs = ips.iter().map(|&ip| SocketAddr::new(ip, *port)).collect();
        }
        Ok(())
    }
}

/// Look up the addresses of host @name with getaddrinfo()
fn lookup(name: &str) -> Result<Vec<IpAddr>, String> {
    let res = (name, 0).to_socket_addrs();
    let found = res.map_err(|e| {
        // A Unix socket in the current directory, without "./"?
        let hint = if std::path::Path::new(name).exists() {
            format!(" (for the Unix socket in the current directory, use './{name}')")
        } else {
            String::new()
        };
        format!("cannot resolve '{name}': {e}{hint}")
    })?;
    // Keep getaddrinfo()'s order (RFC 6724 and gai.conf), drop duplicates
    let mut ips: Vec<IpAddr> = Vec::new();
    for a in found {
        if !ips.contains(&a.ip()) {
            ips.push(a.ip());
        }
    }
    if ips.is_empty() {
        return Err(format!("cannot resolve '{name}': no addresses"));
    }
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fwds(spec: &str) -> Vec<Forward> {
        parse_forwards(Proto::Tcp, false, spec.as_bytes()).unwrap().unwrap()
    }

    fn fwd(spec: &str) -> Forward {
        let mut f = fwds(spec);
        assert_eq!(f.len(), 1, "{spec}");
        f.pop().unwrap()
    }

    fn ip(spec: &str) -> (u16, Option<IpAddr>, u16) {
        match fwd(spec) {
            Forward { first, last, target: Target::Ip { addr, port: to }, .. } if first == last => {
                (first, addr, to)
            }
            f => panic!("not a single port with IP target: {f:?}"),
        }
    }

    /// Rules for @spec as (first, last, first target port)
    fn ranges(spec: &str) -> Vec<(u16, u16, u16)> {
        fwds(spec).into_iter().map(|f| match f.target {
            Target::Ip { port, .. } | Target::Host { port, .. } => (f.first, f.last, port),
            Target::Unix(_) => (f.first, f.last, 0),
        }).collect()
    }

    fn a(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn pasta_syntax() {
        assert!(parse_forwards(Proto::Tcp, false, b"none").unwrap().is_none());
        assert_eq!(ip("8080"), (8080, None, 8080));
        assert_eq!(ip("8080:9090"), (8080, None, 9090));
        assert_eq!(ip("8080:192.0.2.1"), (8080, a("192.0.2.1"), 8080));
        assert_eq!(ip("8080:192.0.2.1/80"), (8080, a("192.0.2.1"), 80));
        assert_eq!(ip("8080:::1"), (8080, a("::1"), 8080));
        assert_eq!(ip("8080:2001:db8::1/80"), (8080, a("2001:db8::1"), 80));
        assert_eq!(ip("8080:[::1]/80"), (8080, a("::1"), 80));
        assert_eq!(ip("8080:[::1]"), (8080, a("::1"), 8080));
        assert_eq!(ip("8080:[192.0.2.1]/80"), (8080, a("192.0.2.1"), 80));
        assert_eq!(ip("8080:0.0.0.0/80"), (8080, None, 80));
    }

    #[test]
    fn lists_ranges_exclusions() {
        assert_eq!(ranges("80,443"), [(80, 80, 80), (443, 443, 443)]);
        assert_eq!(ranges("8000-8010"), [(8000, 8010, 8000)]);
        assert_eq!(ranges("8000-8010:9000-9010"), [(8000, 8010, 9000)]);
        assert_eq!(ranges("8000-8010:::1/9000-9010"), [(8000, 8010, 9000)]);
        assert_eq!(ranges("8000-8010:a.lan/9000-9010"), [(8000, 8010, 9000)]);
        assert_eq!(ranges("8000-8010:a.lan"), [(8000, 8010, 8000)]);
        assert_eq!(ranges("8000-8010,~8005"), [(8000, 8004, 8000), (8006, 8010, 8006)]);
        assert_eq!(ranges("~8005,8000-8010:9000-9010"), [(8000, 8004, 9000), (8006, 8010, 9006)]);
        assert_eq!(ranges("8000-8010,~8000-8002,~8009-9000"), [(8003, 8008, 8003)]);
        assert_eq!(ranges("1-3,~2,65534-65535,~1"), [(3, 3, 3), (65534, 65535, 65534)]);
        assert_eq!(ranges("80,~443"), [(80, 80, 80)]);
        assert_eq!(ranges("80,~80,443"), [(443, 443, 443)]);
        assert!(fwds("80,~80").is_empty());
        assert_eq!(ranges("8000-8010:/run/x.sock"), [(8000, 8010, 0)]);

        let f = fwds("8000-8002:192.0.2.1/9000-9002");
        let ports: Vec<_> = f[0].ports().map(|(p, t)| (p, t.to_string())).collect();
        assert_eq!(ports, [(8000, "192.0.2.1:9000".into()), (8001, "192.0.2.1:9001".into()),
                           (8002, "192.0.2.1:9002".into())]);
        let mut f = fwd("8000-8001:a.lan/9000-9001");
        f.target = Target::Host { name: "a.lan".into(), port: 9000,
                                  addrs: vec!["[::1]:9000".parse().unwrap()] };
        let Some((8001, Target::Host { port: 9001, addrs, .. })) = f.ports().nth(1) else { panic!() };
        assert_eq!(addrs, ["[::1]:9001".parse().unwrap()]);
        assert_eq!(f.to_string(), "TCP ports 8000-8001 in namespace to a.lan:9000-9001 in host");
    }

    #[test]
    fn host_targets() {
        let host = |spec: &str| match fwd(spec) {
            Forward { first, target: Target::Host { name, port: to, addrs }, .. } => {
                assert!(addrs.is_empty());
                (first, name, to)
            }
            f => panic!("not a host target: {f:?}"),
        };
        assert_eq!(host("2222:build.lan/22"), (2222, "build.lan".into(), 22));
        assert_eq!(host("8080:example.com"), (8080, "example.com".into(), 8080));
        assert_eq!(host("8080:example.com."), (8080, "example.com.".into(), 8080));
        assert_eq!(host("22:x"), (22, "x".into(), 22));
        assert_eq!(host("22:proxy.sock"), (22, "proxy.sock".into(), 22));
        assert_eq!(host("22:_srv.a-b.1x/23"), (22, "_srv.a-b.1x".into(), 23));
        assert!(parse_forwards(Proto::Tcp, false, format!("1:{}.a", "x".repeat(64)).as_bytes()).is_err());
    }

    #[test]
    fn resolve_localhost() {
        let mut forwards = fwds("8080:localhost/80,8081-8082:localhost/81-82");
        forwards.push(fwd("80:192.0.2.1"));
        let mut cfg = Config { forwards, root: false, debug: false, netns: None, pid: None,
                               command: Vec::new() };
        cfg.resolve().unwrap();
        let Target::Host { addrs, .. } = &cfg.forwards[0].target else { panic!() };
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.ip().is_loopback() && a.port() == 80));
        let Target::Host { addrs, .. } = &cfg.forwards[1].target else { panic!() };
        assert!(addrs.iter().all(|a| a.ip().is_loopback() && a.port() == 81));
    }

    #[test]
    fn unix_targets() {
        let f = fwd("3128:/run/proxy.sock");
        assert_eq!(f.first, 3128);
        assert!(matches!(f.target, Target::Unix(UnixTarget::Path(ref p)) if p == "/run/proxy.sock"));
        let f = fwd("3128:@proxy:x/y");
        assert!(matches!(f.target, Target::Unix(UnixTarget::Abstract(ref n)) if n == b"proxy:x/y"));
        let f = fwd("3128:./proxy.sock");
        assert!(matches!(f.target, Target::Unix(UnixTarget::Path(ref p)) if p.is_absolute()));
        // Commas separate list items, also after a socket path
        let f = fwds("3128:/run/a,8080:/run/b");
        assert!(matches!(f[1].target, Target::Unix(UnixTarget::Path(ref p)) if p == "/run/b"));
        assert!(parse_forwards(Proto::Udp, false, b"53:/run/dns.sock").is_err());
    }

    #[test]
    fn invalid() {
        for spec in ["", "0", "70000", "8080:", "8080:0", "8080:x!", "8080:-x", "8080:a..b",
                     "8080:.a", "8080:a-.b", "8080:1.2.3", "8080:300.1.1.1", "8080:0x7f.1",
                     "8080:a.b/x", "8080:a b", "8080:192.0.2.1/", "8080:192.0.2.1/x",
                     "8080:[::1", "8080:[a.b]",
                     "127.0.0.1/8080", "::1/8080:/a", "%lo/8080", "*/80", "all", "auto",
                     "80,", ",80", "80,,81", "90-80", "0-10", "80-", "-80", "80-90-100",
                     "~80", "~80,~90", "~", "~x", "80,~", "8000-8010:9000", "8000-8010:9000-9011",
                     "8000:9000-9001", "8000-8010:::1/9000", "80:/run/a,b", "65535:65534-65535"] {
            assert!(parse_forwards(Proto::Tcp, false, spec.as_bytes()).is_err(),
                    "'{spec}' should be invalid");
        }
        let long = format!("1:/{}", "x".repeat(200));
        assert!(parse_forwards(Proto::Tcp, false, long.as_bytes()).is_err());
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
        assert!(args(&["-T", "80-90", "-T", "85:81"]).is_err());
        assert!(args(&["-T", "80,80"]).is_err());
        assert!(args(&["-T", "80-90,85"]).is_err());
        assert!(args(&["-T"]).is_err());
        assert!(!args(&["true"]).unwrap().unwrap().root);
        let cfg = args(&["--root", "-T", "80", "id", "--root"]).unwrap().unwrap();
        assert!(cfg.root);
        assert_eq!(cfg.command, ["id", "--root"]);

        // TCP and UDP rules are separate
        let cfg = args(&["-T", "53", "-U", "53", "-U", "123,500-501", "-T", "none"]);
        assert!(cfg.is_err(), "-T none after -T");
        let cfg = args(&["-T", "53", "-U", "53", "-U", "123,500-501", "true"]).unwrap().unwrap();
        let udp: Vec<_> = cfg.forwards.iter().filter(|f| f.proto == Proto::Udp)
            .map(|f| (f.first, f.last)).collect();
        assert_eq!(udp, [(53, 53), (123, 123), (500, 501)]);
        assert!(args(&["-U", "53", "-U", "53"]).is_err());
        assert!(args(&["-U", "none", "-U", "53", "-T", "none", "true"]).is_ok());
        assert!(args(&["-U", "53", "-U", "none"]).is_err());
        assert!(args(&["-U", "53", "--udp-ns=none"]).is_err());
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

        for bad in [&["-U"][..], &["--tcp-ports"], &["--tcp-portsnone"]] {
            assert!(args(bad).is_err(), "{bad:?} should be invalid");
        }
    }

    /// Inbound rules for @spec, as (listening address, first, last, target)
    fn inbound(proto: Proto, spec: &str) -> Vec<(String, u16, u16, String)> {
        parse_forwards(proto, true, spec.as_bytes()).unwrap().unwrap().into_iter()
            .map(|f| {
                assert!(f.inbound);
                (f.bind.to_string(), f.first, f.last, f.target.to_string())
            })
            .collect()
    }

    #[test]
    fn inbound_syntax() {
        let any = |first, last, t: &str| ("*".to_string(), first, last, t.to_string());
        let lo = "port 80 on loopback";
        assert_eq!(inbound(Proto::Tcp, "80"), [any(80, 80, lo)]);
        assert_eq!(inbound(Proto::Tcp, "8080:80"), [any(8080, 8080, lo)]);
        assert_eq!(inbound(Proto::Tcp, "80:127.0.0.2"), [any(80, 80, "127.0.0.2:80")]);
        assert_eq!(inbound(Proto::Tcp, "8080:127.0.0.2/80"), [any(8080, 8080, "127.0.0.2:80")]);
        assert_eq!(inbound(Proto::Tcp, "8080:[::1]/80"), [any(8080, 8080, "[::1]:80")]);
        assert_eq!(inbound(Proto::Tcp, "80:0.0.0.0"), [any(80, 80, lo)]);
        assert_eq!(inbound(Proto::Udp, "8000-8010,~8005"),
                   [any(8000, 8004, "port 8000 on loopback"),
                    any(8006, 8010, "port 8006 on loopback")]);
        assert_eq!(inbound(Proto::Udp, "5000-5001:6000-6001"),
                   [any(5000, 5001, "port 6000 on loopback")]);

        let bound = |spec| inbound(Proto::Tcp, spec).into_iter().map(|r| r.0).collect::<Vec<_>>();
        assert_eq!(bound("127.0.0.1/80"), ["127.0.0.1"]);
        assert_eq!(bound("[::1]/80"), ["[::1]"]);
        assert_eq!(bound("::1/80"), ["[::1]"]);
        assert_eq!(bound("0.0.0.0/80"), ["0.0.0.0"]);
        assert_eq!(bound("::/80"), ["[::]"]);
        assert_eq!(bound("*/80"), ["*"]);
        assert_eq!(bound("/80"), ["*"]);
        assert_eq!(bound("%eth0/80"), ["*%eth0"]);
        assert_eq!(bound("*%eth0/80"), ["*%eth0"]);
        assert_eq!(bound("192.0.2.1%eth0/80"), ["192.0.2.1%eth0"]);
        assert_eq!(bound("fe80::1%eth0/80"), ["[fe80::1]%eth0"]);
        assert_eq!(bound("192.0.2.1/20-30,~25"), ["192.0.2.1", "192.0.2.1"]);
        let r = inbound(Proto::Tcp, "192.0.2.1/5000:::1/6000");
        assert_eq!(r, [("192.0.2.1".into(), 5000, 5000, "[::1]:6000".into())]);
        // The slash is in the target, not after a listening address
        assert_eq!(bound("5000:127.0.0.1/6000"), ["*"]);
        assert_eq!(bound("5000:::1/6000"), ["*"]);

        for spec in ["x/80", "1.2.3/80", "%/80", "%./80", "%../80", "%0123456789abcdef/80",
                     "%a b/80", "127.0.0.1/", "127.0.0.1/x", "80:/run/a.sock", "80:@a",
                     "80:localhost", "80:a.lan/90", "~80", "127.0.0.1/~80", "127.0.0.1/all",
                     "auto", "80/90", "20-30,~25:127.0.0.1"] {
            assert!(parse_forwards(Proto::Tcp, true, spec.as_bytes()).is_err(),
                    "-t '{spec}' should be invalid");
        }
        assert!(parse_forwards(Proto::Tcp, false, b"127.0.0.1/80").unwrap_err()
                .contains("listening address not allowed for -T"));
        assert!(parse_forwards(Proto::Udp, true, b"53:/run/a").unwrap_err()
                .contains("aren't supported for -u"));
    }

    #[test]
    fn netns() {
        let args = |a: &[&str]| parse(a.iter().map(OsString::from));
        let cfg = args(&["--netns", "/proc/1/ns/net", "-T", "80"]).unwrap().unwrap();
        assert_eq!(cfg.netns.unwrap(), PathBuf::from("/proc/1/ns/net"));
        assert!(cfg.command.is_empty());
        let cfg = args(&["--netns=ctr", "-t", "80"]).unwrap().unwrap();
        assert_eq!(cfg.netns.unwrap(), PathBuf::from("/run/netns/ctr"));
        let cfg = args(&["--netns", "./ns"]).unwrap().unwrap();
        assert_eq!(cfg.netns.unwrap(), PathBuf::from("./ns"));
        let cfg = args(&["-T", "80", "1234"]).unwrap().unwrap();
        assert_eq!((cfg.pid, cfg.netns, cfg.command.len()), (Some(1234), None, 0));
        let cfg = args(&["--", "42"]).unwrap().unwrap();
        assert_eq!(cfg.pid, Some(42));
        let cfg = args(&["42", "x"]).unwrap().unwrap();
        assert_eq!((cfg.pid, cfg.command.len()), (None, 2));
        for bad in [&["0"][..], &["99999999999"], &["--netns", "x", "1"], &["--root", "1"]] {
            assert!(args(bad).is_err(), "{bad:?} should be invalid");
        }
        for bad in [&["--netns"][..], &["--netns="], &["--netns", "x", "true"],
                    &["--netns", "x", "--", "true"], &["--root", "--netns", "x"], &["--netnsx"]] {
            assert!(args(bad).is_err(), "{bad:?} should be invalid");
        }
    }

    #[test]
    fn long_names() {
        let args = |a: &[&str]| parse(a.iter().map(OsString::from));
        let cfg = args(&["--out-tcp", "80", "--out-udp=81", "--in-tcp=82", "--in-udp", "83",
                         "--tcp-ns", "84", "--udp-ns=85", "--tcp-ports=86", "--udp-ports", "87",
                         "true"]).unwrap().unwrap();
        let rules: Vec<_> = cfg.forwards.iter().map(|f| (f.proto, f.inbound, f.first)).collect();
        assert_eq!(rules, [(Proto::Tcp, false, 80), (Proto::Udp, false, 81), (Proto::Tcp, true, 82),
                           (Proto::Udp, true, 83), (Proto::Tcp, false, 84), (Proto::Udp, false, 85),
                           (Proto::Tcp, true, 86), (Proto::Udp, true, 87)]);
        assert_eq!(cfg.command, ["true"]);
        // Synonyms are the same option: "none" conflicts with earlier rules
        assert!(args(&["--in-tcp", "80", "--tcp-ports=none"]).is_err());
        assert!(args(&["-T", "80", "--out-tcp", "80"]).is_err());
        for bad in [&["--in-tcpx=80"][..], &["--in-tc=80"], &["--out-tcp"], &["--in"]] {
            assert!(args(bad).is_err(), "{bad:?} should be invalid");
        }
        let e = args(&["--in-udp"]).unwrap_err();
        assert_eq!(e, "option requires an argument: --in-udp");
    }

    #[test]
    fn inbound_options() {
        let args = |a: &[&str]| parse(a.iter().map(OsString::from));
        let cfg = args(&["-t", "80", "-T", "80", "-u", "80", "-U", "80", "--tcp-ports=81",
                         "--udp-ports", "127.0.0.1/82", "true"]).unwrap().unwrap();
        let rules: Vec<_> = cfg.forwards.iter().map(|f| (f.proto, f.inbound, f.first)).collect();
        assert_eq!(rules, [(Proto::Tcp, true, 80), (Proto::Tcp, false, 80), (Proto::Udp, true, 80),
                           (Proto::Udp, false, 80), (Proto::Tcp, true, 81), (Proto::Udp, true, 82)]);
        assert_eq!(cfg.forwards[0].to_string(),
                   "TCP port 80 in host to port 80 on loopback in namespace");

        // Same port on different addresses is fine, not on overlapping ones
        assert!(args(&["-t", "127.0.0.1/80", "-t", "127.0.0.2/80", "-t", "::1/80", "true"]).is_ok());
        assert!(args(&["-t", "0.0.0.0/80", "-t", "::/80", "true"]).is_ok());
        assert!(args(&["-t", "%eth0/80", "-t", "%eth1/81", "true"]).is_ok());
        for bad in [&["-t", "80", "-t", "127.0.0.1/80"][..], &["-t", "127.0.0.1/80", "-t", "80"],
                    &["-t", "0.0.0.0/80", "-t", "127.0.0.1/79-81"], &["-t", "::/80", "-t", "::1/80"],
                    &["-t", "127.0.0.1/80", "-t", "127.0.0.1/80:81"], &["-u", "80", "-u", "none"],
                    &["-t", "80", "--tcp-ports=none"]] {
            assert!(args(bad).is_err(), "{bad:?} should be invalid");
        }
        assert!(args(&["-t", "none", "-t", "80", "-T", "80", "-T", "none", "true"]).is_err());
        assert!(args(&["-t", "none", "-t", "80", "-T", "none", "-u", "none", "true"]).is_ok());
    }

    #[test]
    fn auto_addresses() {
        let auto = |a: &str| auto_addr(a.parse().unwrap()).to_string();
        assert_eq!(auto("127.0.0.5"), "127.0.0.5");
        assert_eq!(auto("::1"), "::1");
        assert_eq!(auto("192.0.2.1"), "127.0.0.1");
        assert_eq!(auto("2001:db8::1"), "::1");
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
        for opt in ["-T", "-U"] {
            let e = parse([opt, "~80"].iter().map(OsString::from)).unwrap_err();
            assert!(e.contains("by design"), "{opt} ~80: {e}");
        }
    }
}
