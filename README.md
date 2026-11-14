# specchio

*Specchio* (Italian for "mirror") is a narrowly scoped relative of `pasta`
from [passt](https://passt.top/). It runs a command in new user and network
namespaces where only `lo` exists, and forwards chosen TCP ports inside them
to TCP ports on the host or other hosts, or to Unix domain sockets on the
host, and chosen UDP ports to UDP ports on the host or other hosts. It also
forwards chosen TCP and UDP ports on the host to ports inside the namespaces.
TCP data moves only by `splice()`, and there is no TAP interface, no packet
parsing and no `fork()` per connection. This covers all of `pasta`'s
splicing (TCP and UDP, in both directions).

The intended use is sandboxing: give a sandboxed agent access to, say, an
HTTP(S) proxy as an object capability. The agent can reach the forwarded port
and nothing else, and needs no credentials.

```sh
specchio -T 3128:/run/user/1000/proxy.sock -- \
    env https_proxy=http://127.0.0.1:3128 agent ...
```

specchio only isolates the network: for the filesystem and the rest, nest
`bwrap` or similar inside it (`specchio ... -- bwrap ... -- agent ...`).

### `-T`, `--tcp-ns`

This uses `pasta`'s syntax; `-T` can be repeated:

| Spec | In the namespace | Connects to on the host |
|---|---|---|
| `-T none` | nothing | |
| `-T 80,443` | ports 80 and 443 | the same ports (each item of a list can have its own target) |
| `-T 8000-8010` | ports 8000 to 8010 | the same ports |
| `-T 8000-8010:9000-9010` | same | ports 9000 to 9010 (8000 → 9000, 8001 → 9001, ...) |
| `-T 8000-8010,~8005` | ports 8000 to 8004 and 8006 to 8010 | the same ports (exclusions apply to the whole list) |
| `-T 8080` | any loopback address, port 8080 | the same loopback address (`127.0.0.5` → `127.0.0.5`, `::1` → `::1`), port 8080 |
| `-T 8080:9090` | same | the same loopback address, port 9090 |
| `-T 8080:192.0.2.1` | same | `192.0.2.1`, port 8080 |
| `-T 8080:192.0.2.1/9090` | same | `192.0.2.1`, port 9090 (also `[2001:db8::1]/9090` or `2001:db8::1/9090`; ranges as above) |
| `-T 2222:build.lan/22` | same | `build.lan`, resolved at start-up, port 22 (`-T 22:build.lan` for port 22 to 22) |
| `-T 3128:/run/proxy.sock` | same | Unix socket (also `./rel/path`, `../rel/path`; `@name` for abstract sockets; `8000-8010:/run/proxy.sock` for all ports of a range) |

As in `pasta`, `-T none` is an error after other `-T` options, but not
before them, and a port can't be forwarded twice. `pasta` command lines like
`pasta -t none -u none -U none -T 8080 -- ...` work unchanged.

### `-U`, `--udp-ns`

The same syntax as `-T`, for UDP, except that Unix domain socket targets
aren't supported. `-U` and `-T` can forward the same port. As in `pasta`, a
flow is a client address and port in the namespace sending to a forwarded
port: each flow gets its own socket on the host, connected to the target, and
replies to that socket go back to the client, from the address and port it
sent to. A flow expires after 30 s without datagrams, or 120 s once it has
seen more than one datagram in either direction and at least one reply
(`pasta`'s defaults; it reads them from `nf_conntrack_udp_timeout` and
`nf_conntrack_udp_timeout_stream`). Datagrams are copied with
`recvmmsg()`/`sendmmsg()`, as in `pasta`: `splice()` doesn't apply to them.

Compared to `pasta`:

- `auto` and `all` aren't supported, and won't be: they forward whatever the
  sandbox happens to listen on, or every port, and the point of specchio is
  to grant access explicitly.

- A list of exclusions only (`-T ~80`) means all other (non-ephemeral) ports
  in `pasta`, so it's rejected, like `all`.
- As with `pasta`, a listening address (`ADDR/PORT`) isn't allowed for `-T`
  and `-U`. specchio listens on all addresses (dual-stack), bound to `lo` with
  `SO_BINDTODEVICE`.
- The target address is honoured. `pasta` parses it for `-T`, but
  `fwd_nat_from_splice()` ignores it and always uses the same loopback
  address. It can be any address, of the host or another host: specchio
  connects from the host's network namespace, as any other process there
  would. Unspecified addresses (`0.0.0.0`, `::`) mean "automatic", as in
  `pasta`.
- Host name targets are a specchio extension. Names are resolved once, with
  `getaddrinfo()` (so `/etc/hosts` and the rest of NSS apply), before the
  sandbox starts, and an unresolvable name is an error. The addresses aren't
  looked up again while specchio runs. Each connection tries them in the
  order `getaddrinfo()` gives (RFC 6724, `gai.conf`) until one connects.
  An address that doesn't answer at all holds a connection up until the
  kernel gives up on it (`tcp_syn_retries`, about two minutes by default);
  there's no Happy Eyeballs. For UDP, a new flow uses the first address it
  can `connect()` to, which only fails without a route: an address that
  turns out not to answer, or to refuse datagrams (ICMP port unreachable),
  isn't replaced by the next one. A name is dot-separated labels of letters,
  digits, `-` and `_`; one whose last label is numeric is rejected as a
  mistyped IPv4 address.
- UDP flows aren't bound to the client's address and port on the host side:
  the kernel picks them, as for TCP. `pasta` binds them to the same loopback
  address and port as the client in the namespace (`fwd_nat_from_splice()`),
  which wouldn't work for targets on other hosts, and fails if that port is in
  use on the host. Replies to the namespace go out through the socket
  receiving on the forwarded port, with the source address set by
  `IP_PKTINFO`/`IPV6_PKTINFO`; `pasta` instead creates a socket per flow in
  the namespace, which specchio could only do by joining its user namespace
  (see "How it works"). The same goes for replies to clients on the host,
  with `-u`, which saves a socket per flow. ICMP errors
  from the target (such as port unreachable) aren't relayed to the client,
  which sees no reply, as with `pasta`'s spliced flows.
- Unix domain socket targets are a specchio extension. A target starting with
  `/`, `./`, `../` or `@` can't be a port or an address in `pasta`'s syntax.
  Without such a prefix, `proxy.sock` is a host name: if resolving it fails
  and a file of that name exists, the error message suggests `./proxy.sock`.

### `-t`, `--tcp-ports`

Forwards TCP ports on the host to ports in the namespace, also with `pasta`'s
syntax, and lists, ranges and exclusions as for `-T`:

| Spec | Listens on the host | Connects to in the namespace |
|---|---|---|
| `-t 8080` | all addresses (IPv4 and IPv6), port 8080 | the same loopback address if one was connected to on the host (`127.0.0.5` → `127.0.0.5`, `::1` → `::1`), `127.0.0.1` or `::1` otherwise, port 8080 |
| `-t 8080:8000` | same | same, port 8000 |
| `-t 8080:127.0.0.2` | same | `127.0.0.2`, port 8080 |
| `-t 8080:127.0.0.2/8000` | same | `127.0.0.2`, port 8000 (also `[::1]/8000` or `::1/8000`) |
| `-t 127.0.0.1/8080` | `127.0.0.1` only, port 8080 | `127.0.0.1`, port 8080 |
| `-t 0.0.0.0/8080`, `-t ::/8080` | all IPv4, or all IPv6 addresses only | as for `-t 8080` |
| `-t %eth0/8080`, `-t 192.0.2.1%eth0/8080` | as without `%eth0`, on interface `eth0` only (`SO_BINDTODEVICE`) | same |

- As with `pasta`, `-t 8080` listens on all addresses, so other hosts can
  connect, unless a firewall stops them. Use `-t 127.0.0.1/8080` (or
  `-t ::1/8080`) to accept local connections only. For servers, socket
  activation is an alternative: the command inherits listening sockets from
  systemd, which `pasta` doesn't allow (see below), and specchio isn't
  involved at all.
- The listening sockets are created before the command starts: if a port is
  taken, or below `net.ipv4.ip_unprivileged_port_start`, specchio exits
  without running it.
- Ports below 1024 in the namespace: by default, the command has no
  capabilities, and can't listen on them. Use a higher port, or `--root`.
- The target is always a loopback address in the namespace, as only `lo`
  exists there. For spliced connections, `pasta` connects to the namespace's
  address on its other interface instead, unless `--host-lo-to-ns-lo` is
  given and the connection was to a loopback address on the host: specchio
  does the same as that option, and uses `127.0.0.1` or `::1` for
  connections to other addresses. Host names and Unix domain sockets aren't
  allowed as targets.
- The command sees connections coming from a loopback address in the
  namespace, from a port the kernel picks, as with `pasta`'s spliced
  connections.

### `-u`, `--udp-ports`

The same syntax as `-t`, for UDP. Flows work as for `-U`, the other way
around: each flow, from a client address and port on the host, gets a socket
in the namespace, connected to the target, and replies to it go back to the
client from the address and port it sent to. As for `-U`, that socket isn't
bound to the client's source port, unlike in `pasta`: the kernel picks one.

With no command, specchio runs `$SHELL`. The command inherits all of
specchio's open files, such as sockets from systemd socket activation. Once
the command is started, specchio itself drops them: it points standard input
and output to `/dev/null` and closes the rest, keeping only standard error for
its messages. So a reader of the command's output sees EOF as soon as the
command closes it, not only once specchio exits. (`pasta` instead closes
everything except standard streams at startup, so the command never gets
them.) It exits with the command's exit
status (128 + signal number if the command was killed).

The command runs with the user and group IDs specchio was started with, and
without capabilities, so programs (and users) aren't misled into thinking
they run as root. Supplementary groups show up as the overflow group
(`nobody`), as they aren't mapped. With `--root`, the command runs as root in
the new user namespace instead, with all capabilities there: it can configure
the network namespace, but gains no privileges outside it. If specchio is
started as root (in whatever user namespace), the command stays root.

## How it works

1. **Child (`sandbox.rs`)**: `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, maps the
   original UID/GID to root (a fixed one-line map), brings `lo` up, and
   creates a listening (TCP) or receiving (UDP) socket for each port forwarded
   from the namespace. Unless `--root` is given, it then creates a nested user
   namespace, mapping the original UID/GID to root of the first one, so that
   the command runs with its original IDs, and loses all capabilities when
   `exec`ed. It sends the sockets to the parent with `SCM_RIGHTS` over a
   `socketpair`, at most 253 per message, closes them, waits for the parent
   to be ready, and `exec`s the command.
   A socket stays in the network namespace it was created in, so the parent
   needs no capabilities and never enters the namespace (unlike `pasta`, which
   uses `setns()`), unless it forwards from the host (see below). The command
   can't get at the listeners afterwards: they're closed before `exec`, and
   the parent lives in the outer user namespace, so the command can't
   `ptrace` it or use `pidfd_getfd()` on it.
2. **Parent (`main.rs`, `splice.rs`)**: a single-threaded epoll loop accepts
   connections, connects to the target (for a TCP target without an address,
   the namespace side's local address from `getsockname()`), and splices both
   directions through a pipe pair. The connection state machine is ported from `tcp_splice.c`
   (`SPLICE_CONNECT`, `OUT_WAIT_n`, `FIN_RCVD_n`, `FIN_SENT_n`, the pipe pool,
   and `SPLICE_F_MORE`/`TCP_NODELAY` corking). The parent waits for the command
   with a pidfd, and the child gets `PR_SET_PDEATHSIG`, so neither outlives the
   other.
3. **From the host (`ns.rs`)**: inbound connections and UDP flows need a
   socket in the namespace each, created while the command runs. So the child also sends a
   descriptor for its network namespace, and the parent makes itself
   non-dumpable and joins the sandbox's user namespace (the one owning the
   network namespace, found with `NS_GET_USERNS`) while it's still
   single-threaded: entering a network namespace needs `CAP_SYS_ADMIN` in
   one's own user namespace. Then, like `pasta`, it keeps pools of sockets
   created in the network namespace (32 of each kind in use), refilled
   between batches of events by a short-lived thread that enters it with
   `setns()`. The main thread never leaves the host's network namespace. As
   it's not dumpable, the command can't `ptrace` it or take its descriptors,
   even as root in that user namespace. See `notes/user-ns.md`.
4. **UDP (`udp.rs`)**: datagrams from the namespace are read in batches with
   `recvmmsg()`, along with their source address and their destination
   address (`IP_PKTINFO`/`IPV6_PKTINFO`), which identify the flow (in a hash
   table). Each flow has a host side socket, `connect()`ed to the target, and
   polled for replies. Flows that expired are closed once per second. Flows
   from the host work the same way, with sockets for the target taken from
   the pools in the namespace.

TCP connections (six descriptors each: two sockets and two pipes) and UDP
flows (one socket each) share the descriptor limit. When it's reached, TCP
listeners stop accepting connections, and datagrams of new UDP flows are
dropped.

### Differences from `tcp_splice.c`

- **`EPOLLHUP` isn't fatal.** A Unix socket whose peer closed reports
  `EPOLLHUP` (shut down in both directions) while unread data may still be
  queued on it, or still sit in our pipe. `tcp_splice.c` resets the connection
  on `EPOLLHUP`, which loses that data. Here the socket is taken out of epoll
  (`EPOLLHUP` can't be masked) and drained when the other side becomes
  writable. As a consequence, `forward()` also no longer treats `EAGAIN` from
  the read side as "socket empty" when the pipe had data: the pipe may have
  been full. TCP sets `EPOLLHUP` under the same condition, so `pasta` might be
  affected too; that hasn't been checked.
- **`connect()` retries.** A non-blocking `connect()` to a Unix socket with a
  full listen backlog fails with `EAGAIN`, and nothing notifies us when there's
  room again. specchio retries with exponential backoff (1 ms to 100 ms) and
  gives up after 5 s. For TCP, `EAGAIN` means no free local ports, and is
  retried in the same way.
- `SO_RCVLOWAT` handling is left out, since `tcp_splice.c` no longer enables
  it anyway.

## Not yet done

- **Hardening**: seccomp, dropping the filesystem view like `pasta`'s
  `isolate_prefork()`. For path targets, that needs `O_PATH` directory handles
  opened at startup, then `fchdir()` plus `connect()` with a relative name.
- Abstract socket targets have no access control: any process in the host
  network namespace can listen on that name. Prefer filesystem sockets.

## Testing

```sh
cargo test               # unit tests (argument parsing)
cargo build --release && tests/run.sh   # end-to-end, needs python3 and socat
```

`tests/udp_client.py` binds its socket explicitly before sending: with
Python 3.14.10, `recvfrom()` on a socket bound implicitly by `sendto()`
returns a bogus source address (family 0), even without specchio.

Throughput with `dd | socat` over host loopback, 8 GB: about 4.4 GB/s for a
direct connection, `pasta --splice-only -T` and specchio alike.

## Licence

GPL-2.0-or-later. `src/splice.rs` is derived from `tcp_splice.c` in passt,
Copyright (c) 2020-2022 Red Hat GmbH, author Stefano Brivio.
