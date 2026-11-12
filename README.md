# specchio

*Specchio* (Italian for "mirror") is a narrowly scoped relative of `pasta`
from [passt](https://passt.top/). It runs a command in new user and network
namespaces where only `lo` exists, and forwards chosen TCP ports inside them
to Unix domain sockets on the host. Data moves only by `splice()`, and there
is no TAP interface, no packet parsing and no `fork()` per connection.

The intended use is sandboxing: give a sandboxed agent access to, say, an
HTTP(S) proxy as an object capability. The agent can reach the forwarded port
and nothing else, and needs no credentials.

```sh
specchio -T 3128:/run/user/1000/proxy.sock -- \
    bwrap --dev-bind / / --unshare-user --uid "$(id -u)" --gid "$(id -g)" -- \
    env https_proxy=http://127.0.0.1:3128 agent ...
```

`-T [ADDR/]PORT:TARGET` can be repeated. `TARGET` is a path, or `@name` for an
abstract socket. Without `ADDR`, specchio listens on `127.0.0.1` and, if
available, `::1`. With no command, specchio runs `$SHELL`. specchio exits with
the command's exit status (128 + signal number if it was killed).

## How it works

1. **Child (`sandbox.rs`)**: `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, maps the
   original UID/GID to root (a fixed one-line map), brings `lo` up, creates the
   listening sockets, and sends them to the parent with `SCM_RIGHTS` over a
   `socketpair`. It then closes them and `exec`s the command.
   A socket stays in the network namespace it was created in, so the parent
   needs no capabilities and never enters the namespace (unlike `pasta`, which
   uses `setns()`). The command can't get at the listeners afterwards: they're
   closed before `exec`, and the parent lives in the outer user namespace, so
   the command can't `ptrace` it or use `pidfd_getfd()` on it.
2. **Parent (`main.rs`, `splice.rs`)**: a single-threaded epoll loop accepts
   connections, connects to the target, and splices both directions through a
   pipe pair. The connection state machine is ported from `tcp_splice.c`
   (`SPLICE_CONNECT`, `OUT_WAIT_n`, `FIN_RCVD_n`, `FIN_SENT_n`, the pipe pool,
   and `SPLICE_F_MORE`/`TCP_NODELAY` corking). The parent waits for the command
   with a pidfd, and the child gets `PR_SET_PDEATHSIG`, so neither outlives the
   other.

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
  gives up after 5 s.
- `SO_RCVLOWAT` handling is left out, since `tcp_splice.c` no longer enables
  it anyway.

## Not yet done

- **Inbound forwarding** (host port to sandbox). This needs sockets created in
  the sandbox namespace on demand, and a pool sent at startup can't be refilled
  once the child has `exec`'d. Options: keep a small helper process in the
  namespace that makes sockets on request over the same `socketpair`, or have
  the parent join the sandbox user namespace and `setns()` from a thread
  (network `setns()` is per-thread).
- **Hardening**: seccomp, dropping the filesystem view like `pasta`'s
  `isolate_prefork()`. For path targets, that needs `O_PATH` directory handles
  opened at startup, then `fchdir()` plus `connect()` with a relative name.
- Abstract socket targets have no access control: any process in the host
  network namespace can listen on that name. Prefer filesystem sockets.
- The command runs as root in the new user namespace, holding all capabilities
  there. Nest `bwrap` (as above) to drop that.

## Testing

```sh
cargo test               # unit tests (argument parsing)
cargo build --release && tests/run.sh   # end-to-end, needs python3 and socat
```

## Licence

GPL-2.0-or-later. `src/splice.rs` is derived from `tcp_splice.c` in passt,
Copyright (c) 2020-2022 Red Hat GmbH, author Stefano Brivio.
