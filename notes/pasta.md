# Findings about `pasta`, and why specchio exists

Notes from investigating whether `pasta` (from [passt](https://passt.top/))
could be extended to splice sandbox connections to host Unix domain sockets,
before we decided to write specchio instead. Collected 2026-11-12.

Source references to passt are as of upstream `6aa4f88` 
("passt-repair: Suppress false positive cppcheck negativeIndex warning"). 
Line numbers will drift for other versions.

Contents:

1. [Earlier Q&A with Gemini, annotated](#1-earlier-qa-with-gemini-annotated)
2. [What makes Unix domain sockets hard in `pasta`](#2-what-makes-unix-domain-sockets-hard-in-pasta)
3. [How `pasta` reaches into the sandbox, and what specchio does instead](#3-how-pasta-reaches-into-the-sandbox-and-what-specchio-does-instead)
4. [No tokio: port `tcp_splice.c` instead](#4-no-tokio-port-tcp_splicec-instead)
5. [`pasta` closes inherited descriptors too early](#5-pasta-closes-inherited-descriptors-too-early)
6. [Other things found along the way](#6-other-things-found-along-the-way)

---

## 1. Earlier Q&A with Gemini, annotated

The original Q&A was conducted on the possibility of modifying `pasta`.
We reproduce it here to records what we considered before going off to 
write our own tool. Gemini's answers are
kept as they were, except that wrong or misleading parts are ~~struck
through~~, each followed by a **Correction**. Parts that were checked and
found right are left alone, sometimes with a **Note**.

Overall verdict: the high-level ideas hold up (splice works on any stream
socket, an L4 proxy loses the client's address, avoiding async DNS keeps
things simple), but the answers assume `pasta`'s code is more flexible than
it is, and they miss the two things that actually make Unix domain socket
targets hard: `pasta`'s filesystem isolation and `pesto` (section 2).

### 1.1 [2026-10-31] Splicing incoming connections on non-loopback interfaces

**Query (summary).** The splice path is only used for inbound connections
from the host's *loopback* interface (`fwd_nat_from_host()` in `fwd.c`). With
`--splice-only` and no TAP interface, could inbound connections from other
interfaces be spliced too, rewriting the source address to loopback inside the
sandbox? Is that the only thing blocking it?

**Gemini's answer:**

> Your intuition is exactly right. The strict restriction in
> `fwd_nat_from_host()`—specifically the `inany_is_loopback(&ini->eaddr)`
> check—is indeed what prevents external host interfaces from utilizing the
> `splice()` optimization.
>
> **The Transparency Problem (Why the restriction exists)**
>
> By design, `passt` and `pasta` aim to be transparent Layer-2/Layer-3
> translators. When a connection comes in from an external machine (say,
> `192.168.1.42`), `pasta` wants the application inside your sandbox to see
> `192.168.1.42` as the source IP address.
>
> To accomplish this without root privileges, `pasta` parses the L4 payload,
> rebuilds the TCP/IP headers with the original source IP, and feeds raw
> packets through the TAP interface.
>
> If `pasta` were to use the `splice()` path for external connections, it
> would act as a traditional Layer-4 proxy (like `socat` or Docker's userland
> proxy). It would accept the connection on the host, create a brand-new
> socket *inside* the namespace, and splice the file descriptors together.
> ~~Because the inner socket is created by `pasta` from within the namespace,
> the sandboxed application would see the connection originating from
> localhost (`127.0.0.1`), permanently losing the real external client IP.~~
>
> **Correction:** the client's address is lost, but by default the sandboxed
> application doesn't see `127.0.0.1`. For spliced inbound connections `pasta`
> connects to the namespace's *public* address and lets the kernel pick the
> source, so the application sees its own public address as the peer. Only
> with `--host-lo-to-ns-lo` does it connect to (and come from) loopback
> (`fwd_nat_from_host()`, `fwd.c` around line 1060; "Handling of local
> traffic" in `passt.1`). `--splice-only` turns `--host-lo-to-ns-lo` on
> implicitly (`conf.c` around line 1828).
>
> ~~The authors restricted splicing to the loopback interface because loopback
> traffic already originates from `127.0.0.1`. Splicing it doesn't destroy any
> meaningful source IP information, so the optimization is entirely "free."~~
>
> **Correction:** the man page gives the reason: "Because it's not possible
> to bind sockets to foreign addresses, this bypass only applies to local
> connections and traffic." And, as above, spliced loopback connections don't
> keep `127.0.0.1` as the source by default either.
>
> **Why your `--splice-only` solution works**
>
> As you pointed out, if you run with `--splice-only`, you are explicitly
> choosing not to create a TAP interface. In this mode:
> 1. The sandbox can't see external source IPs anyway because there is no TAP
>    interface to deliver spoofed packets.
> 2. The sandbox is inherently simpler and lighter.
> 3. You just want port forwarding to work.
>
> If the `inany_is_loopback()` restriction were bypassed when `--splice-only`
> is active, `pasta` would seamlessly fall back to behaving like a standard L4
> proxy for external traffic. ~~The kernel inside the namespace would simply
> assign a local source IP to the inner connection, and `splice()` would
> shuttle the bytes flawlessly.~~
>
> **Correction:** not quite "simply". With `--splice-only` the namespace has
> only `lo`, so the target address must be a loopback address too. For a
> connection that arrived on a non-loopback host address, the
> `host_lo_to_ns_lo` branch in `fwd_nat_from_host()` doesn't apply (it only
> keeps the destination when it is already loopback), so the target falls
> back to the namespace's public address, which doesn't exist without a TAP
> interface. The NAT logic would need a new case mapping such connections to
> namespace loopback.
>
> **Pitching it upstream**
>
> This is an excellent feature request for the upstream `passt/pasta` project.
>
> ~~The codebase actually shows that the maintainers are already thinking about
> expanding this path.~~ Right above the loopback check in `fwd.c`, there is a
> telling comment:
> ```c
> /* TODO: Allow splicing with specified target address */
> if (!c->no_splice && inany_is_unspecified(&rule->taddr) &&
>     inany_is_loopback(&ini->eaddr) && ...
> ```
>
> **Correction:** the comment exists (`fwd.c:1054`), but it's about a
> different restriction: rules with an explicit *target address*
> (`-t 8080:192.0.2.1`) never take the splice path. It says nothing about
> sources from non-loopback interfaces.
>
> When you suggest this to the upstream mailing list or bug tracker, frame it
> as allowing `pasta` to act as a **pure L4 proxy** for external connections
> when `--splice-only` is passed (or via a new flag like `--splice-external`).
> Since users requesting this mode explicitly prioritize low overhead and
> sandbox simplicity over source-IP preservation, removing the loopback
> restriction for that specific path perfectly serves the use case.

### 1.2 [2026-10-31] Restrictions on the file descriptors that `splice(2)` works with

**Query (summary).** `splice(2)` says one of the descriptors must be a pipe,
yet `pasta` uses it between sockets. Are there kernel restrictions that would
block the feature?

**Gemini's answer:**

> You caught a very specific and important detail in the kernel
> documentation. The `splice(2)` manual page is completely accurate: the
> system call strictly requires that at least one of the file descriptors
> refers to a pipe.
>
> To get around this and transfer data between two TCP sockets, Linux network
> tools (including `HAProxy`, ~~`socat`,~~ and `pasta`) use a standard
> "pipe-in-the-middle" pattern.
>
> **Correction:** `socat` doesn't use `splice()`; it copies with
> `read()`/`write()` (no reference to `splice` in `/usr/bin/socat` on this
> system). That's part of why specchio exists.
>
> Here is how it works under the hood:
> 1. The application asks the kernel to create a standard pipe, which returns
>    two file descriptors: a write-end and a read-end.
> 2. The application executes a `splice()` call to move data from the incoming
>    socket into the pipe's write-end.
> 3. The application executes a second `splice()` call to move that data from
>    the pipe's read-end into the outgoing socket.
>
> Even though this requires two system calls instead of one, the data never
> actually leaves kernel space, preserving the massive performance benefits of
> zero-copy networking.
>
> The `passt`/`pasta` project already fully implements this architecture. If
> you look at its splicing subsystem (specifically `tcp_splice.c`), the
> application doesn't just create pipes on the fly. It actually initializes
> and maintains a pre-allocated pool of pipe file descriptors specifically to
> act as these middlemen without incurring setup latency for new connections.
>
> **Note:** right. `TCP_SPLICE_PIPE_POOL_SIZE` is 32, refilled by
> `tcp_splice_pipe_refill()`. Each connection takes two pipes, one per
> direction. specchio does the same.
>
> Because `pasta` already maintains this intermediate pipe pool to satisfy the
> kernel's requirements for loopback traffic, your `--splice-only` feature
> would not require any new kernel capabilities. `pasta` would simply hand the
> external socket file descriptors to its existing pipe pool, meaning there
> are no Linux kernel blockers preventing your proposal from working.
>
> ~~[How to Use splice() Correctly](https://www.youtube.com/watch?v=7rx9J0LON8Q)~~
>
> ~~This video breakdown of standard input and UNIX sockets visually explains
> how developers utilize intermediary pipes to satisfy the `splice()` system
> call's requirements.~~
>
> **Correction:** unverified link (we couldn't fetch it from the sandbox), and
> the description doesn't match the title. Treat it as possibly made up.

### 1.3 [2026-10-31] Could socket splicing be extended to arbitrary outbound TCP/IP connections?

**Query (summary).** Could `--tcp-ns ‹guest-port›:‹foreign-ip›/‹foreign-port›`
make `pasta` connect to a remote machine without a TAP interface, like
reverse port forwarding, replacing `socat` + `pasta`?

**Gemini's answer:**

> It is highly technically feasible, as this reverse L4 proxy behavior is
> essentially a mirror image of `pasta`'s existing loopback splicing
> architecture. Implementing this would bypass the TAP interface completely
> and hook directly into the zero-copy infrastructure you were just looking
> at.
>
> From a socket programming and architecture perspective, `pasta` is
> perfectly positioned to do this because it already orchestrates
> non-blocking sockets across namespace boundaries using `epoll` and
> `setns()`.
>
> Here is what the technical implementation would require under the hood:
>
> * **Namespace Boundary Switching:** `pasta` already has the utility
>   functions to hop between the host and the sandbox network namespaces. For
>   your feature, `pasta` would bind a listening socket on `guest-port`
>   *inside* the namespace.
>
>   **Note:** this already happens for every `-T` port; nothing new needed.
>
> * **The State Machine Mirror:** When the `epoll` loop detects an `accept()`
>   event on that guest socket, ~~`pasta` would switch to the host namespace,~~
>   create a new non-blocking socket, and call `connect()` targeting
>   `foreign-ip:foreign-port`.
>
>   **Correction:** `pasta`'s main process never leaves the host namespace;
>   it only enters the sandbox's in short-lived helper tasks (section 3).
>   The host-side socket is created directly, from a pre-opened pool
>   (`tcp_conn_sock()`).
>
> * ~~**Asynchronous Connection Handling:** Because `pasta` is strictly
>   single-threaded and non-blocking, that `connect()` call will likely return
>   `EINPROGRESS`. You would need to add a minor extension to the TCP
>   connection state machine (in `tcp_splice.c`) to track this outbound
>   connection attempt in the `epoll` loop until it receives `EPOLLOUT`,
>   signaling the connection to the foreign IP is established.~~
>
>   **Correction:** nothing to add: `tcp_splice.c` already has this state
>   (`SPLICE_CONNECT`, `EINPROGRESS` handled in `tcp_splice_connect()`, line
>   ~401, completed by `tcp_splice_connect_finish()` on `EPOLLOUT`).
>
> * **Plugging into the Pipe Pool:** Once the connection is established, you
>   simply hand both file descriptors—the accepted guest socket and the
>   connected host socket—straight into `pasta`'s existing intermediate pipe
>   pool. The kernel handles the `splice()` forwarding from there, with zero
>   L2/L3 packet parsing overhead.
>
> The main technical constraint to watch out for is name resolution. Because
> `pasta` relies on a single-threaded event loop, calling standard libc
> `getaddrinfo()` to resolve a hostname for the foreign address would block
> the entire application. As long as you restrict the configuration argument
> strictly to IP addresses (as you noted with `foreign-ip-address`), you
> avoid the need to implement asynchronous DNS resolution, making the patch
> relatively straightforward C code.
>
> This approach cleanly eliminates the need for managing orphaned `socat`
> background processes and keeps the sandbox boundary tightly controlled
> within a single binary.

**What Gemini missed:** the syntax the query asks for already exists.
`pasta` parses `-T PORT:ADDR/PORT` (`parse_port_chunk()` in `fwd_rule.c`)
and stores the address in `rule->taddr`, but `fwd_nat_from_splice()`
(`fwd.c:948`) ignores it: it only accepts loopback-to-loopback connections
and always targets the loopback address used in the namespace. So the
smallest version of this feature is mostly in the NAT step, not the state
machine. specchio honours the target address, but restricts it to addresses
of host interfaces (checked at startup), which keeps the "no external hosts"
scope.

### 1.4 [2026-11-06] How about splicing outbound connections into Unix domain sockets?

**Query (summary).** Async host name lookup is a mess, so drop that. Instead,
how about a host Unix domain socket as the target, so sandbox-scoped services
(like an HTTP(S) proxy) become an object capability, with no credentials
injected into the agent?

**Gemini's answer:**

> Bridging a sandboxed TCP port directly to a host UNIX domain socket is not
> just technically feasible, it is structurally cleaner than TCP-to-TCP port
> forwarding and perfectly aligns with a strict capability-based security
> model.
>
> From a Linux systems programming perspective, this is a highly elegant
> solution that bypasses the async DNS disaster entirely. Here is why the
> mechanics work seamlessly with `pasta`'s existing architecture:
>
> **1. `splice()` Is Agnostic to the Socket Domain**
>
> The Linux kernel treats `AF_UNIX` stream sockets (`SOCK_STREAM`) exactly
> like `AF_INET` TCP sockets when it comes to the `splice()` system call.
> Once the connection is established, the file descriptor for the UNIX
> domain socket can be handed straight to `pasta`'s existing pre-allocated
> pipe pool. ~~The zero-copy pump will shuttle bytes between the guest's TCP
> socket and the host's UDS with absolutely zero modifications required to
> the core `tcp_splice.c` data path.~~
>
> **Correction:** `splice()` itself is fine with `AF_UNIX`, but the state
> machine around it isn't. Found while porting it to specchio:
>
> - A Unix socket whose peer has closed reports `EPOLLHUP` while unread data
>   may still be queued on it, or still sit in our pipe. `tcp_splice.c` resets
>   the connection on `EPOLLHUP` (line 659), losing the tail of the data: 2 of
>   20 bulk transfers failed in testing. specchio stops polling such a socket
>   and keeps draining it instead.
> - `tcp_splice_forward()` treats `EAGAIN` on the read side as "socket empty"
>   even when it could mean "pipe full", relying on `EPOLLIN` firing again.
>   That breaks once the socket is no longer polled.
> - TCP-only socket options (`TCP_QUICKACK`, and `TCP_NODELAY`, used to flush
>   after corking) are set on both sides. On a Unix socket they fail; that's
>   harmless (`pasta` only logs it), but the code should know which side is
>   TCP. specchio skips them for Unix sockets.
>
> **2. Synchronous Path Resolution vs. Async Network Resolution**
>
> You completely avoid the `getaddrinfo` thread-pool problem. Calling
> `connect()` on a UNIX domain socket only involves local filesystem path
> resolution (or abstract namespace lookup). Even if you use a non-blocking
> socket, `connect()` typically succeeds immediately unless the listen
> backlog on the host proxy is full—~~in which case it cleanly yields `EAGAIN`
> or `EINPROGRESS` to `pasta`'s `epoll` event loop.~~
>
> **Correction:** a full backlog gives `EAGAIN`, and nothing is cleanly
> yielded: epoll can't tell you when the backlog has room again (an
> unconnected socket immediately reports `EPOLLOUT | EPOLLHUP`).
> `tcp_splice_connect()` treats anything but `EINPROGRESS` as an error and
> resets the connection. specchio retries with backoff (1 ms to 100 ms, for
> up to 5 s); `socat`'s backlog of 5 triggered this with only 50 concurrent
> clients.
>
> Also missing: with filesystem paths, the resolution happens in `pasta`'s
> own mount namespace, which by then is an empty tmpfs (section 2.1).
>
> **3. Straightforward C Implementation**
>
> ~~Modifying `pasta` to support this would primarily touch the configuration
> parser and the connection initiator:~~
>
> **Correction:** much more is involved; see section 2. In short: the
> filesystem isolation, the `pesto` protocol, `struct fwd_rule`,
> `fwd_nat_from_splice()` (loopback only), and flow table code that assumes
> both sides of a flow have IP addresses and ports (`struct flowside`,
> flow hashing and logging).
>
> * **The Parser:** When parsing the `--tcp-ns` argument, if the target
>   string begins with `/` (for filesystem sockets) or `@` (for Linux
>   abstract namespace sockets), the parser flags it as a UDS target.
>
>   **Note:** that's what specchio does (also `./` and `../`). These can't
>   be mistaken for a port or address in `pasta`'s syntax.
>
> * **The Initiator:** Instead of populating a `struct sockaddr_in`, the
>   host-side connection factory allocates a `struct sockaddr_un`, copies the
>   path into `sun_path`, calls `socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK,
>   0)`, and executes the `connect()`.
>
> **Architectural Synergy for Sandboxing**
>
> This approach is exceptionally powerful for unprivileged sandboxing. By
> routing traffic this way, the AI agent inside the namespace only sees a
> standard TCP endpoint (e.g., `127.0.0.1:8080`). It requires no injected
> credentials, no host filesystem access, and no ambient network routing.
>
> ~~Using the Linux abstract namespace (e.g., `@my-agent-proxy`) for the UDS
> is particularly useful here.~~ Abstract sockets do not leave orphaned files
> on the host filesystem if the proxy crashes, which makes tearing down
> ephemeral AI agent environments significantly cleaner. You can launch your
> mitmproxy or HTTP proxy on the host bound to an abstract UDS, start the
> sandbox with `pasta` bridging a guest port to that UDS, and ~~entirely
> control the agent's egress traffic via that single, unprivileged object
> capability.~~
>
> **Correction:** abstract sockets work against the object-capability model.
> They have no access control: any process in the host's network namespace
> can connect to the name, or bind it first if the proxy isn't running yet.
> (The sandbox itself can't reach them, since abstract names are scoped to a
> network namespace.) Filesystem sockets, protected by directory permissions,
> are the better choice; abstract ones would need the proxy to check
> `SO_PEERCRED`. One real advantage of abstract sockets for `pasta`: being
> per network namespace, not per mount namespace, they'd still be reachable
> after `pasta`'s filesystem isolation (section 2.1).

---

## 2. What makes Unix domain sockets hard in `pasta`

Both points below were missed in Gemini's analysis. Together with the
additional work in 1.4, they made us judge that the change was more work than
expected and unlikely to be accepted upstream as is.

### 2.1 Filesystem isolation

`pasta` sandboxes *itself* (not the command it starts, which is why this
isn't visible when you mount host directories into the sandbox). The startup
order:

1. `conf()` calls `pasta_start_ns()` (`conf.c:1949`), which forks the
   command. The command keeps a normal view of the filesystem.
2. `isolate_prefork()` (`passt.c:426`, `isolation.c:477`) then runs in the
   `pasta` process: it unshares new mount, IPC, UTS (and PID) namespaces,
   mounts an empty read-only tmpfs and `pivot_root()`s into it
   (`isolation.c:511`), detaching the old root.
3. `isolate_postfork()` applies a seccomp allowlist built from the
   `#syscalls` comments in each source file.

So while forwarding, `pasta` can't see any file: `connect()` to
`/run/user/1000/proxy.sock` would fail with `ENOENT`. Ways around it:

- **Open a directory handle before isolating** (best option): open the
  socket's parent directory with `O_PATH` during `conf()`, then at connect
  time `fchdir()` into it and `connect()` with the bare name. `pasta` then
  holds a capability to one directory instead of ambient filesystem access,
  and it sidesteps the 108-byte `sun_path` limit. Needs `fchdir` in the
  seccomp list.
- **Abstract sockets**: unaffected by the mount namespace (see 1.4), but no
  access control.
- **Bind-mount the socket into the tmpfs** before `pivot_root()`: clumsier.

specchio doesn't isolate its own filesystem view yet, so it connects to paths
directly. If it adopts `pasta`-style hardening, the directory-handle approach
is the plan (see the README's "Not yet done").

### 2.2 `pesto` has to understand the forwarding rules too

`pesto` (`pesto.c`, protocol in `pesto.h`) is a client that changes `pasta`'s
forwarding rules at run time, over a control socket. It isn't incremental:

- It reads `pasta`'s whole rule table (`pesto.c:228`) and writes the whole
  table back.
- `pasta` clears the pending table and refills it from what `pesto` sends
  (`conf.c:2206`, `conf.c:2211`).

So a rule `pesto` can't represent would be silently deleted by any `pesto`
update. UDS support couldn't simply be left out of `pesto`; at least it must
pass such rules through unchanged. Also, rules from `pesto` arrive after
isolation, so `pasta` couldn't resolve a new path from them anyway; only
command line rules could use filesystem paths.

A workable design would keep UDS targets (directory handle plus name) in a
separate table in `pasta`, store only a flag and an index in
`struct fwd_rule`, let `pesto` treat that as opaque, and reject `pesto` rules
referring to an unknown index. Changing `struct fwd_rule` means raising
`PESTO_PROTOCOL_VERSION` (now 2; `pesto.h` says v1 to v2 was done without
backwards compatibility).

specchio has no run-time rule changes at all (by design: no `pesto`, no
`-T auto` port scanning), so this doesn't apply to it.

---

## 3. How `pasta` reaches into the sandbox, and what specchio does instead

Key fact: a socket belongs to the network namespace that was current when
`socket()` was called, for its whole life, whoever holds the descriptor.
Nothing is "injected" into the sandbox; the forwarder just holds sockets that
live in the sandbox's namespace.

### Option A: what `pasta` does

1. **Keeps a handle to the namespace.** `pasta_start_ns()` starts the command
   in new namespaces, and `pasta_wait_for_ns()` opens `/proc/<pid>/ns/net`
   into `c->pasta_netns_fd` (`pasta.c:108`).
2. **Enters it briefly, from a helper task.** `NS_CALL()` (`util.h:122`) runs
   a function in a throwaway task made with
   `clone(CLONE_VM | CLONE_VFORK | CLONE_FILES)`. The task calls
   `setns(pasta_netns_fd, CLONE_NEWNET)` (`ns_enter()`, `util.c:374`),
   creates the socket and exits. Thanks to `CLONE_FILES` the descriptor lands
   in `pasta`'s table. The main process never leaves the host namespace.
3. **Listening sockets in the sandbox** for `-T` are made this way, also later
   ones from `pesto` or `-T auto` scanning (`fwd_listen_sync()`, `fwd.c:483`).
4. **Spliced connections:** `pasta` accepts on the sandbox-side listener in
   its epoll loop, then connects a host socket taken from a pool made in the
   host namespace. For the inbound direction it takes a socket from a pool
   pre-created in the sandbox namespace (`tcp_sock_refill_ns()`), refilled
   via `NS_CALL()` as needed.
5. To keep calling `setns()` after startup, `pasta` keeps `CAP_SYS_ADMIN` in
   its user namespace (`isolation.c:533`).

In Rust, Option A wouldn't need the `clone()` trick: `setns(CLONE_NEWNET)`
only affects the calling thread, so a thread could `setns()`, create the
socket and hand back an `OwnedFd`. But only after the whole process has
joined the sandbox's user namespace: see `user-ns.md`.

### Option B: what specchio does

specchio has a fixed set of listeners known at startup, so the child sets
everything up itself before `exec`ing the command (`src/sandbox.rs`):

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, then write a fixed one-line map
   of the original UID/GID to root (so the child has `CAP_NET_ADMIN` there).
2. Bring `lo` up (`SIOCSIFFLAGS`).
3. Create the listening sockets: one per `-T` port, dual-stack, bound to `lo`
   with `SO_BINDTODEVICE`.
4. Unless `--root` is given, create a nested user namespace mapping the
   original UID/GID to root of the first one, so that the command runs with
   its original IDs and without capabilities (see `user-ns.md`, section 5).
5. Send the sockets to the parent with `SCM_RIGHTS` over a `socketpair`,
   followed by a descriptor for the network namespace if there's inbound
   forwarding.
6. Close the sockets, wait for the parent to be ready, and `exec` the
   command.

Compared to Option A:

- The parent needs no namespace handle, and doesn't enter the namespaces, as
  long as it only forwards from the sandbox to the host. Inbound forwarding
  changes this, and what it means for the parent's privileges and isolation
  is covered in `user-ns.md`.
- It matches the object-capability idea literally: the parent holds the
  listeners and the targets, nothing else.
- The command can't reach the listeners: they're closed before `exec`, and the
  parent is out of reach of `ptrace` and `pidfd_getfd()` (see `user-ns.md`
  for how that holds once the parent joins the sandbox's user namespace).
- The cost: no new sockets in the sandbox namespace after `exec`. That matters
  for **inbound** forwarding (`-t`), which needs a sandbox-side socket per
  connection, and a pool sent at startup can't be refilled. So for inbound
  forwarding, specchio does what Option A does on top: it joins the
  sandbox's user namespace, and refills pools of sockets from a thread that
  enters the network namespace. See `user-ns.md`.

---

## 4. No tokio: port `tcp_splice.c` instead

Decision: a hand-written, single-threaded epoll loop with the connection state
machine ported almost line by line from `tcp_splice.c` (`src/splice.rs`;
GPL-2.0-or-later like passt, so porting closely is fine). Reasons:

- tokio is built around reading and writing socket data in user space,
  asynchronously. specchio never touches the data: it only moves it with
  `splice()` through pipes, and needs readiness events, which plain epoll
  gives directly.
- `tcp_splice.c` already is the state machine we need (`SPLICE_CONNECT`,
  `SPLICE_ESTABLISHED`, `OUT_WAIT_n`, `FIN_RCVD_n`, `FIN_SENT_n`, the pipe
  pool, `SPLICE_F_MORE`/`TCP_NODELAY` corking), with years of edge cases
  worked out (half-close, back-pressure, draining before close).
- Fewer dependencies (only `libc`), a smaller attack surface, and easier to
  apply seccomp to later.

Where specchio deliberately differs from `tcp_splice.c`, see 1.4 and the
README: `EPOLLHUP` isn't fatal, `connect()` retries on `EAGAIN`, no
`SO_RCVLOWAT` handling.

---

## 5. `pasta` closes inherited descriptors too early

`isolate_fds()` (`isolation.c:263`) closes every descriptor above standard
error (`close_range()` at `isolation.c:278`), except the one given with
`--fd`. It's called first thing in `main()` (`passt.c:348`), *before*
`pasta_start_ns()` forks the command. So the command never receives any
inherited descriptor. This broke two things for us:

- **systemd socket activation**: the listening sockets systemd passes never
  reach a server started under `pasta`.
- **Passing data to `bwrap` by descriptor**, e.g. `bwrap --args FD`: the
  descriptor is gone by the time `bwrap` runs. Worked around by writing the
  arguments to a temporary file instead.

specchio (commit `89ad781`) does it the other way round: the command inherits
everything at `fork()`, and only afterwards does the specchio parent drop its
own copies (`sys::drop_inherited()`): standard input and output go to
`/dev/null`, everything above standard error is closed except the listeners
and the pidfd, and standard error stays for messages. Besides keeping socket
activation working, this means a reader of the command's output sees EOF when
the command closes it, rather than when the forwarder exits.

Still the user's job, not specchio's: systemd's `LISTEN_PID` names the
process systemd started, and has to be rewritten for the process that
finally uses the sockets. With `bwrap` creating a PID namespace, that PID is
only known inside it, so it's fixed up by a wrapper script.

---

## 6. Other things found along the way

- **`-T` target addresses are ignored by `pasta`** for spliced connections:
  `-T 8080:192.0.2.1/9090` is parsed, but `fwd_nat_from_splice()` connects to
  the namespace-side loopback address on the host (see 1.3).
- **Possible data loss in `pasta` on `EPOLLHUP`**: TCP sockets also report
  `EPOLLHUP` once shut down in both directions, possibly with data still
  queued, so the `tcp_splice.c` behaviour described in 1.4 may lose data for
  TCP too. Not checked; may be worth reporting upstream.
- **Throughput**: 8 GB over host loopback through `pasta --splice-only -T`
  and through specchio took about the same time as a direct connection
  (about 4.4 GB/s, likely limited by the `dd | socat` test itself).
  `pasta` without `--splice-only` needs `/dev/net/tun`.
- **`--splice-only`** implies `--host-lo-to-ns-lo` and disables ICMP and DNS
  forwarding (`conf.c` around line 1822).
