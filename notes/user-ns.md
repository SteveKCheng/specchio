# User namespaces: entering the sandbox, isolation, and dropping fake root

Notes from planning inbound forwarding (`-t`/`-u`, host port to sandbox),
which needs sockets created in the sandbox's network namespace while the
command runs, and an option to run the command without root in its user
namespace. Collected 2026-11-13, on Linux 7.3, by testing as an
unprivileged user. Source references to passt are as of `6aa4f88`.

Contents:

1. [Where things stand](#1-where-things-stand)
2. [Entering the sandbox's network namespace needs its user namespace](#2-entering-the-sandboxs-network-namespace-needs-its-user-namespace)
3. [Joining a user namespace is per process, and single-threaded only](#3-joining-a-user-namespace-is-per-process-and-single-threaded-only)
4. [Isolation once specchio has joined](#4-isolation-once-specchio-has-joined)
5. [Dropping fake root with a nested user namespace](#5-dropping-fake-root-with-a-nested-user-namespace)
6. [Implementation](#6-implementation)

---

## 1. Where things stood

Before inbound forwarding, specchio only forwarded from the sandbox to the
host, and the parent never entered any namespace: the child creates new user
and network namespaces, creates all listening sockets in them, sends them to
the parent over a `socketpair`, and `exec`s the command (`notes/pasta.md`,
section 3, "Option B"). The parent stays in the outer user namespace, without
capabilities, out of reach of the command. That's still the case without
`-t`.

Inbound forwarding needs a socket in the sandbox's network namespace for
each connection, after the command has started, and a pool sent at startup
can't be refilled. The options considered were:

- a small helper process left in the namespaces, creating sockets on request
  over the same `socketpair`;
- the parent entering the sandbox's network namespace with `setns()` when it
  needs a socket, as `pasta` does (`NS_CALL()`, `util.h`).

The second is simpler, but turns out to need the parent to join the
sandbox's user namespace as well.

## 2. Entering the sandbox's network namespace needs its user namespace

`setns(fd, CLONE_NEWNET)` requires `CAP_SYS_ADMIN` twice: over the user
namespace that owns the target network namespace, and in the caller's own
user namespace. The specchio parent has the first: it's in the parent user
namespace of the sandbox's, with the effective user ID that created it, which
gives it all capabilities there. It lacks the second, as an unprivileged
process in its own user namespace.

Tested, with a sandbox made by `unshare -Urn`:

| Attempt | Result |
|---|---|
| `setns(CLONE_NEWNET)`, from a thread, without joining the user namespace | `EPERM` |
| `setns(CLONE_NEWUSER)` while the process has more than one thread | `EINVAL` |
| `setns(CLONE_NEWUSER)` while single-threaded | works; we're now uid 0 in it |
| then `setns(CLONE_NEWNET)` in a thread | works: a socket bound and listening there is in the sandbox's network namespace, while the main thread stays in the host's |
| then `setns(CLONE_NEWNET)` back into the host's network namespace | `EPERM` |

This is why `pasta` keeps `CAP_SYS_ADMIN` in its user namespace
(`isolation.c:440`, `isolation.c:533`): its main process lives in the
sandbox's user namespace, which it creates itself.

The same rule works against us on the way back: once specchio is in the
sandbox's user namespace, it has no capabilities over the user namespace
that owns the host's network namespace, so it can't `setns()` back into it.
Entering the sandbox's network namespace is one-way for whichever thread
does it.

## 3. Joining a user namespace is per process, and single-threaded only

- `setns(CLONE_NEWUSER)` fails with `EINVAL` if the process has more than one
  thread (or, per `setns(2)`, shares its filesystem attributes with another
  process). In one test, a process that had started threads and joined them
  still got `EINVAL`, while a fresh process that had never started any
  succeeded. So specchio must
  join before it starts any thread, at startup, right after the child has
  set up the namespaces.
- Joining the user namespace one is already in also gives `EINVAL`.
- A network namespace, by contrast, is per thread. As the main thread can't
  come back (section 2), sockets in the sandbox must be created by another
  thread: a short-lived one, started when sockets are needed, which
  `setns()`s into the sandbox's network namespace, creates them, hands them
  back and exits. Tested: three such threads in turn created listening
  sockets in the sandbox's network namespace, a connection from inside the
  sandbox reached one of them, and the main thread stayed in the host's
  network namespace and could still create sockets there. Threads are fine
  once the user namespace has been joined; only the join itself needs a
  single thread. `pasta` uses short-lived `clone()`d tasks for the same thing
  (`NS_CALL()`), and never switches its main thread either.
- Since inbound forwarding is for one-offs and servers without socket
  activation (the preferred way to expose sandboxed servers: the command
  inherits sockets from systemd, unlike with `pasta`), refills should be rare, and a brief pause of the event loop
  while a thread creates sockets is acceptable. The thread can be joined
  right away, so specchio still has a single thread most of the time.
- Joining changes credentials, not access: uid 0 in the sandbox's user
  namespace is the original user ID outside, so specchio still opens files,
  and connects to Unix domain sockets on the host, as before.
- Caveat for threads: `PR_SET_PDEATHSIG` fires when the parent *thread*
  exits, not the parent process. The `fork()` of the child must stay on the
  main thread (see `notes/signals.md`, section 1).

## 4. Isolation once specchio has joined

Once specchio is in the sandbox's user namespace, the command, root in that
namespace, has all capabilities over it, including `CAP_SYS_PTRACE`. Tested:
a process that joined a sandbox's user namespace, holding an open file, and
an "attacker" running as root in the sandbox:

| Process that joined | `pidfd_getfd()` from the sandbox | `PTRACE_ATTACH` |
|---|---|---|
| default (dumpable) | took the descriptor, read the file | succeeded |
| after `prctl(PR_SET_DUMPABLE, 0)` | `EPERM` | `EPERM` |

For a non-dumpable target, `ptrace` access (which `pidfd_getfd()` also
checks, as do `/proc/PID/fd` and `/proc/PID/mem`) requires `CAP_SYS_PTRACE`
in the user namespace of the target's memory map, which is the user
namespace the target was in at its last `exec`. `setns()` doesn't change it,
so it stays the outer namespace, where the command has no capabilities.
`pasta` does the same (`prctl(PR_SET_DUMPABLE, 0)`, `isolation.c:558`).

specchio must set `PR_SET_DUMPABLE` to 0 before joining, so that there's no
window in which it's in the sandbox's user namespace and still dumpable.

Unchanged by joining, and already the case: the command can send signals to
specchio. `kill(2)` checks that the sender's real or effective user ID
matches the target's real or saved user ID, compared as kernel user IDs,
after mapping, or that the sender has `CAP_KILL` in the target's user
namespace. Root in the sandbox is the same kernel user ID as the user
running specchio.

The helper process alternative has the same exposure: the helper lives in
the sandbox's user namespace, so it would need `PR_SET_DUMPABLE` set to 0
too, besides being an extra process with its own protocol.

## 5. Dropping fake root with a nested user namespace

The command used to run as root in the sandbox's user namespace, with all
capabilities there (it could, for example, reconfigure `lo`). `bwrap` with
`--unshare-user --uid` drops that, but not everyone uses `bwrap`, and some
programs (or users) are confused by running as "root", unaware that it's
"fake". Dropping it can be done entirely by the child, before `exec`, with
nothing for the parent to do. specchio now does this by default (`--root`
disables it, and there's nothing to drop if specchio was started as root):

1. After creating the sockets, `unshare(CLONE_NEWUSER)` again.
2. Write `uid_map` as `UID 0 1` and `gid_map` as `GID 0 1`, with the original
   user and group IDs: they map to root of the sandbox's user namespace, the
   child's current identity. `setgroups` is already `deny`, inherited from
   the sandbox's user namespace.
3. `exec` the command: as it's not root in its user namespace, `execve()`
   clears its capabilities.

Tested: the command ran with the original user and group IDs, `CapPrm` and
`CapEff` were 0, and `ip link set lo down` failed with "Operation not
permitted". The parent death signal (`PR_GET_PDEATHSIG`) was unaffected by
the nested `unshare()` and the map writes.

Without capabilities, the command can't listen on ports below 1024 or use
ping sockets either. Keeping `CAP_NET_BIND_SERVICE` across `exec()` as an
ambient capability doesn't help: tested with `unshare --keep-caps`, the
command had all capabilities in the nested user namespace, and `bind()` to
port 80 still failed with `EACCES`. The check is against the user namespace
owning the network namespace, the parent of the nested one, and
capabilities never apply to ancestor user namespaces. Instead, the child,
root in the owning user namespace, sets the per-namespace sysctls
`net.ipv4.ip_unprivileged_port_start` to 0 and `net.ipv4.ping_group_range`
to "0 0" before nesting (tested: binding port 80 and `ping` over IPv4 and
IPv6 then work in the nested namespace, and the host's values don't change).
The range is stored as kernel group IDs, so "0 0", written as root of the
sandbox's user namespace, is the original group ID, and reads as such from
the nested one. Both settings cover IPv6 too.

The one interaction with inbound forwarding: specchio must join the
sandbox's user namespace, the one that owns the network namespace, not the
nested one. Being in the nested one gives no capabilities over the network
namespace, so `setns()` into it would fail with `EPERM`. So specchio must not
open `/proc/PID/ns/user` of the child once it has nested. Either:

- the child sends descriptors for its network namespace (or user namespace)
  over `SCM_RIGHTS`, with the listening sockets, before nesting; or
- specchio gets the owning user namespace from a network namespace
  descriptor with `ioctl(NS_GET_USERNS)` (see `ioctl_ns(2)`), which is right
  whenever that descriptor was opened.

Tested, with a sandbox that had already nested a user namespace (as above):
joining the child's current user namespace (`/proc/PID/ns/user`, the nested
one) worked, but left us as uid 1000 there, and `setns()` into the network
namespace then failed with `EPERM`. With `NS_GET_USERNS` on
`/proc/PID/ns/net`, we got the sandbox's user namespace (the same as
`NS_GET_PARENT` of the nested one), joined it as uid 0, and `setns()` into
the network namespace worked.

## 6. Implementation

Only if any inbound forwarding is configured (otherwise specchio stays in its
own user namespace, single-threaded, and dumpable):

1. specchio creates the listening sockets on the host before starting the
   sandbox, so that a port in use is reported before the command runs.
2. The child opens `/proc/self/ns/net` and sends it after the listening
   sockets. Whether it has nested a user namespace by then doesn't matter, as
   specchio finds the owning one from the network namespace.
3. specchio sets `PR_SET_DUMPABLE` to 0, gets the owning user namespace with
   `NS_GET_USERNS`, and joins it with `setns()`, while still single-threaded
   (`ns::join()`). If anything fails, the child is killed.
4. The child waits for a message from specchio before `exec`ing the command
   (for outbound forwarding only, too), so the command never runs if specchio
   couldn't set up.
5. As `pasta` does (`tcp_sock_refill_ns()`), specchio keeps pools of
   non-blocking sockets created in the sandbox's network namespace, by
   protocol and IP version, each kind only once it's been needed: 32
   sockets each, refilled when below 16, between batches of events, and
   right away if a pool is empty when a connection needs a socket. A thread
   creates them: it `setns()`s into the network namespace, creates the
   sockets, and exits, and the main thread waits for it (`ns::NsSockets`).
   After a failure to refill, specchio waits a second before trying again in
   the background. The main thread never leaves the host's network
   namespace, as it couldn't come back, and specchio is single-threaded
   again once the thread is joined.
6. An inbound TCP connection or UDP flow takes a socket of the IP version of
   its target from a pool, and `connect()`s it from the main thread: the
   socket stays in the network namespace it was created in.

Checked: with `--root`, the command (root in the user namespace specchio
joined) gets `EPERM` from both `pidfd_getfd()` and `PTRACE_ATTACH` on
specchio (a test in `tests/run.sh`).
