# Signals, process lifetimes, and `bwrap`

Notes from looking into how a command run by specchio, typically a
service sandboxed with `bwrap`, can be stopped reliably and gracefully,
from shell scripts and from systemd. Collected 2026-11-13, on Linux 7.3
with bubblewrap 0.12.0. Source references to bubblewrap are as of tag
`v0.12.0` (`bubblewrap.c`).

Contents:

1. [What specchio does now](#1-what-specchio-does-now)
2. [Experiments](#2-experiments)
3. [How `bwrap` is structured, and why it doesn't forward signals](#3-how-bwrap-is-structured-and-why-it-doesnt-forward-signals)
4. [PID 1 and signals](#4-pid-1-and-signals)
5. [systemd](#5-systemd)
6. [Options for specchio](#6-options-for-specchio)
7. [Who can signal or trace whom](#7-who-can-signal-or-trace-whom)

---

## 1. What specchio does now

- The child sets `PR_SET_PDEATHSIG(SIGKILL)` before `exec`ing the command,
  so the command is killed when specchio dies, however it dies. This
  applies to the **direct child only**: descendants of the command are
  reparented (to init, or the nearest subreaper) and survive. The README's
  "neither outlives the other" is only true for the direct child.
- specchio ignores `SIGINT` and `SIGQUIT`, like a shell waiting for a
  foreground job: the terminal sends them to the whole foreground process
  group, so the command gets them anyway.
- `SIGTERM`, `SIGHUP` and other signals have their default action:
  specchio dies at once, and the death signal `SIGKILL`s the command. The
  command never sees the `SIGTERM`, and can't shut down gracefully.

Correction to a comment in `src/sandbox.rs`: it says that `unshare()`
clears the parent death signal. It doesn't, at least on Linux 7.3: tested
with `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, writing `uid_map` and
`gid_map`, and a further nested `unshare(CLONE_NEWUSER)`, `PR_GET_PDEATHSIG`
still returned `SIGKILL` after each step. What does clear it (see
`prctl(2)`): `exec` of a set-user-ID, set-group-ID or file capability
binary, and changes of effective or filesystem user or group IDs. The
`getppid()` check after setting it is still needed, for the case where
specchio died before that point.

Also: the death signal is sent when the parent *thread* exits, not the
parent process. If specchio ever uses threads (for example, to create
sockets in the sandbox for inbound forwarding), the `fork()` of the
child must stay on the main thread.

## 2. Experiments

Setup: a test service, `sh` with a `trap` on `SIGTERM` that sleeps 2 s
before exiting (a "slow" graceful shutdown), plus a background `sleep` as
a grandchild. Run either directly under `bwrap`, or under
`specchio -- bwrap ...`, in a new session (`setsid`), then `SIGTERM` sent
either to the top process only (`kill PID`, like `KillMode=mixed` or a
shell script), or to the whole process group (`kill -- -PGID`, like
systemd's default `KillMode=control-group`).

### `SIGTERM` to the top process only

| Setup | Service got `SIGTERM` | Leftover processes |
|---|---|---|
| `bwrap --die-with-parent` (no PID namespace) | no | grandchild survives |
| `bwrap --unshare-pid --die-with-parent` | no | none |
| `bwrap --unshare-pid --as-pid-1 --die-with-parent` | no | none |
| specchio + `bwrap --unshare-pid --die-with-parent` | no | none |
| specchio + `bwrap --unshare-pid --as-pid-1 --die-with-parent` | no | none |

`bwrap` doesn't forward signals: it dies of the `SIGTERM`, and
`--die-with-parent` `SIGKILL`s the rest. With a PID namespace, that takes
down the whole tree: the sandbox's PID 1 gets `SIGKILL` from its death
signal, and when PID 1 of a namespace dies, the kernel `SIGKILL`s
everything else in it (see section 4). Without one, the grandchild
survives. Stopping is complete, but never graceful.

### `SIGTERM` to all processes, slow shutdown

| Setup | Service got `SIGTERM` | Shutdown finished |
|---|---|---|
| `bwrap --unshare-pid --die-with-parent` | yes | **no** |
| specchio + `bwrap --unshare-pid --die-with-parent` | yes | **no** |
| specchio + `bwrap --die-with-parent` (no PID namespace) | yes | **no** |
| `bwrap --unshare-pid` | yes | yes |
| specchio + `bwrap --unshare-pid` | yes | yes, but specchio had already exited |

The sandbox's PID 1 (the inner `bwrap`) gets the `SIGTERM` too, but
ignores it (section 4), and only exits once the service has, so the
namespace isn't torn down early. But the outer `bwrap` (and specchio)
die of the same signal at once, and `--die-with-parent` (or specchio's
death signal) then `SIGKILL`s the service in the middle of its shutdown.
Without `--die-with-parent` the shutdown completes, but specchio is gone
by then, so the service's forwarded ports stop working while it shuts
down (for example, it can't flush anything through a proxy).

## 3. How `bwrap` is structured, and why it doesn't forward signals

`bwrap` creates all namespaces with a single `clone()`
(`raw_clone (clone_flags, NULL)`, line 3075), rather than `unshare()`ing
in its own process. So there are up to three processes:

1. **The outer `bwrap`, the monitor** (`monitor_child()`, line 482). It
   stays outside the sandbox and:
   - in the setuid case, writes the child's UID/GID maps while still
     privileged (line 3227), then drops privileges (in the unprivileged
     case, the child writes its own maps, line 3374), and releases the
     child through an eventfd (`child_wait_fd`);
   - reports the child's PID and namespace IDs (`--info-fd`,
     `--json-status-fd`) and handles `--userns-block-fd`;
   - waits for the sandbox and exits with the command's exit status.
     It blocks `SIGCHLD` and reads it from a `signalfd`
     (`block_sigchild()`, line 3014, and line 512); **no other signal is
     handled**, so `SIGTERM` or `SIGINT` just kill it;
   - with `--die-with-parent`, sets `PR_SET_PDEATHSIG(SIGKILL)` on itself
     (`handle_die_with_parent()`, line 372), as do the processes below.
2. **The inner `bwrap`, PID 1 of the sandbox** (`do_init()`, line 584),
   only with `--unshare-pid` (or `--lock-file`, `--sync-fd`) and without
   `--as-pid-1`: forked after setup (line 3447), it reaps zombies, passes
   the exit status of the command (PID 2) to the monitor through an
   eventfd, and exits once it has no children left, which tears down the
   PID namespace. It drops all capabilities and installs no signal
   handlers either.
3. **The command**, `exec`ed by the cloned child (PID 2 with an init
   above, PID 1 with `--as-pid-1`, or whatever PID without a PID
   namespace).

Why not a single process that enters the namespaces and `exec`s the
command, as `unshare(1)` does without `--fork`?

- A new PID namespace needs a new process: `unshare(CLONE_NEWPID)` only
  applies to the caller's future children (`unshare --pid` needs
  `--fork` for that reason). The `clone()` with `CLONE_NEWPID` makes the
  child PID 1 directly.
- `bwrap` was designed to work as a setuid binary, where a privileged
  process in the parent user namespace must write the child's ID maps,
  and the sandboxed process must never hold those privileges.
- The monitor reports the sandbox's PID and namespace IDs, and the
  command's exit status, to the caller (Flatpak uses `--info-fd`, for
  example).

Without `--unshare-pid` (and without the options above), there is no
inner `bwrap`: the cloned child `exec`s the command directly, and only the
monitor remains as an extra process. Without the setuid and reporting
requirements, that monitor isn't strictly needed: `unshare()` followed by
`exec` would do. But `bwrap` always uses one code path.

The inner `bwrap` seen in process listings is therefore PID 1 of the
sandbox's PID namespace, from `--unshare-pid`.

For comparison, `pasta` (source at passt `6aa4f88`, tested with the Fedora
package 0^20261002):

- `pasta` doesn't forward signals either, and its command doesn't die with
  it. `SIGTERM` and `SIGQUIT` make `pasta` itself exit (`exit_handler()`,
  `passt.c:169`), other signals have their default action, and nothing is
  sent to the command. The command's `PR_SET_PDEATHSIG(SIGKILL)` only
  covers setup: it's cleared just before `exec` ("Let us outlive our
  parent now", `pasta.c:228`). Unless `--no-pidns` is given, the command
  runs as PID 1 of a new PID namespace (`pasta_start_ns()`), with no init
  above it, so it ignores signals it has no handler for (section 4).
  Tested with `pasta --splice-only`: after `SIGTERM` to `pasta`, `pasta`
  was gone, and the command kept running, reparented to init, as PID 1
  of its namespace, without its port forwarding. So `kill` on `pasta`
  from a script orphans the sandbox, like `bwrap` without
  `--die-with-parent`, and there is no option to change that.

## 4. PID 1 and signals

Two rules, from `pid_namespaces(7)`, explain the experiments:

- **PID 1 is protected from signals it doesn't handle.** PID 1 of a PID
  namespace only receives signals for which it has installed a handler,
  from processes in the namespace and from ancestor namespaces alike. The
  only exceptions are `SIGKILL` and `SIGSTOP` sent from an ancestor
  namespace (and the death signal, which the kernel sends).
- **When PID 1 dies, the namespace dies.** The kernel then `SIGKILL`s every
  other process in the namespace, abruptly.

`bwrap`'s init installs no handlers (`SigCgt` is 0 in `/proc/PID/status`),
so `SIGTERM` doesn't kill it. Tested with `bwrap --unshare-pid` and a
service that takes 2 s to shut down: `SIGTERM` sent only to the sandbox's
PID 1 had no effect on either; `SIGTERM` to the service then let it
finish its shutdown, after which PID 1 exited (it exits when it has no
children left) and the outer `bwrap` exited with status 0. `SIGKILL` to
PID 1 took down the service at once. So with systemd's default
`KillMode=control-group`, `SIGTERM` reaches everything, PID 1 waits, and
the service shuts down gracefully, unless something `SIGKILL`s PID 1
first, which is what `--die-with-parent` does once the outer `bwrap`
has died of the same `SIGTERM`.

Even so, forwarding signals would be useful in `bwrap`: when only the
outer `bwrap` is signalled (a shell script, `KillMode=mixed`), nothing
inside learns of it.

- With `--as-pid-1`, the command is PID 1. A command without a `SIGTERM`
  handler (a shell script without `trap`, many simple programs) ignores
  `SIGTERM` from systemd, and only stops at the final `SIGKILL`
  (`TimeoutStopSec`, 90 s by default). It must also reap orphaned
  descendants itself.
- Without `--as-pid-1`, `bwrap`'s init is PID 1, and the command behaves
  as usual. `--as-pid-1` is not needed for `--die-with-parent` to take
  down the whole tree: `--unshare-pid` is what does that.

## 5. systemd

- `systemctl stop` is already reliable for specchio and `bwrap`: with the
  default `KillMode=control-group`, systemd sends `KillSignal` (`SIGTERM`)
  to every process in the unit's cgroup, which namespaces don't change,
  and `SIGKILL`s whatever is left after `TimeoutStopSec`. In all the
  experiments above, nothing survived.
- What fails is a *graceful* stop: see section 2. `bwrap
  --die-with-parent`, and specchio's current behaviour, cut a service's
  shutdown short.
- `KillMode=mixed` sends `KillSignal` to the main process only (here,
  specchio), and the final `SIGKILL` to the whole cgroup. This only lets
  the service see `SIGTERM` if specchio forwards it, and, with `bwrap` in
  between, only if `bwrap` forwards it too, which it doesn't.
- With the default `KillMode=control-group` and signal forwarding in
  specchio, a command run directly under specchio gets `KillSignal` twice:
  from systemd and from specchio. Most programs don't mind, but some treat
  a second signal as "quit immediately". `KillMode=mixed` avoids this.

## 6. Options for specchio

Considered:

- **Making specchio a process group leader**, and signalling the group.
  Rejected: from a script without job control, `setpgid()` takes specchio
  and the command out of the terminal's foreground process group (Ctrl-C
  no longer reaches them, reading the terminal raises `SIGTTIN`); it does
  nothing for `SIGKILL`, which specchio can't act on; and the command can
  leave the group anyway (`setsid()`, which `bwrap --new-session` calls).
- **Forwarding signals** to the command. Decided: catch `SIGTERM` and
  `SIGHUP` with a `signalfd` (which fits the epoll loop), forward them to
  the command, and keep running until it exits, then exit with its status.
  Also forward `SIGINT` and `SIGQUIT`, but only if they were sent with
  `kill()` (`si_code` `SI_USER`), not by the terminal (`SI_KERNEL`, from
  `SEND_SIG_PRIV`), which already sends them to the whole foreground
  group; this also covers units with `KillSignal=SIGINT`. The `si_code`
  values are yet to be checked in practice. The death signal stays, as the
  fallback for `SIGKILL` and crashes.
- **Becoming a child subreaper** (`PR_SET_CHILD_SUBREAPER`), and exiting
  only once no children are left. Deferred. It would keep specchio, and
  the forwarded ports, alive while the rest of the sandbox shuts down:
  with `bwrap --unshare-pid` without `--die-with-parent` under systemd,
  the outer `bwrap` dies at once, the sandbox's PID 1 is reparented to
  specchio, and specchio exits when it does. But once the command has
  exited, specchio would have to forward termination signals to adopted
  children too, and `SIGKILL` them after a grace period: otherwise
  `kill -TERM` on specchio from a script would hang, as `bwrap` doesn't
  pass the signal on and its init, as PID 1, ignores it.

Forwarding alone doesn't make a `bwrap`-wrapped service shut down
gracefully, because `bwrap` dies of the forwarded signal. It does for
commands that handle signals themselves, and keeps specchio running for as
long as the command does.

Suggested usage, for now:

- Use `bwrap --unshare-pid` so that the whole sandbox goes away together,
  and avoid `--as-pid-1` unless the service handles signals and reaps
  children like an init.
- Under systemd, the cgroup already guarantees cleanup, so
  `--die-with-parent` isn't needed there, and leaving it out lets the
  service finish its shutdown (though without its forwarded ports, see
  above). From shell scripts, `--die-with-parent` gives a complete, but
  abrupt, stop.

## 7. Who can signal or trace whom

Found while looking at inbound forwarding, where specchio would have to
join the sandbox's user namespace (to `setns()` into its network
namespace).

- `kill(2)` only checks that the sender's real or effective user ID
  matches the target's real or saved user ID, as kernel user IDs (after
  mapping), or that the sender has `CAP_KILL` in the target's user
  namespace. Root in the sandbox is the same kernel user ID as the user
  running specchio, so the command can always signal specchio, whatever
  namespaces either is in.
- `ptrace(2)` and `pidfd_getfd(2)` have extra checks: for a non-dumpable
  target, the tracer needs `CAP_SYS_PTRACE` in the user namespace the
  target was in at its last `exec` (plus LSM checks such as Yama). Tested:
  a process that joined a sandbox's user namespace had a descriptor taken
  with `pidfd_getfd()`, and was attached with `PTRACE_ATTACH`, from root
  in the sandbox; after `prctl(PR_SET_DUMPABLE, 0)`, both failed with
  `EPERM`. `pasta` does the same (`isolation.c:558` in passt).
