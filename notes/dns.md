# Asynchronous host name resolution, and why we don't do it

Notes from looking into resolving target host names asynchronously, from
specchio's epoll loop, so that names could be looked up again for each
connection. Collected 2026-11-13. We decided against it: host name targets
are resolved once, with a blocking `getaddrinfo()`, before the sandbox
starts (see the README).

Contents:

1. [The problem](#1-the-problem)
2. [Options outside a DNS client](#2-options-outside-a-dns-client)
3. [Sans-I/O DNS crates](#3-sans-io-dns-crates)
4. [What a minimal client of our own would take](#4-what-a-minimal-client-of-our-own-would-take)
5. [Why we resolve once at startup instead](#5-why-we-resolve-once-at-startup-instead)

---

## 1. The problem

C libraries have no non-blocking `getaddrinfo()`. Calling it per connection
from the single-threaded event loop could stall every connection for as
long as a lookup takes. The usual workaround, `getaddrinfo()` on a thread
pool (which is also what glibc's `getaddrinfo_a()` does internally), brings
threads into an otherwise single-threaded program, and a blocked lookup
can't be cancelled.

specchio doesn't use an async runtime (see `pasta.md`, section 4), so a
Rust async resolver isn't an option as-is either. What's left is a DNS
client that plugs into our own epoll loop: either a protocol we speak to a
local service, or a sans-I/O DNS implementation that we feed with our own
socket reads and writes.

The aim was the most minimal client possible, mapping a name to IP
addresses, and leaving everything else (recursion, `/etc/hosts`, search
domains, caching) to the DNS server, expected to be a local recursive
resolver.

## 2. Options outside a DNS client

- **Varlink** (`io.systemd.Resolve` on systemd-resolved's Unix domain
  socket): a Unix socket fits our epoll loop, and resolved does everything,
  including `/etc/hosts`. But it ties specchio to systemd, as there's no
  other implementation, and it needs a JSON encoder and parser.
- **c-ares**: a C library with an interface for external event loops.
  Complete, but a C dependency much larger than what we need.
- **A plain DNS client talking to systemd-resolved's stub** (`127.0.0.53`,
  the usual `nameserver` in `/etc/resolv.conf` on Fedora) gets most of the
  Varlink benefits anyway: resolved applies `/etc/hosts`, search domains
  and per-link DNS servers to stub queries too. Without resolved or a
  similar local resolver, though, `/etc/hosts` and search domains would be
  silently ignored, unlike with `getaddrinfo()`.

## 3. Sans-I/O DNS crates

The crate sources were inspected. Size added to a stripped release binary 
was measured with a toy program doing one blocking A lookup, built like 
specchio (LTO, `panic = "abort"`).

| | mini-sansio-dns 2.0.1 | dns-protocol 0.1.2 | sansio-dns 0.1.0 |
|---|---|---|---|
| Scope | A/AAAA query builder and parser, trivial state machine | Encodes and parses general DNS messages, `no_std`, no allocation | Full stub resolver: retries, TCP fallback, search domains, hosts file, cache, DNS over TLS |
| Source size | ~550 lines, no dependencies | ~2000 lines, `memchr` | ~4650 lines, plus `hickory-proto`, `thiserror`, optionally `rustls` |
| Added to stripped binary | +14 KB | +20 KB | much larger (not measured) |
| Maintenance | 168 downloads, released 2026-07, MIT | last release 2024-06, MIT/Apache-2.0 | 21 downloads, first release 2026-10 |

### mini-sansio-dns

The right size, but not usable as it is:

- Every query has ID `0xABCD`, and replies aren't checked against the ID or
  the question, so a late reply to an earlier query, or a spoofed one, is
  accepted.
- It returns only the first matching record, as a `SocketAddr` with port 0,
  so there's nothing to fall back to.
- A name with a trailing dot (`example.com.`) produces a malformed query;
  empty labels aren't checked.
- NXDOMAIN, SERVFAIL and truncated replies all come back as
  `InvalidDnsResponse`.
- The "sans-I/O" state machine is just write once, read once. Retransmission
  and timeouts, the only stateful part of a UDP DNS client, are left to the
  caller.

(Version 0.2.0 depended on `rustix`; 2.0.1 has no dependencies.)

### dns-protocol

Correct message encoding and parsing, usable for the wire format, with
caveats:

- `Message::read()` takes caller-provided record arrays and fails outright
  if a reply has more answer or additional records than they hold, so they
  need to be sized generously (say, 32 answers).
- `Label::names()` follows compression pointers with no loop guard
  (`src/ser.rs:215`): a crafted reply could hang the event loop. It must
  not be called on untrusted names.
- Label comparison (`PartialEq`) compares raw segments: case-sensitive, and
  a compressed name never equals an uncompressed one. Matching the question
  in a reply has to be done on raw bytes.
- No release in over two years.

### sansio-dns

Built on `hickory-proto`, carefully designed and documented, but the
opposite of minimal: it reimplements the resolver we wanted to leave all
complexity to.

## 4. What a minimal client of our own would take

Writing it ourselves looked better than any of the crates: about 150 lines
for the wire format, the same binary size as mini-sansio-dns, under our
licence and with nothing third-party to audit.

- **Query** (~30 lines): one question, RD set, random ID from `getrandom()`.
- **Reply** (~80 lines): check ID, QR and the question; NXDOMAIN as a
  definite failure; skip names with a loop-guarded pointer walk; collect
  all A/AAAA records without following CNAMEs, which a recursive resolver
  already resolves.
- **Truncated replies**: fail them. A/AAAA answers practically never exceed
  512 bytes; EDNS0 with a 1232-byte buffer (an 11-byte OPT record) would
  make that even less likely, and TCP fallback unnecessary.

Integration into specchio, estimated at 400 to 500 lines with tests:

1. Read the first `nameserver` from `/etc/resolv.conf` at startup.
2. On `accept()` for a host name target, instead of `connect()` right away:
   a connected, non-blocking UDP socket (the kernel then drops datagrams
   from other sources, and picks a random source port), registered as a new
   `Ref::Dns(id)`, sending the A and AAAA queries; `connect()` once the
   reply arrives.
3. Turn the `connect()` retry list and `Forwarder::timeout()` into general
   deadlines, for retransmissions (say, 1 s, 2 s, 4 s) and giving up.
4. Try the resulting addresses in order on connection failure (this part
   exists now, for names resolved at startup).
5. A future seccomp filter would have to allow UDP sockets.

## 5. Why we resolve once at startup instead

Forwarding targets are fixed on the command line, so asynchronous
resolution only matters to look names up again for each connection, to
follow TTL expiry or DNS-based failover. For the expected uses that's not
worth the cost:

- Most forwards go to Unix domain sockets, typically a filtering HTTP(S)
  proxy that sandboxed clients send API requests through. Firewalls being a
  fact of life, software rarely needs many other ports anyway.
- The remaining case, SSH to a host on the LAN, resolves quickly, and the
  address doesn't change while a sandbox runs.

A blocking `getaddrinfo()` before the event loop starts costs no code, and
gives full NSS behaviour (`/etc/hosts`, mDNS, and so on) with no dependency
on a local stub resolver. If per-connection lookups become necessary, the
syntax stays the same, and section 4 is the plan.
