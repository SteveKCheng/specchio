# Executable size

Notes on why the release `specchio` binary is about 600 KB even though
its only dependency is `libc`, and what could be done about it.
Collected 2026-11-15 with rustc 1.99.0 (stable), x86-64 Linux, at commit
`72bb0e5` (about 4,100 lines of Rust). The release profile was
`panic = "abort"`, `lto = true`.

Contents:

1. [Summary](#1-summary)
2. [Where the bytes go](#2-where-the-bytes-go)
3. [Why the backtrace symbolizer is linked in](#3-why-the-backtrace-symbolizer-is-linked-in)
4. [Stable-toolchain options (measured)](#4-stable-toolchain-options-measured)
5. [Nightly option: rebuild std with immediate-abort panics](#5-nightly-option-rebuild-std-with-immediate-abort-panics)
6. [Minor source-level savings](#6-minor-source-level-savings)
7. [How to reproduce the measurements](#7-how-to-reproduce-the-measurements)

---

## 1. Summary

The size doesn't come from monomorphization or from specchio's own code.
specchio's own functions add up to roughly 90 KB. Most of the rest is
the Rust standard library, which is precompiled and linked statically,
and the biggest single part of it (about 170 KB of machine code) is a
DWARF debug-info parser. The panic handler uses it to symbolize
backtraces. The rest is symbol tables (Cargo doesn't strip release
builds by default) and unwind tables.

- **On stable:** `strip = true` saves about 112 KB at no cost. That
  takes the binary to about 485 KB. Other profile settings save only
  another 5–35 KB.
- **On nightly:** rebuilding std with immediate-abort panics should
  remove the symbolizer and most of the formatting machinery. This
  hasn't been measured for specchio. The cost is that panics no longer
  print a message.

## 2. Where the bytes go

Total file size: **597,608 bytes**, not stripped.

Largest sections (`size -A`):

| Section | Bytes | Notes |
|---|---:|---|
| `.text` | 368,385 | machine code |
| (symbol tables, not in `size` total) | ~115,000 | `.symtab` / `.strtab`; removed by stripping |
| `.rodata` | 38,818 | string literals, formatting tables, etc. |
| `.eh_frame` | 29,408 | unwind tables; still there with `panic = "abort"` because std was built with them |
| `.rela.dyn` | 15,048 | PIE relocations |
| `.data.rel.ro` | 9,992 | vtables etc. |
| `.eh_frame_hdr` | 5,276 | |
| `.gcc_except_table` | 4,668 | landing-pad tables, from std |

How the `.text` breaks down, based on `nm -C --size-sort -S` over text
symbols:

| Source | Bytes (approx.) |
|---|---:|
| std's backtrace symbolizer: `gimli`, `addr2line`, `miniz_oxide`, `rustc_demangle`, `std::backtrace_rs` | **~170,000** |
| Other std/core/alloc code | ~90,000 |
| specchio's own code (symbols containing `specchio`) | ~90,000 |
| Other | ~15,000 |

Largest individual functions:

| Bytes | Function |
|---:|---|
| 18,517 | `std::backtrace_rs::symbolize::gimli::Cache::with_global` |
| 16,883 | `specchio::config::parse` |
| 13,604 | `specchio::main` |
| 12,517 | `std::backtrace_rs::symbolize::gimli::Context::new` |
| 10,581 | `specchio::Forwarder::listener_event` |
| 9,007 | `gimli::read::dwarf::Unit::new` |
| 7,832 | `addr2line` `LazyLines` init |
| 7,243 | `miniz_oxide::inflate::core::decompress` |
| 6,098 | `gimli::read::unit::EntriesCursor::next_entry` |

specchio's larger functions are big because the optimizer inlines a lot
into them (`config::parse`, `main`, `listener_event`), not because
generics are instantiated many times.

Other std code that appears because specchio uses it:
`std::net::lookup_host` (getaddrinfo wrapper), `Ipv6Addr` `Display`,
`io::Error` `Debug`, and generic slice sorting.

## 3. Why the backtrace symbolizer is linked in

There are about 40 places in `src/` (`unwrap`, `expect`, `panic!`)
that can panic, plus the implicit ones: slice indexing, overflow checks
and so on. All of them go through std's default panic hook. When
`RUST_BACKTRACE` is set, that hook captures a backtrace and symbolizes
it in-process. To do that it reads the executable's own DWARF info,
which may be compressed. That needs a DWARF parser (`gimli`), an
address-to-line mapper (`addr2line`), a zlib inflater (`miniz_oxide`)
and a symbol demangler (`rustc_demangle`).

`panic = "abort"` doesn't help: it only changes what happens *after*
the hook runs (abort instead of unwind). The hook, and everything it
can reach, is still linked. LTO can't remove it either, because the
code is reachable. std is shipped precompiled, so its own build
settings, such as unwind tables, apply no matter what specchio's
profile says.

A C program doesn't pay this cost: glibc doesn't have an in-process
symbolizing crash handler.

## 4. Stable-toolchain options (measured)

Built in a scratch target directory, with the settings added on top of
the current profile and on top of each other in table order:

| Profile settings | Size (bytes) | vs. current |
|---|---:|---:|
| current (`lto = true`, `panic = "abort"`) | 597,608 | — |
| + `strip = true` | 485,224 | −112,384 |
| + `codegen-units = 1` | 480,904 | −4,320 |
| + `opt-level = "s"` | 452,424 | −28,480 |
| + `opt-level = "z"` (instead of `"s"`) | 449,880 | −2,544 |

Assessment:

- **`strip = true`** is free. It only loses symbol names in `perf`,
  `gdb` and so on, and distributions usually strip binaries and ship
  separate debuginfo anyway. Worth adopting when convenient.
- **`codegen-units = 1`** saves little but costs nothing at runtime.
  It only makes release builds slower.
- **`opt-level = "s"` / `"z"`** isn't worth it for a data-path
  forwarder: saving about 30 KB would make the hot paths slower. If
  wanted, it could go in a separate profile (for example
  `[profile.minsize]`) and not in `release`.

So about **450–485 KB** is the floor on stable without code changes.

Stable settings that don't help (not measured, from reasoning):
`panic = "abort"` is already set. Setting a custom panic hook with
`std::panic::set_hook` doesn't remove the default hook's code, because
the default hook is still referenced.

## 5. Nightly option: rebuild std with immediate-abort panics

With a nightly toolchain and the `rust-src` component, std can be
rebuilt as part of the build with panics turned into a bare trap:

```sh
cargo +nightly build --release \
    -Z build-std=std,panic_abort \
    -Z build-std-features=panic_immediate_abort \
    --target x86_64-unknown-linux-gnu
```

On recent nightlies this may have become a codegen option instead
(`-C panic=immediate-abort`, together with `-Z build-std`). Check the
current nightly documentation before relying on either form.

What it does:

- Every panic becomes an immediate `ud2` (SIGILL). There's no hook, no
  message and no backtrace.
- The backtrace symbolizer, much of `core::fmt` reachable only from
  panic messages, and the unwind/landing-pad tables can all be removed.
- std is compiled together with specchio's profile (LTO, opt-level), so
  more of it can be removed or inlined.

Expected result: well under 200 KB stripped. Projects of similar size
usually report numbers in that range. **This hasn't been measured for
specchio.**

Trade-offs:

- It needs nightly, or `RUSTC_BOOTSTRAP=1` on stable, which is a hack.
- Panics are much harder to diagnose: you get only "Illegal
  instruction" and possibly a core dump. To make up for that, a
  different profile or feature could keep normal panics for debug
  builds and testing.
- Builds are slower, because std gets compiled every time the target
  dir is clean.

## 6. Minor source-level savings

These work on stable, but each saves a few KB at most. They're worth
doing only if they also make the code simpler:

- Avoid `std::net::ToSocketAddrs` / `lookup_host` (about 2 KB plus
  dependencies) by calling `libc::getaddrinfo` directly, or by
  accepting only numeric addresses.
- Avoid `Display`-formatting `Ipv6Addr` (about 2 KB) and
  `Debug`-formatting `io::Error` (about 2.4 KB) where a simpler form
  would do. `Display` on `io::Error` is smaller than `Debug`.
- Fewer `unwrap`/`expect` calls don't remove the symbolizer: one panic
  site anywhere, including inside std, is enough to keep it.

## 7. How to reproduce the measurements

```sh
cargo build --release
B=target/release/specchio
ls -l $B
size -A $B | sort -k2 -n -r | head -15

# Largest text symbols
nm -C --size-sort -S $B | grep -i ' t ' | tail -40

# Total size of the backtrace symbolizer
nm -C --size-sort -S $B | grep -i ' t ' |
    awk '{s=strtonum("0x"$2); n=substr($0,index($0,$4));
          if (n ~ /gimli|addr2line|miniz|demangle|backtrace/) bt+=s}
         END {print bt}'

# Profile variants without editing Cargo.toml
T=target/sizeexp
CARGO_TARGET_DIR=$T CARGO_PROFILE_RELEASE_STRIP=true \
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    cargo build --release
ls -l $T/release/specchio
```

`cargo bloat` (a third-party cargo subcommand) gives a similar
per-crate breakdown with less effort, but it isn't installed here.
