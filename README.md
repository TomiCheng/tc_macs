# tc_macs

A Rust workspace for message authentication codes. It holds `tc_macs`, the
shared `Mac` and `MacInit` contracts together with CBC-MAC, CFB-MAC, CMAC,
GMAC and HMAC over any engine that implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits or any
digest that implements [`tc_digest`](https://crates.io/crates/tc_digest),
SipHash and VMPC-MAC, and the MACs built on those contracts: `tc_poly1305`, the
Poly1305 one-time MAC, `tc_dstu_macs`, the DSTU 7564 and DSTU 7624 MACs,
`tc_gost28147_mac`, the GOST 28147-89 MAC, `tc_iso9797_mac`, the ISO/IEC 9797-1
MAC algorithm 3, `tc_kmac`, KMAC128 and KMAC256, and `tc_skein_mac`,
Skein-MAC.
Each crate is published separately and keeps its own README and changelog.

[![CI](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

## Crates

| Crate | Version | Description |
| --- | --- | --- |
| [`tc_macs`](tc_macs) | [![crates.io](https://img.shields.io/crates/v/tc_macs.svg)](https://crates.io/crates/tc_macs) [![docs.rs](https://docs.rs/tc_macs/badge.svg)](https://docs.rs/tc_macs) | CBC-MAC, CFB-MAC, CMAC, GMAC and HMAC over `tc_block_cipher` engines and `tc_digest` digests, SipHash and VMPC-MAC, and the `Mac` and `MacInit` contracts that MAC crates implement. Each MAC over a cipher or digest is constant time exactly when that primitive is, SipHash is constant time and VMPC-MAC is variable time; each wipes its buffers on drop. `no_std`, no `unsafe`; the default build carries only the contracts and depends on `tc_block_cipher` and `tc_zeroize`. Default-off `cbc-mac`, `cfb-mac`, `cmac`, `gmac`, `hmac`, `siphash` and `vmpc-mac` features add the MACs, and a default-off `alloc` feature adds the forms sized at run time. |
| [`tc_poly1305`](tc_poly1305) | [![crates.io](https://img.shields.io/crates/v/tc_poly1305.svg)](https://crates.io/crates/tc_poly1305) [![docs.rs](https://docs.rs/tc_poly1305/badge.svg)](https://docs.rs/tc_poly1305) | Raw Poly1305 (RFC 8439) with a 32-byte one-time key, which `do_final` consumes. Constant time; wipes its key and state on drop. `no_std`, no allocator, no `unsafe`, no features; depends on `tc_macs` and `tc_zeroize`. |
| [`tc_dstu_macs`](tc_dstu_macs) | [![crates.io](https://img.shields.io/crates/v/tc_dstu_macs.svg)](https://crates.io/crates/tc_dstu_macs) [![docs.rs](https://docs.rs/tc_dstu_macs/badge.svg)](https://docs.rs/tc_dstu_macs) | The DSTU 7564 (Kupyna) and DSTU 7624 (Kalyna) MACs. Variable time; wipes its key and state on drop. `no_std` with an allocator, no `unsafe`, no features; depends on `tc_macs`, `tc_block_cipher`, `tc_digest`, `tc_dstu7564`, `tc_dstu7624` and `tc_zeroize`. |
| [`tc_gost28147_mac`](tc_gost28147_mac) | [![crates.io](https://img.shields.io/crates/v/tc_gost28147_mac.svg)](https://crates.io/crates/tc_gost28147_mac) [![docs.rs](https://docs.rs/tc_gost28147_mac/badge.svg)](https://docs.rs/tc_gost28147_mac) | The GOST 28147-89 MAC with a 4-byte tag. Variable time; wipes its key and state on drop. `no_std`, no `unsafe`; a default-off `alloc` feature adds owned parameters; depends on `tc_macs`, `tc_block_cipher`, `tc_block_modes`, `tc_gost28147` and `tc_zeroize`. |
| [`tc_iso9797_mac`](tc_iso9797_mac) | [![crates.io](https://img.shields.io/crates/v/tc_iso9797_mac.svg)](https://crates.io/crates/tc_iso9797_mac) [![docs.rs](https://docs.rs/tc_iso9797_mac/badge.svg)](https://docs.rs/tc_iso9797_mac) | The ISO/IEC 9797-1 MAC algorithm 3 over DES, the ANSI X9.19 retail MAC, with a 16- or 24-byte key and an 8-byte IV. Variable time; wipes its state on drop. `no_std`, no allocator, no `unsafe`, no features; depends on `tc_macs`, `tc_block_cipher`, `tc_block_modes`, `tc_block_padding`, `tc_des` and `tc_zeroize`. |
| [`tc_kmac`](tc_kmac) | [![crates.io](https://img.shields.io/crates/v/tc_kmac.svg)](https://crates.io/crates/tc_kmac) [![docs.rs](https://docs.rs/tc_kmac/badge.svg)](https://docs.rs/tc_kmac) | KMAC128 and KMAC256 (NIST SP 800-185), as fixed-length MACs and as KMACXOF. Constant time; wipes its key on drop. `no_std` with an allocator, no `unsafe`, no features; depends on `tc_macs`, `tc_digest`, `tc_keccak` and `tc_zeroize`. |
| [`tc_skein_mac`](tc_skein_mac) | [![crates.io](https://img.shields.io/crates/v/tc_skein_mac.svg)](https://crates.io/crates/tc_skein_mac) [![docs.rs](https://docs.rs/tc_skein_mac/badge.svg)](https://docs.rs/tc_skein_mac) | Skein-MAC with a 256-, 512- or 1024-bit state. Constant time; its Skein state wipes itself on drop. `no_std`, no `unsafe`; a default-off `alloc` feature adds owned parameters; depends on `tc_macs` and `tc_skein`. |

`tc_macs` defines the contracts that every MAC crate in the workspace
implements; each MAC documents its own tag sizes, key and IV requirements and
timing guarantees.

## Requirements

Rust 1.85 or later, edition 2024. Every crate builds without `std`.
`tc_macs`, `tc_gost28147_mac` and `tc_skein_mac` reach the heap only through
their default-off `alloc` features, `tc_poly1305` and `tc_iso9797_mac` never do,
`tc_dstu_macs` needs an allocator for the key of its `Dstu7564Mac`, and
`tc_kmac` for the key it keeps.

Rust 1.85 is the earliest compiler for edition 2024, and it is guaranteed for
every build in this workspace, tests included: every dependency and
dev-dependency is a `tc_*` crate that requires Rust 1.85 as well. The workspace
lock tracks the latest dependency releases, so CI on stable tests what a user
on a current toolchain resolves.

## Workspace checks

```text
cargo test --locked
cargo test --locked --all-features
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo doc --locked --no-deps --all-features
```

CI additionally runs these on Linux x64, i686 and ARM64, macOS ARM64, and
Windows x64, with and without every feature, runs Clippy and rustdoc on each
`tc_macs` feature alone, runs the tests on Rust 1.85.0, checks the
`wasm32-unknown-unknown` and `aarch64-unknown-none` targets and the dependency
set of each crate and feature on each target, and verifies the package
archives. See [.github/workflows/ci.yml](.github/workflows/ci.yml).

Before a release, check each archive and run publication validation from a
committed checkout:

```text
cargo package -p <crate> --list --locked
cargo publish -p <crate> --dry-run --locked
```

The archive must include both license texts, the crate README, the changelog,
the source and the integration tests, and no `target/` or other build
artifacts. Every other crate requires the `tc_macs` release, so `tc_macs`
publishes first.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
