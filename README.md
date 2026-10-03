# tc_macs

A Rust workspace for message authentication codes. It holds `tc_macs`, the
shared `Mac` and `MacInit` contracts together with CBC-MAC, CFB-MAC, CMAC,
GMAC and HMAC over any engine that implements the
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) traits or any
digest that implements [`tc_digest`](https://crates.io/crates/tc_digest), and
the MACs built on those contracts: `tc_poly1305`, the Poly1305 one-time MAC.
Each crate is published separately and keeps its own README and changelog.

[![CI](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

## Crates

| Crate | Version | Description |
| --- | --- | --- |
| [`tc_macs`](tc_macs) | [![crates.io](https://img.shields.io/crates/v/tc_macs.svg)](https://crates.io/crates/tc_macs) [![docs.rs](https://docs.rs/tc_macs/badge.svg)](https://docs.rs/tc_macs) | CBC-MAC, CFB-MAC, CMAC, GMAC and HMAC over `tc_block_cipher` engines and `tc_digest` digests, and the `Mac` and `MacInit` contracts that MAC crates implement. Each MAC is constant time exactly when its cipher or digest is, and wipes its buffers on drop. `no_std`, no `unsafe`; the default build carries only the contracts and depends on `tc_block_cipher` and `tc_zeroize`. Default-off `cbc-mac`, `cfb-mac`, `cmac`, `gmac` and `hmac` features add the MACs, and a default-off `alloc` feature adds their forms sized at run time. |
| [`tc_poly1305`](tc_poly1305) | [![crates.io](https://img.shields.io/crates/v/tc_poly1305.svg)](https://crates.io/crates/tc_poly1305) [![docs.rs](https://docs.rs/tc_poly1305/badge.svg)](https://docs.rs/tc_poly1305) | Raw Poly1305 (RFC 8439) with a 32-byte one-time key, which `do_final` consumes. Constant time; wipes its key and state on drop. `no_std`, no allocator, no `unsafe`, no features; depends on `tc_macs` and `tc_zeroize`. |

`tc_macs` defines the contracts that every MAC crate in the workspace
implements; each MAC documents its own tag sizes, key and IV requirements and
timing guarantees.

## Requirements

Rust 1.85 or later, edition 2024. Every crate builds without `std`.
`tc_macs` reaches the heap only through its default-off `alloc` feature, and
`tc_poly1305` never does.

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
artifacts. `tc_poly1305` requires the `tc_macs` release, so `tc_macs`
publishes first.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
