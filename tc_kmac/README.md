# tc_kmac

[![crates.io](https://img.shields.io/crates/v/tc_kmac.svg)](https://crates.io/crates/tc_kmac)
[![docs.rs](https://docs.rs/tc_kmac/badge.svg)](https://docs.rs/tc_kmac)
[![CI](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

KMAC128 and KMAC256 (NIST SP 800-185), as fixed-length MACs over the `Mac` and
`MacInit` contracts of [`tc_macs`](https://crates.io/crates/tc_macs) and as
KMACXOF over the `TryXof` trait of
[`tc_digest`](https://crates.io/crates/tc_digest). `no_std` with an allocator,
no `unsafe`, Rust 1.85 or later.

## Types

- `KMac` — KMAC128 or KMAC256 with a customization string; a 32- or 64-byte
  tag, or KMACXOF output of any length.

## Usage

```toml
[dependencies]
tc_kmac = "0.1.0"
tc_macs = "0.1.0"
```

```rust
use tc_kmac::KMac;
use tc_macs::{KeyRef, Mac, MacInit};

let mut mac = KMac::new(256, b"My Tagged Application");
mac.init(&KeyRef::new(&[0x42; 32])).expect("any key");
mac.update(b"attack at dawn").expect("initialized");
let mut tag = [0; 64];
mac.do_final(&mut tag).expect("room for the tag");
```

## Security

KMAC is constant time, as Keccak is; the lengths of the key, the customization
and the message are public. Compare a received tag in constant time. The key is
wiped on drop.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
