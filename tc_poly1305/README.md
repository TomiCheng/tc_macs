# tc_poly1305

[![crates.io](https://img.shields.io/crates/v/tc_poly1305.svg)](https://crates.io/crates/tc_poly1305)
[![docs.rs](https://docs.rs/tc_poly1305/badge.svg)](https://docs.rs/tc_poly1305)
[![CI](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The Poly1305 one-time message authentication code (RFC 8439), constant time,
over the `Mac` and `MacInit` contracts of
[`tc_macs`](https://crates.io/crates/tc_macs). Raw Poly1305 with a
caller-supplied 32-byte one-time key; Poly1305-AES is not included. `no_std`,
no allocator, no `unsafe`, Rust 1.85 or later.

## Types

- `Poly1305` — the MAC; implements `tc_macs::Mac` and `tc_macs::MacInit` for
  any `tc_macs::KeyParams`.
- `BLOCK_BYTES`, `KEY_BYTES`, `TAG_BYTES` — the block, key and tag lengths: 16,
  32 and 16 bytes.

## Usage

```toml
[dependencies]
tc_poly1305 = "0.1.0"
tc_macs = "0.1.0"
```

```rust
use tc_macs::{KeyRef, Mac, MacInit};
use tc_poly1305::{Poly1305, TAG_BYTES};

let mut mac = Poly1305::new();
mac.init(&KeyRef::new(&[0x42; 32])).expect("32-byte key");
mac.update(b"attack at dawn").expect("initialized");
let mut tag = [0; TAG_BYTES];
mac.do_final(&mut tag).expect("room for the tag");
```

## Security

A Poly1305 key must never authenticate two messages, so `do_final` consumes
it: the key is wiped and the MAC refuses input until it is initialized with a
fresh one. This is stricter than Bouncy Castle, which keeps the key. Compare a
received tag in constant time. `Poly1305` is constant time, and it wipes the
key and the message state on drop; a clone is another copy of the key.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
