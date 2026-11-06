# tc_gost28147_mac

[![crates.io](https://img.shields.io/crates/v/tc_gost28147_mac.svg)](https://crates.io/crates/tc_gost28147_mac)
[![docs.rs](https://docs.rs/tc_gost28147_mac/badge.svg)](https://docs.rs/tc_gost28147_mac)
[![CI](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The GOST 28147-89 message authentication code, over the `Mac` and `MacInit`
contracts of [`tc_macs`](https://crates.io/crates/tc_macs). `no_std`, no
`unsafe`, Rust 1.85 or later.

## Types

- `Gost28147Mac` — the MAC, with a 32-byte key and a 4-byte tag.
- `Gost28147MacParamsRef` — a borrowed key, 8-byte IV and S-box, which is the
  CryptoPro E-A S-box unless another is selected.
- `Gost28147MacParamsOwned` (`alloc`) — the same parameters owned, and wiped on
  drop.

## Features

- `alloc` (off by default) — `Gost28147MacParamsOwned`. The MAC itself never
  allocates.

## Usage

```toml
[dependencies]
tc_gost28147_mac = "0.1.0"
tc_macs = "0.1.0"
```

```rust
use tc_gost28147_mac::{Gost28147Mac, Gost28147MacParamsRef};
use tc_macs::{Mac, MacInit};

let mut mac = Gost28147Mac::new();
let params = Gost28147MacParamsRef::new(&[0x42; 32], &[0x24; 8]);
mac.init(&params).expect("valid lengths");
mac.update(b"attack at dawn").expect("initialized");
let mut tag = [0; 4];
mac.do_final(&mut tag).expect("room for the tag");
```

## Security

`Gost28147Mac` is variable time: every round indexes the S-box with secret bytes,
so cache timing can leak the key and the message. Use it only where that leakage
is outside the threat model. A 4-byte tag can be guessed in about 2^32 tries, so
limit how often a verifier may be asked. As in Bouncy Castle, a message of one
block or less ignores the IV. Compare a received tag in constant time. The MAC
wipes its key and message state on drop.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
