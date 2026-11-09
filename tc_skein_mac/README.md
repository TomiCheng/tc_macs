# tc_skein_mac

[![crates.io](https://img.shields.io/crates/v/tc_skein_mac.svg)](https://crates.io/crates/tc_skein_mac)
[![docs.rs](https://docs.rs/tc_skein_mac/badge.svg)](https://docs.rs/tc_skein_mac)
[![CI](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Skein-MAC with a 256-, 512- or 1024-bit state, over the `Mac` and `MacInit`
contracts of [`tc_macs`](https://crates.io/crates/tc_macs). `no_std`, no
`unsafe`, Rust 1.85 or later.

## Types

- `SkeinMac` — the MAC, with a key of at least 16 bytes and a tag of any whole
  number of bytes.
- `SkeinParamsRef` — borrowed Skein parameters: the key, and optionally a
  personalisation, public key, key identifier or nonce.
- `SkeinParamsOwned` (`alloc`) — the same parameters owned, and wiped on drop.

## Traits

- `SkeinParams` — the parameters `init` takes, re-exported from `tc_skein`.

## Features

- `alloc` (off by default) — `SkeinParamsOwned`. The MAC itself never
  allocates.

## Usage

```toml
[dependencies]
tc_macs = "0.1.0"
tc_skein_mac = "0.1.0"
```

```rust
use tc_macs::{Mac, MacInit};
use tc_skein_mac::{SkeinMac, SkeinParamsRef};

let mut mac = SkeinMac::new(SkeinMac::SKEIN_512, 256);
mac.init(&SkeinParamsRef::new().with_key(&[0x42; 32])).expect("a key");
mac.update(b"attack at dawn").expect("initialized");
let mut tag = [0; 32];
mac.do_final(&mut tag).expect("room for the tag");
```

## Security

Skein-MAC is constant time, as Skein is: Threefish uses only additions,
rotations and XORs. Compare a received tag in constant time. The Skein state
wipes itself on drop.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
