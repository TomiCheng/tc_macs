# tc_iso9797_mac

[![crates.io](https://img.shields.io/crates/v/tc_iso9797_mac.svg)](https://crates.io/crates/tc_iso9797_mac)
[![docs.rs](https://docs.rs/tc_iso9797_mac/badge.svg)](https://docs.rs/tc_iso9797_mac)
[![CI](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The ISO/IEC 9797-1 MAC algorithm 3 over DES, the ANSI X9.19 retail MAC, over
the `Mac` and `MacInit` contracts of
[`tc_macs`](https://crates.io/crates/tc_macs). `no_std`, no allocator, no
`unsafe`, Rust 1.85 or later.

## Types

- `Iso9797Alg3Mac` — the MAC, with a 16- or 24-byte key, an 8-byte IV and a tag
  of up to 8 bytes.
- `NoPadding`, `WithPadding` — how the final block is completed: with zeros, or
  with a `tc_block_padding` scheme.
- `Iso9797Alg3MacCreateError` — a tag length the MAC cannot produce.

## Traits

- `Iso9797Padding` — the sealed bound that `NoPadding` and `WithPadding` meet.

## Usage

```toml
[dependencies]
tc_block_modes = "0.1.0"
tc_iso9797_mac = "0.1.0"
tc_macs = "0.1.0"
```

```rust
use tc_block_modes::KeyWithIvRef;
use tc_iso9797_mac::Iso9797Alg3Mac;
use tc_macs::{Mac, MacInit};

let mut mac = Iso9797Alg3Mac::new();
mac.init(&KeyWithIvRef::new(&[0x42; 16], &[0; 8])).expect("valid lengths");
mac.update(b"attack at dawn").expect("initialized");
let mut tag = [0; 8];
mac.do_final(&mut tag).expect("room for the tag");
```

## Security

The MAC is variable time, as DES is: it looks up S-boxes with secret data, so
cache timing can leak the key and the message. DES and this MAC are kept for
legacy protocols; do not choose them for new designs. Compare a received tag in
constant time. The MAC wipes its IV, chain and message state on drop.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
