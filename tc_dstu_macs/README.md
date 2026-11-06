# tc_dstu_macs

[![crates.io](https://img.shields.io/crates/v/tc_dstu_macs.svg)](https://crates.io/crates/tc_dstu_macs)
[![docs.rs](https://docs.rs/tc_dstu_macs/badge.svg)](https://docs.rs/tc_dstu_macs)
[![CI](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

The DSTU 7564 (Kupyna) and DSTU 7624 (Kalyna) message authentication codes, over
the `Mac` and `MacInit` contracts of
[`tc_macs`](https://crates.io/crates/tc_macs). `no_std` with an allocator, no
`unsafe`, Rust 1.85 or later.

## Types

- `Dstu7564Mac` — the keyed DSTU 7564 digest, with a 256-, 384- or 512-bit tag.
- `Dstu7624Mac128`, `Dstu7624Mac256`, `Dstu7624Mac512` — the DSTU 7624 MAC over
  a 128-, 256- or 512-bit block, forms of the generic `Dstu7624Mac`.
- `Dstu7624MacCreateError`, `Dstu7624MacError` — the failures of the DSTU 7624
  MAC, whose message must be a whole number of blocks.
- `MAC_BITS` — the tag lengths of `Dstu7564Mac`, in bits.

## Usage

```toml
[dependencies]
tc_dstu_macs = "0.1.0"
tc_macs = "0.1.0"
```

```rust
use tc_dstu_macs::Dstu7564Mac;
use tc_macs::{KeyRef, Mac, MacInit};

let mut mac = Dstu7564Mac::new(256);
mac.init(&KeyRef::new(&[0x42; 32])).expect("a key");
mac.update(b"attack at dawn").expect("initialized");
let mut tag = [0; 32];
mac.do_final(&mut tag).expect("room for the tag");
```

## Security

Both MACs are variable time: their primitives index S-boxes with secret bytes,
so cache timing can leak the key and the message. Use them only where that
leakage is outside the threat model. Compare a received tag in constant time.
Each wipes its key and message state on drop.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
