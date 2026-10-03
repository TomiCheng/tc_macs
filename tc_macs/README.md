# tc_macs

[![crates.io](https://img.shields.io/crates/v/tc_macs.svg)](https://crates.io/crates/tc_macs)
[![docs.rs](https://docs.rs/tc_macs/badge.svg)](https://docs.rs/tc_macs)
[![CI](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_macs/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Message authentication codes over block ciphers and digests: CBC-MAC,
CFB-MAC, CMAC, GMAC and HMAC, and the `Mac` and `MacInit` contracts they share
with MAC crates such as [`tc_poly1305`](https://crates.io/crates/tc_poly1305).
Ported from Bouncy Castle C#. `no_std`, no `unsafe`, Rust 1.85 or later.

The default build carries only the contracts, their errors and the key
containers, and depends on `tc_block_cipher` and `tc_zeroize`; each MAC is
behind its own feature.

## Types

- `FixedCbcMac`, `CbcMac` (`cbc-mac`) — CBC-MAC, for messages of one fixed
  length.
- `FixedPaddedCbcMac`, `PaddedCbcMac` (`cbc-mac`) — CBC-MAC that pads the
  final block.
- `FixedCfbMac`, `CfbMac` (`cfb-mac`) — CFB-MAC, for messages of one fixed
  length.
- `FixedPaddedCfbMac`, `PaddedCfbMac` (`cfb-mac`) — CFB-MAC that pads a
  partial final segment.
- `FixedCmac`, `Cmac` (`cmac`) — CMAC (NIST SP 800-38B, RFC 4493) over a 64-
  or 128-bit block cipher.
- `Gmac` (`gmac`) — GMAC (NIST SP 800-38D) over a 128-bit block cipher.
- `FixedHmac`, `Hmac` (`hmac`) — HMAC (RFC 2104) over a `tc_digest` digest.
- `InitError`, `MacError` — initialization and processing errors that wrap the
  primitive's.
- `KeyRef`, `KeyFixed`, `KeyOwned` (`alloc`) — key containers re-exported from
  `tc_block_cipher`.

The `Fixed` forms keep their buffers inline, with the block size as a const
parameter; the others also need `alloc` and size them from the cipher or
digest at run time.

## Traits

- `Mac` — `mac_size`, `update`, `do_final` and `reset` over caller-provided
  buffers; usable as `dyn Mac<Error = E>`.
- `MacInit` — keys a MAC from parameters of type `P`.
- `KeyParams` — the key a parameter type provides; re-exported from
  `tc_block_cipher`.

## Features

- `cbc-mac` (off by default) — CBC-MAC; adds `tc_block_modes` and
  `tc_block_padding`.
- `cfb-mac` (off by default) — CFB-MAC; adds `tc_block_modes` and
  `tc_block_padding`.
- `cmac` (off by default) — CMAC; adds no dependency.
- `gmac` (off by default) — GMAC; adds `tc_aead_cipher` and `tc_block_modes`.
- `hmac` (off by default) — HMAC; adds `tc_digest`.
- `alloc` (off by default) — the MACs sized at run time, and `KeyOwned`; does
  not require the standard library.

## Usage

```toml
[dependencies]
tc_macs = { version = "0.1.0", features = ["cmac"] }
tc_aes = "0.1.0"
```

```rust
use tc_aes::AesEngine;
use tc_macs::{FixedCmac, KeyRef, Mac, MacInit};

let mut mac = FixedCmac::<_, 16>::new(AesEngine::new());
mac.init(&KeyRef::new(&[0x42; 16])).expect("valid key");
mac.update(b"attack at dawn").expect("initialized");
let mut tag = [0; 16];
mac.do_final(&mut tag).expect("room for the tag");
```

## Security

CBC-MAC and CFB-MAC are secure only for messages of one fixed length; use
CMAC, GMAC or HMAC where lengths vary. A GMAC nonce must never repeat under one
key. Compare a received tag in constant time. Each MAC is constant time
exactly when the cipher or digest it wraps is: `tc_aes::AesEngine` is constant
time unless it falls back to its table engine, and the engines of `tc_des` are
variable time. Every MAC wipes its buffers on drop.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
