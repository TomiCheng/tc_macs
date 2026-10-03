# Changelog

All notable changes to `tc_poly1305` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `Poly1305`: raw Poly1305 (RFC 8439) with a 32-byte one-time key supplied
  through any `tc_macs::KeyParams`, implementing `tc_macs::Mac` and
  `tc_macs::MacInit`, with a 16-byte tag.
- `do_final` consumes the one-time key: it wipes the key and leaves the MAC
  uninitialized until the next `init`, which is stricter than Bouncy Castle.
  `reset` before `do_final` discards the message and keeps the key, and a short
  output buffer is refused without consuming it. A key of any other length is
  refused with `InvalidKeyLength` and leaves the MAC uninitialized.
- The `BLOCK_BYTES`, `KEY_BYTES` and `TAG_BYTES` constants.
- `const fn new`, `Default`, `Clone`, and `Display`, which writes
  `"Poly1305"` as Bouncy Castle does.
- Tests against the RFC 8439 vector of section 2.5.2 at every chunk size and a
  raw Poly1305 vector from Bouncy Castle; tests of the empty message, the
  consumed key and the error paths; a test that every public API documents
  whether it is constant or variable time; and a doctest.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_macs` 0.1, whose default build carries only the contracts,
  and `tc_zeroize` 0.1. Contains no `unsafe` code.
- Constant time; lengths are public.
- Poly1305-AES, the block-cipher construction, is not included.
- The key and the message state are wiped on drop. Wiping does not reach the
  caller's buffers, a clone, or copies left in registers and on the stack.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
