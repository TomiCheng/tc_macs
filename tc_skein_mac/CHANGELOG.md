# Changelog

All notable changes to `tc_skein_mac` are documented in this file.

## 0.1.0 - 2026-11-09

Initial release.

### Added

- `SkeinMac`: Skein-MAC with a 256-, 512- or 1024-bit state and a tag of any
  whole number of bytes, implementing `tc_macs::Mac` and `tc_macs::MacInit` for
  any `SkeinParams`; `init` reports a missing key or one shorter than 16 bytes
  as `InvalidKeyLength`, as Bouncy Castle throws. `new` panics on an invalid
  state or tag size, as Bouncy Castle throws. `Display` writes the Bouncy Castle
  name, such as `"Skein-MAC-512-256"`.
- The `SKEIN_256`, `SKEIN_512` and `SKEIN_1024` state sizes.
- `SkeinParams` and `SkeinParamsRef`, re-exported from `tc_skein`, and with the
  default-off `alloc` feature `SkeinParamsOwned`, which wipes the parameters on
  drop.
- Every `do_final` checks its output before touching any state, and starts the
  next message under the same parameters. A failed `init` leaves the MAC
  uninitialized.
- Tests against the vectors of Bouncy Castle's `SkeinMacTest`, in one piece and
  byte by byte; tests of the error paths, of `reset`, of a clone and of the other
  Skein parameters; a test that every public API documents whether it is
  constant or variable time; and a doctest.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_macs` 0.1, whose default build carries only the contracts, and
  `tc_skein` 0.1. Contains no `unsafe` code, and never allocates.
- Constant time, as Skein is. The lengths of the parameters and the message are
  public.
- The Skein state, which holds the keyed chaining value, wipes itself on drop.
  Wiping does not reach the caller's buffers or copies left in registers and on
  the stack.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
