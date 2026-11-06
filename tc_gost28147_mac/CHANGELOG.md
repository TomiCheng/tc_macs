# Changelog

All notable changes to `tc_gost28147_mac` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `Gost28147Mac`: the GOST 28147-89 MAC with a 32-byte key, a 128-byte S-box, an
  8-byte IV and a 4-byte tag, implementing `tc_macs::Mac` and `tc_macs::MacInit`
  for any `tc_gost28147::Gost28147Params` that is also a
  `tc_block_modes::IvParams`. A key, an S-box or an IV of another length is
  refused and leaves the MAC uninitialized.
- `do_final` checks its output before touching any state, and starts the next
  message under the same parameters. As in Bouncy Castle, a message of one block
  or less ignores the IV.
- `Gost28147MacParamsRef`: a borrowed key, IV and S-box, with the CryptoPro E-A
  S-box unless `with_s_box` selects another. An all-zero IV gives Bouncy Castle's
  form keyed without one.
- `Gost28147MacParamsOwned` behind the default-off `alloc` feature: the same
  parameters in vectors, wiped on drop, whose `Debug` prints only the lengths.
- `const fn new`, `Default`, and `Display`, which writes `"Gost28147Mac"` as
  Bouncy Castle does.
- Tests against the zero-IV vector of Bouncy Castle's `GOST28147MacTest` and
  vectors produced with Bouncy Castle's `Gost28147Mac`; tests of the error paths
  and of `reset`; a test that every public API documents whether it is constant
  or variable time; and a doctest.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_macs` 0.1, whose default build carries only the contracts,
  `tc_block_cipher` 0.1, `tc_block_modes` 0.1, `tc_gost28147` 0.1 and
  `tc_zeroize` 0.1. Contains no `unsafe` code, and only the `alloc` feature
  reaches the heap.
- Variable time: every round indexes the S-box with secret bytes. Lengths are
  public.
- The key, the S-box, the IV and the message state are wiped on drop. Wiping does
  not reach the caller's buffers or copies left in registers and on the stack.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
