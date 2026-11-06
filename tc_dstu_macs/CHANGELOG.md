# Changelog

All notable changes to `tc_dstu_macs` are documented in this file.

## 0.1.0 - 2026-11-06

Initial release.

### Added

- `Dstu7564Mac`: the keyed DSTU 7564 digest with a 256-, 384- or 512-bit tag and
  a key of at least one byte, implementing `tc_macs::Mac` and `tc_macs::MacInit`
  for any `tc_macs::KeyParams`. `new` panics on any other tag length, as the
  digest's does. A key of a whole number of digest blocks is padded with one
  more block, where Bouncy Castle's padding overruns its buffer and throws.
  `Display` writes `"DSTU7564Mac"`, as Bouncy Castle does.
- `Dstu7624Mac`, with the `Dstu7624Mac128`, `Dstu7624Mac256` and `Dstu7624Mac512`
  forms: the DSTU 7624 MAC with a tag of whole bytes up to the block size, and a
  message of a whole number of blocks. `new` reports a bad tag length through
  `Dstu7624MacCreateError`, and `do_final` reports an unaligned message through
  `Dstu7624MacError` with the message left in place. `Display` writes
  `"Dstu7624Mac"`, as Bouncy Castle does.
- The `MAC_BITS` constant, the tag lengths of `Dstu7564Mac`.
- Every `do_final` checks its input and output before touching any state, and
  starts the next message under the same key. A failed `init` leaves the MAC
  uninitialized.
- Tests against the vectors of Bouncy Castle's `DSTU7564Test` and `DSTU7624Test`;
  the 256-bit block, for which Bouncy Castle has no vector, against the cipher
  chained by hand; tests of the error paths and of `reset`; a test that every
  public API documents whether it is constant or variable time; and a doctest.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_macs` 0.1, whose default build carries only the contracts,
  `tc_block_cipher` 0.1, `tc_digest` 0.1, `tc_dstu7564` 0.1, `tc_dstu7624` 0.1
  and `tc_zeroize` 0.1. Contains no `unsafe` code.
- `Dstu7564Mac` needs an allocator; `Dstu7624Mac` does not use one.
- Variable time, as its primitives are: they index S-boxes with secret bytes.
  Lengths are public.
- The key and the message state are wiped on drop. Wiping does not reach the
  caller's buffers or copies left in registers and on the stack.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
