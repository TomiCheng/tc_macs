# Changelog

All notable changes to `tc_iso9797_mac` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `Iso9797Alg3Mac`: the ISO/IEC 9797-1 MAC algorithm 3 over DES, the ANSI X9.19
  retail MAC, with a 16- or 24-byte key, an 8-byte IV and a tag of whole bytes
  up to 8, implementing `tc_macs::Mac` and `tc_macs::MacInit` for any
  `tc_macs::KeyParams` that is also a `tc_block_modes::IvParams`. Bouncy Castle
  also takes a key alone, with a zero IV; here the IV is required, as for
  CBC-MAC in `tc_macs`, so pass 8 zero bytes for that. `Display` writes
  `"ISO9797Alg3"`, as Bouncy Castle does.
- `NoPadding`, which fills a partial final block with zeros as Bouncy Castle
  does by default, and `WithPadding`, which pads with a `tc_block_padding`
  scheme and follows a full final block with a block of padding alone; the
  sealed `Iso9797Padding` trait they implement.
- `Iso9797Alg3MacCreateError`, for a tag length outside whole bytes from 8 to
  64 bits, where Bouncy Castle checks only the whole bytes.
- Every `do_final` checks its output before touching any state, and starts the
  next message under the same key and IV. `reset` restarts the chain from the
  IV, as Bouncy Castle's Java `reset` does; its C# `Reset` leaves the chain
  where the last message ended. A failed `init` leaves the MAC uninitialized.
- Tests against the vector of Bouncy Castle's `ISO9797Alg3MacTest`; the
  triple-length key, an IV and padding against DES chained by hand; tests of
  the error paths and of `reset`; a test that every public API documents whether
  it is constant or variable time; and a doctest.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_macs` 0.1, whose default build carries only the contracts,
  `tc_block_cipher` 0.1, `tc_block_modes` 0.1, `tc_block_padding` 0.1,
  `tc_des` 0.1 and `tc_zeroize` 0.1. Contains no `unsafe` code and never
  allocates.
- Variable time, as DES is: every DES engine looks up S-boxes with secret data.
  Lengths are public.
- The IV, the chain and the message state are wiped on drop, and each DES
  engine wipes its key schedule. Wiping does not reach the caller's buffers or
  copies left in registers and on the stack.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
