# Changelog

All notable changes to `tc_kmac` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `KMac`: KMAC128 and KMAC256 (NIST SP 800-185) with a customization string,
  implementing `tc_macs::Mac` and `tc_macs::MacInit` for any
  `tc_macs::KeyParams`, with a tag of 32 or 64 bytes. It also implements
  `tc_digest::TryDigest` and `tc_digest::TryXof`, so `try_output` gives
  KMACXOF, whose output does not depend on its length. Any key length is
  accepted, the empty key included, as Bouncy Castle does, so `init` never
  fails. `Display` writes `"KMAC128"` or `"KMAC256"`, as Bouncy Castle does.
- Every `do_final` checks its output before touching any state, and finishing a
  message starts the next one under the same key.
- Tests against the vectors of Bouncy Castle's `KMACTest`: the six KMAC samples
  of NIST SP 800-185, KMACXOF output, a key whose padding crosses the rate, and
  a long customization string; tests of the error paths and of `reset`; a test
  that every public API documents whether it is constant or variable time; and a
  doctest.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_macs` 0.1, whose default build carries only the contracts,
  `tc_digest` 0.1, `tc_keccak` 0.1 and `tc_zeroize` 0.1. Contains no `unsafe`
  code.
- Needs an allocator, for the key it keeps to start each message again.
- Constant time, as Keccak is. The lengths of the key, the customization and the
  message are public.
- The key is wiped on drop, and the cSHAKE state wipes itself. Wiping does not
  reach the caller's buffers or copies left in registers and on the stack.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
