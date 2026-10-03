# Changelog

All notable changes to `tc_macs` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- The `Mac` contract, which sizes the tag, takes a message in pieces with
  `update`, writes the tag into a caller-provided buffer with `do_final` and
  discards a message with `reset`, and can be used as `dyn Mac<Error = E>`;
  and the separate `MacInit` contract, which keys a MAC from parameters of type
  `P`. Together they are the Rust form of Bouncy Castle's `IMac`.
- `InitError` and `MacError`, which wrap the primitive's error and report it
  through `source`.
- `FixedCbcMac` and `FixedPaddedCbcMac` and, with the default-off `alloc`
  feature, `CbcMac` and `PaddedCbcMac`: CBC-MAC over a `tc_block_cipher`
  engine, keyed with a key and an IV of one block, with a tag of half a block
  by default. Without padding a partial final block is filled with zeros; with
  padding a full final block is followed by a block of padding alone.
- `FixedCfbMac` and `FixedPaddedCfbMac` and, with `alloc`, `CfbMac` and
  `PaddedCfbMac`: CFB-MAC keyed with a key and an IV of one block, with 8-bit
  feedback and a tag of half a block by default. The padded forms pad only a
  partial final segment, as Bouncy Castle does.
- `FixedCmac` and, with `alloc`, `Cmac`: CMAC (NIST SP 800-38B, RFC 4493) over
  64- and 128-bit block ciphers, keyed with a key alone, with a tag of a whole
  block by default.
- `Gmac`: GMAC (NIST SP 800-38D) over a 128-bit block cipher, with tags of 4 to
  16 bytes. It refuses at `init` the key and nonce of the previous `init`, and
  after `do_final` it stays finalized until a fresh nonce.
- `FixedHmac`, over a cloneable digest with up to 128 bytes of output, and,
  with `alloc`, `Hmac`, over any digest: HMAC (RFC 2104) over a
  `tc_digest::Digest`, keyed with a key of any length.
- `KeyRef`, `KeyFixed`, `KeyParams` and, with `alloc`, `KeyOwned`, re-exported
  from `tc_block_cipher`.
- A failed `init` leaves every MAC uninitialized. `update` and `do_final` fail
  before `init`, and a short output buffer is refused without losing the
  message.
- `Display` for every MAC, writing Bouncy Castle's name, such as `"AES/CBC"`,
  `"DES/CFB8"`, `"AES-GMAC"` or `"SHA-256/HMAC"`; CMAC writes `"AES/CMAC"`
  rather than the name of its inner CBC mode, which CBC-MAC shares.
- Tests against the DES CBC-MAC and CFB-MAC vectors and the DESede CMAC vector
  of Bouncy Castle's `MacTest`, the AES-128, AES-192 and AES-256 CMAC examples
  of NIST SP 800-38B, the GMAC vectors of Bouncy Castle's `GMacTest`, which are
  NIST GCM vectors with associated data alone, and the HMAC-SHA-256 and
  HMAC-SHA-512 vectors of RFC 4231, at every split of the input; tests that the
  allocating forms match the fixed ones; tests of the error paths; a test that
  every public API documents whether it is constant or variable time; and
  doctests for every MAC.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_aead_cipher` 0.1, `tc_block_cipher` 0.1, `tc_block_modes`
  0.1, `tc_block_padding` 0.1, `tc_digest` 0.1 and `tc_zeroize` 0.1. Contains
  no `unsafe` code.
- Every MAC is constant time exactly when the cipher or digest it wraps is;
  lengths are public.
- CBC-MAC and CFB-MAC are secure only for messages of one fixed length.
- CBC-MAC and CFB-MAC require an IV of exactly one block, where Bouncy Castle
  also accepts a shorter one.
- The constructors panic on a tag, feedback or block size the MAC does not
  support.
- Every MAC wipes its buffers on drop; the wrapped cipher or digest wipes its
  own state when its type does. Wiping does not reach the caller's buffers or
  copies left in registers and on the stack.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
