//! The Poly1305 one-time message authentication code (RFC 8439) over the
//! `tc_macs` traits.
//!
//! [`Poly1305`] is raw Poly1305 with a caller-supplied 32-byte one-time key,
//! as ChaCha20-Poly1305 derives from its keystream. It does not implement the
//! optional block-cipher construction, Poly1305-AES. The key goes in through
//! any `tc_macs::KeyParams`, such as `tc_macs::KeyRef`, and the MAC runs
//! through the `tc_macs::Mac` and `tc_macs::MacInit` contracts.
//!
//! A Poly1305 key must never authenticate two messages, so `do_final` consumes
//! it: the MAC wipes the key and refuses further input until it is initialized
//! with a fresh one. This is stricter than Bouncy Castle, which keeps the key.
//!
//! The crate is `no_std`, needs no allocator and contains no `unsafe` code.
//! Poly1305 is constant time: it multiplies 26-bit limbs into 64-bit products
//! and reduces without branches, and only lengths decide the work.
//!
//! # Example
//!
//! ```
//! use tc_macs::{KeyRef, Mac, MacError, MacInit};
//! use tc_poly1305::{Poly1305, TAG_BYTES};
//!
//! // RFC 8439, section 2.5.2.
//! let key = [
//!     0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
//!     0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
//!     0xf5, 0x1b,
//! ];
//! let mut mac = Poly1305::new();
//! mac.init(&KeyRef::new(&key))?;
//! mac.update(b"Cryptographic Forum Research Group")?;
//! let mut tag = [0; TAG_BYTES];
//! mac.do_final(&mut tag)?;
//! assert_eq!(
//!     tag,
//!     [
//!         0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
//!         0x27, 0xa9,
//!     ]
//! );
//!
//! // The key is used up; the next message needs a fresh one.
//! assert_eq!(mac.update(b"again"), Err(MacError::NotInitialised));
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod mac;

pub use mac::Poly1305;

/// Poly1305 input block length in bytes.
pub const BLOCK_BYTES: usize = 16;
/// Poly1305 one-time key length in bytes: the 16-byte `r`, which is clamped,
/// followed by the 16-byte `s`.
pub const KEY_BYTES: usize = 32;
/// Poly1305 authentication-tag length in bytes.
pub const TAG_BYTES: usize = 16;
