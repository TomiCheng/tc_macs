//! Message authentication codes over block ciphers and digests, and the
//! [`Mac`] and [`MacInit`] contracts they share with MAC crates built on this
//! one, such as `tc_poly1305`.
//!
//! - [`FixedCbcMac`] and `CbcMac` (`alloc`) — CBC-MAC, with
//!   [`FixedPaddedCbcMac`] and `PaddedCbcMac` (`alloc`) padding the final
//!   block.
//! - [`FixedCfbMac`] and `CfbMac` (`alloc`) — CFB-MAC, with
//!   [`FixedPaddedCfbMac`] and `PaddedCfbMac` (`alloc`) padding the final
//!   segment.
//! - [`FixedCmac`] and `Cmac` (`alloc`) — CMAC (NIST SP 800-38B, RFC 4493)
//!   over a 64- or 128-bit block cipher.
//! - [`Gmac`] — GMAC (NIST SP 800-38D) over a 128-bit block cipher.
//! - [`FixedHmac`] and `Hmac` (`alloc`) — HMAC (RFC 2104) over a digest.
//!
//! The block-cipher MACs run over any engine that implements the
//! `tc_block_cipher` traits, such as `tc_aes`, and HMAC over any digest that
//! implements `tc_digest::Digest`, such as those of `tc_sha`. Each follows the
//! Bouncy Castle class of its family, including its default tag size and its
//! name.
//!
//! Every MAC takes its key through [`KeyParams`]; [`KeyRef`], [`KeyFixed`] and
//! `KeyOwned` (`alloc`) are re-exported from `tc_block_cipher`. CBC-MAC,
//! CFB-MAC and GMAC also take an IV through `tc_block_modes::IvParams`, which
//! `tc_block_modes::KeyWithIvRef` provides together with the key.
//!
//! The crate is `no_std` and contains no `unsafe` code. The default-off `alloc`
//! feature adds the MACs that size their buffers from the cipher at run time,
//! and `KeyOwned`; the `Fixed` forms keep theirs inline, with the block size as
//! the const parameter `N`.
//!
//! Every MAC documents its timing: each is constant time exactly when the
//! cipher or digest it wraps is, and lengths are public. Every MAC wipes its
//! buffers on drop, and the cipher or digest it wraps wipes its own state when
//! that type does, as the engines of `tc_aes`, `tc_des` and `tc_sha` do.
//!
//! # Example
//!
//! Generic code authenticates a message through the same calls whatever the
//! MAC:
//!
//! ```
//! use tc_aes::AesEngine;
//! use tc_macs::{FixedCmac, FixedHmac, KeyRef, Mac, MacInit};
//! use tc_sha::Sha256Digest;
//!
//! fn tag<M: Mac>(mac: &mut M, message: &[u8]) -> Result<Vec<u8>, M::Error> {
//!     mac.update(message)?;
//!     let mut tag = vec![0; mac.mac_size()];
//!     mac.do_final(&mut tag)?;
//!     Ok(tag)
//! }
//!
//! let key = KeyRef::new(&[0x42; 16]);
//!
//! let mut cmac = FixedCmac::<_, 16>::new(AesEngine::new());
//! cmac.init(&key)?;
//! assert_eq!(tag(&mut cmac, b"attack at dawn")?.len(), 16);
//!
//! let mut hmac = FixedHmac::new(Sha256Digest::new());
//! hmac.init(&key)?;
//! assert_eq!(tag(&mut hmac, b"attack at dawn")?.len(), 32);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod cbc;
mod cfb;
mod cmac;
mod errors;
mod gmac;
mod hmac;
mod traits;

#[cfg(feature = "alloc")]
pub use cbc::CbcMac;
pub use cbc::FixedCbcMac;
pub use cbc::FixedPaddedCbcMac;
#[cfg(feature = "alloc")]
pub use cbc::PaddedCbcMac;
#[cfg(feature = "alloc")]
pub use cfb::CfbMac;
pub use cfb::FixedCfbMac;
pub use cfb::FixedPaddedCfbMac;
#[cfg(feature = "alloc")]
pub use cfb::PaddedCfbMac;
#[cfg(feature = "alloc")]
pub use cmac::Cmac;
pub use cmac::FixedCmac;
pub use errors::{InitError, MacError};
pub use gmac::Gmac;
pub use hmac::FixedHmac;
#[cfg(feature = "alloc")]
pub use hmac::Hmac;
#[cfg(feature = "alloc")]
pub use tc_block_cipher::KeyOwned;
pub use tc_block_cipher::{KeyFixed, KeyParams, KeyRef};
pub use traits::{Mac, MacInit};
