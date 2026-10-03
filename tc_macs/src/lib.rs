//! Message authentication codes over block ciphers and digests, and the
//! [`Mac`] and [`MacInit`] contracts they share with MAC crates built on this
//! one, such as `tc_poly1305`.
//!
//! The default build carries only the contracts, their errors and the key
//! containers, so a MAC crate that implements the contracts depends on nothing
//! more. Each MAC is behind its own default-off feature:
//!
//! - `cbc-mac` — `FixedCbcMac`, and `FixedPaddedCbcMac`, which pads the final
//!   block; adds `tc_block_modes` and `tc_block_padding`.
//! - `cfb-mac` — `FixedCfbMac`, and `FixedPaddedCfbMac`, which pads a partial
//!   final segment; adds `tc_block_modes` and `tc_block_padding`.
//! - `cmac` — `FixedCmac`, CMAC (NIST SP 800-38B, RFC 4493) over a 64- or
//!   128-bit block cipher; adds no dependency.
//! - `gmac` — `Gmac`, GMAC (NIST SP 800-38D) over a 128-bit block cipher; adds
//!   `tc_aead_cipher` and `tc_block_modes`.
//! - `hmac` — `FixedHmac`, HMAC (RFC 2104) over a digest; adds `tc_digest`.
//! - `alloc` — `KeyOwned`, and for each MAC enabled the form that sizes its
//!   buffers from the cipher or digest at run time: `CbcMac`, `PaddedCbcMac`,
//!   `CfbMac`, `PaddedCfbMac`, `Cmac` and `Hmac`.
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
//! The crate is `no_std` and contains no `unsafe` code. Only `alloc` reaches
//! the heap; the `Fixed` forms keep their buffers inline, with the block size
//! as the const parameter `N`.
//!
//! Every MAC documents its timing: each is constant time exactly when the
//! cipher or digest it wraps is, and lengths are public. Every MAC wipes its
//! buffers on drop, and the cipher or digest it wraps wipes its own state when
//! that type does, as the engines of `tc_aes`, `tc_des` and `tc_sha` do.
//!
//! # Example
//!
//! With the `cmac` and `hmac` features, generic code authenticates a message
//! through the same calls whatever the MAC:
//!
//! ```
//! # #[cfg(all(feature = "cmac", feature = "hmac"))]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
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
//! # Ok(())
//! # }
//! # #[cfg(not(all(feature = "cmac", feature = "hmac")))]
//! # fn main() {}
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "cbc-mac")]
mod cbc;
#[cfg(feature = "cfb-mac")]
mod cfb;
#[cfg(feature = "cmac")]
mod cmac;
mod errors;
#[cfg(feature = "gmac")]
mod gmac;
#[cfg(feature = "hmac")]
mod hmac;
mod traits;

#[cfg(all(feature = "cbc-mac", feature = "alloc"))]
pub use cbc::CbcMac;
#[cfg(feature = "cbc-mac")]
pub use cbc::FixedCbcMac;
#[cfg(feature = "cbc-mac")]
pub use cbc::FixedPaddedCbcMac;
#[cfg(all(feature = "cbc-mac", feature = "alloc"))]
pub use cbc::PaddedCbcMac;
#[cfg(all(feature = "cfb-mac", feature = "alloc"))]
pub use cfb::CfbMac;
#[cfg(feature = "cfb-mac")]
pub use cfb::FixedCfbMac;
#[cfg(feature = "cfb-mac")]
pub use cfb::FixedPaddedCfbMac;
#[cfg(all(feature = "cfb-mac", feature = "alloc"))]
pub use cfb::PaddedCfbMac;
#[cfg(all(feature = "cmac", feature = "alloc"))]
pub use cmac::Cmac;
#[cfg(feature = "cmac")]
pub use cmac::FixedCmac;
pub use errors::{InitError, MacError};
#[cfg(feature = "gmac")]
pub use gmac::Gmac;
#[cfg(feature = "hmac")]
pub use hmac::FixedHmac;
#[cfg(all(feature = "hmac", feature = "alloc"))]
pub use hmac::Hmac;
#[cfg(feature = "alloc")]
pub use tc_block_cipher::KeyOwned;
pub use tc_block_cipher::{KeyFixed, KeyParams, KeyRef};
pub use traits::{Mac, MacInit};
