//! The GOST 28147-89 message authentication code over the `tc_macs` traits.
//!
//! [`Gost28147Mac`] follows Bouncy Castle's `Gost28147Mac`: 16 rounds of the
//! cipher over 8-byte blocks, a 32-byte key, a 4-byte tag, and a final partial
//! block filled with zeros. It runs through the `tc_macs::Mac` and
//! `tc_macs::MacInit` contracts.
//!
//! [`Gost28147MacParamsRef`] carries the key, the IV and the S-box, which is the
//! CryptoPro E-A S-box unless another is selected. With the default-off `alloc`
//! feature, `Gost28147MacParamsOwned` owns them and wipes them on drop. Types of
//! the caller's own may implement `tc_gost28147::Gost28147Params` and
//! `tc_block_modes::IvParams` instead.
//!
//! The crate is `no_std` and contains no `unsafe` code, and only the `alloc`
//! feature reaches the heap.
//!
//! [`Gost28147Mac`] is variable time: every round indexes the S-box with secret
//! bytes, so cache timing can leak the key and the message. Use it only where
//! that leakage is outside the threat model. A 4-byte tag can also be guessed in
//! about 2^32 tries, so limit how often a verifier may be asked.
//!
//! # Example
//!
//! ```
//! use tc_gost28147_mac::{Gost28147Mac, Gost28147MacParamsRef};
//! use tc_macs::{Mac, MacInit};
//!
//! let mut mac = Gost28147Mac::new();
//! mac.init(&Gost28147MacParamsRef::new(&[0x42; 32], &[0x24; 8]))?;
//! mac.update(b"attack at dawn")?;
//! let mut tag = [0; 4];
//! assert_eq!(mac.do_final(&mut tag)?, tag.len());
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod mac;
mod params;
#[cfg(feature = "alloc")]
mod params_owned;

pub use mac::Gost28147Mac;
pub use params::Gost28147MacParamsRef;
#[cfg(feature = "alloc")]
pub use params_owned::Gost28147MacParamsOwned;
