//! The ISO/IEC 9797-1 MAC algorithm 3 over DES, also known as the ANSI X9.19
//! retail MAC, over the `tc_macs` traits.
//!
//! [`Iso9797Alg3Mac`] chains the message through single DES in CBC mode under
//! the first part of a double- or triple-length key, then decrypts the last
//! block under the second part and encrypts it again under the third, which is
//! the first for a double-length key. It follows Bouncy Castle's
//! `ISO9797Alg3Mac`, and runs through the `tc_macs::Mac` and `tc_macs::MacInit`
//! contracts.
//!
//! The crate is `no_std`, never allocates, and contains no `unsafe` code.
//!
//! The MAC is variable time, as DES is: every DES engine looks up S-boxes with
//! secret data, so cache timing can leak the key and the message. Use it only
//! where that leakage is outside the threat model.
//!
//! # Example
//!
//! ```
//! use tc_block_modes::KeyWithIvRef;
//! use tc_iso9797_mac::Iso9797Alg3Mac;
//! use tc_macs::{Mac, MacInit};
//!
//! let mut mac = Iso9797Alg3Mac::new();
//! mac.init(&KeyWithIvRef::new(&[0x42; 16], &[0; 8]))?;
//! mac.update(b"attack at dawn")?;
//! let mut tag = [0; 8];
//! assert_eq!(mac.do_final(&mut tag)?, tag.len());
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod errors;
mod mac;
mod padding;

pub use errors::Iso9797Alg3MacCreateError;
pub use mac::Iso9797Alg3Mac;
pub use padding::{Iso9797Padding, NoPadding, WithPadding};
