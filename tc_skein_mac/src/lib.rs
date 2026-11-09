//! Skein-MAC over the `tc_macs` traits.
//!
//! [`SkeinMac`] is the keyed form of the Skein 1.3 hash function, with a 256-,
//! 512- or 1024-bit state and a tag of any whole number of bytes. It follows
//! Bouncy Castle's `SkeinMac`, and runs through the `tc_macs::Mac` and
//! `tc_macs::MacInit` contracts. The key, and any other Skein parameter, comes
//! through the [`SkeinParams`] trait of `tc_skein`: [`SkeinParamsRef`] borrows
//! them, and with the `alloc` feature `SkeinParamsOwned` owns them and wipes
//! them on drop.
//!
//! The crate is `no_std`, never allocates, and contains no `unsafe` code.
//!
//! Skein-MAC is constant time, as Skein is: Threefish uses only additions,
//! rotations and XORs. The lengths of the parameters and the message are
//! public.
//!
//! # Example
//!
//! ```
//! use tc_macs::{Mac, MacInit};
//! use tc_skein_mac::{SkeinMac, SkeinParamsRef};
//!
//! let mut mac = SkeinMac::new(SkeinMac::SKEIN_512, 256);
//! mac.init(&SkeinParamsRef::new().with_key(&[0x42; 32]))?;
//! mac.update(b"attack at dawn")?;
//! let mut tag = [0; 32];
//! assert_eq!(mac.do_final(&mut tag)?, tag.len());
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod skein_mac;

pub use skein_mac::SkeinMac;
#[cfg(feature = "alloc")]
pub use tc_skein::SkeinParamsOwned;
pub use tc_skein::{SkeinParams, SkeinParamsRef};
