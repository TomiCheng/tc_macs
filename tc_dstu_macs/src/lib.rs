//! The DSTU 7564 and DSTU 7624 message authentication codes over the `tc_macs`
//! traits.
//!
//! [`Dstu7564Mac`] is the keyed construction of the DSTU 7564 (Kupyna) digest,
//! with a 256-, 384- or 512-bit tag. [`Dstu7624Mac`] is the MAC of the DSTU 7624
//! (Kalyna) block cipher over a 128-, 256- or 512-bit block, whose message must
//! be a whole number of blocks. Each follows its Bouncy Castle class, and runs
//! through the `tc_macs::Mac` and `tc_macs::MacInit` contracts.
//!
//! The crate is `no_std` and contains no `unsafe` code. [`Dstu7564Mac`] needs an
//! allocator, for the key it keeps; [`Dstu7624Mac`] does not use one.
//!
//! Both are variable time: their primitives index S-boxes with secret bytes, so
//! cache timing can leak the key and the message. Use them only where that
//! leakage is outside the threat model.
//!
//! # Example
//!
//! ```
//! use tc_dstu_macs::Dstu7564Mac;
//! use tc_macs::{KeyRef, Mac, MacInit};
//!
//! let mut mac = Dstu7564Mac::new(256);
//! mac.init(&KeyRef::new(&[0x42; 32]))?;
//! mac.update(b"attack at dawn")?;
//! let mut tag = [0; 32];
//! assert_eq!(mac.do_final(&mut tag)?, tag.len());
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

mod dstu7564;
mod dstu7624;

pub use dstu7564::Dstu7564Mac;
pub use dstu7624::{
    Dstu7624Mac, Dstu7624Mac128, Dstu7624Mac256, Dstu7624Mac512, Dstu7624MacCreateError,
    Dstu7624MacError,
};

/// The tag lengths [`Dstu7564Mac`] supports, in bits.
pub const MAC_BITS: [usize; 3] = [256, 384, 512];
