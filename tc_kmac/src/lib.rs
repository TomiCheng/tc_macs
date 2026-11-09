//! KMAC128 and KMAC256 (NIST SP 800-185) over the `tc_macs` traits.
//!
//! [`KMac`] is the MAC of the Keccak family: cSHAKE under the function name
//! `"KMAC"`, keyed by the padded key and closed by the output length. It
//! follows Bouncy Castle's `KMac`. Through `tc_macs::Mac` it gives a tag of
//! twice its strength, 32 bytes for KMAC128 and 64 for KMAC256; through
//! `tc_digest::TryXof` it is KMACXOF, whose output has no fixed length.
//!
//! The crate is `no_std` and contains no `unsafe` code. It needs an allocator,
//! for the key it keeps to start each message again.
//!
//! KMAC is constant time, as Keccak is: the permutation uses only XORs, ANDs,
//! NOTs and rotations. The lengths of the key, the customization and the
//! message are public.
//!
//! # Example
//!
//! ```
//! use tc_kmac::KMac;
//! use tc_macs::{KeyRef, Mac, MacInit};
//!
//! let mut mac = KMac::new(128, b"My Tagged Application");
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

mod kmac;

pub use kmac::KMac;
