//! HMAC sized at run time.

use crate::{Mac, MacError, MacInit};
use alloc::{vec, vec::Vec};
use core::fmt::{Display, Formatter};
use core::{convert::Infallible, fmt};
use tc_block_cipher::KeyParams;
use tc_digest::Digest;
use tc_zeroize::{Zeroize, Zeroizing};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;
const MINIMUM_BLOCK_LENGTH: usize = 16;

/// HMAC (RFC 2104) over the digest `D`, with its pads sized from the digest's
/// block length at run time; Bouncy Castle's `HMac`.
///
/// Available with the `hmac` and `alloc` features.
///
/// It computes the same tags as [`FixedHmac`](crate::FixedHmac) but does not
/// require `D: Clone`, and it has no limit on the digest size. It keeps the
/// keyed inner and outer pads, so that successful finalization and
/// [`reset`](Mac::reset) retain the most recently initialized key, and after
/// finalization it restores the inner state by resetting the digest and
/// feeding the inner pad again, matching Bouncy Castle's fallback for
/// non-memoable digests.
///
/// Constant time exactly when the digest is: only the key length decides
/// whether the key is hashed first, and only lengths decide the work. The pads
/// are wiped on drop. The digest that absorbed the inner pad is as sensitive as
/// the key, and it is wiped only if the digest wipes itself on drop, as the
/// digests of `tc_sha` do.
///
/// # Example
///
/// ```
/// use tc_macs::{Hmac, KeyRef, Mac, MacInit};
/// use tc_sha::Sha512Digest;
///
/// let mut mac = Hmac::new(Sha512Digest::new());
/// mac.init(&KeyRef::new(b"Jefe"))?;
/// mac.update(b"what do ya want for nothing?")?;
/// let mut tag = vec![0; mac.mac_size()];
/// assert_eq!(mac.do_final(&mut tag)?, 64);
/// assert_eq!(mac.to_string(), "SHA-512/HMAC");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Hmac<D> {
    digest: D,
    digest_size: usize,
    block_length: usize,
    input_pad: Zeroizing<Vec<u8>>,
    output_buffer: Zeroizing<Vec<u8>>,
    initialized: bool,
}

impl<D> Hmac<D> {
    /// Returns the digest used by this HMAC. Constant time.
    pub const fn underlying_digest(&self) -> &D {
        &self.digest
    }

    fn clear_key_material(&mut self) {
        // Wipe the contents only: zeroizing a Vec would also empty it.
        self.input_pad[..].zeroize();
        self.output_buffer[..].zeroize();
    }
}

impl<D: Digest> Hmac<D> {
    /// Wraps `digest` with the block length it reports. Constant time.
    ///
    /// # Panics
    ///
    /// Panics if the digest reports a block size shorter than 16 bytes or a
    /// digest size larger than its block size.
    pub fn new(digest: D) -> Self {
        let block_length = digest.byte_length();
        Self::with_block_length(digest, block_length)
    }

    /// Wraps `digest` with an explicit block length of `block_length` bytes.
    ///
    /// This corresponds to Bouncy Castle's constructor overload that accepts
    /// a block length. Most callers should use [`new`](Self::new).
    /// Constant time.
    ///
    /// # Panics
    ///
    /// Panics if `block_length` is shorter than 16 bytes or shorter than the
    /// digest output.
    pub fn with_block_length(digest: D, block_length: usize) -> Self {
        let digest_size = digest.digest_size();
        assert!(
            block_length >= MINIMUM_BLOCK_LENGTH,
            "HMAC block length must be at least 16 bytes"
        );
        assert!(
            digest_size <= block_length,
            "HMAC digest size must not exceed its block length"
        );

        Self {
            digest,
            digest_size,
            block_length,
            input_pad: Zeroizing::new(vec![0; block_length]),
            output_buffer: Zeroizing::new(vec![0; block_length + digest_size]),
            initialized: false,
        }
    }

    fn restore_inner_state(&mut self) {
        self.digest.reset();
        if self.initialized {
            self.digest.update(&self.input_pad);
        }
    }
}

impl<D: Display> Display for Hmac<D> {
    /// Writes the digest's name followed by `/HMAC`, such as
    /// `"SHA-256/HMAC"`, as Bouncy Castle's `AlgorithmName` does.
    /// Constant time: no key material is inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/HMAC", self.digest)
    }
}

impl<D: Digest> Mac for Hmac<D> {
    type Error = MacError;

    /// Returns the tag length in bytes, the digest's output size.
    /// Constant time.
    fn mac_size(&self) -> usize {
        self.digest_size
    }

    /// Adds `input` to the inner hash. Constant time exactly when the digest
    /// is.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }

        self.digest.update(input);
        Ok(())
    }

    /// Finishes the inner hash, hashes it under the outer pad, writes the tag
    /// and starts the next message under the same key. Constant time exactly
    /// when the digest is.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        if output.len() < self.digest_size {
            return Err(MacError::OutputTooShort {
                required: self.digest_size,
                available: output.len(),
            });
        }

        let inner_hash = &mut self.output_buffer[self.block_length..];
        let inner_length = self.digest.do_final(inner_hash);
        debug_assert_eq!(inner_length, self.digest_size);

        self.digest.update(&self.output_buffer);
        let written = self.digest.do_final(output);
        debug_assert_eq!(written, self.digest_size);

        self.output_buffer[self.block_length..].fill(0);
        self.restore_inner_state();
        Ok(written)
    }

    /// Discards the message and keeps the key by feeding the inner pad again.
    /// Constant time exactly when the digest is.
    fn reset(&mut self) {
        self.restore_inner_state();
    }
}

impl<D, P> MacInit<P> for Hmac<D>
where
    D: Digest,
    P: KeyParams + ?Sized,
{
    type Error = Infallible;

    /// Keys the MAC with a key of any length, hashing one longer than the
    /// block first, and absorbs the inner pad. Constant time exactly when the
    /// digest is: only the key length decides the work.
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.digest.reset();
        self.clear_key_material();

        let key = params.key();
        let key_length = if key.len() > self.block_length {
            self.digest.update(key);
            let written = self.digest.do_final(&mut self.input_pad);
            debug_assert_eq!(written, self.digest_size);
            self.digest_size
        } else {
            self.input_pad[..key.len()].copy_from_slice(key);
            key.len()
        };
        self.input_pad[key_length..].fill(0);

        self.output_buffer[..self.block_length].copy_from_slice(&self.input_pad);
        for byte in self.input_pad.iter_mut() {
            *byte ^= IPAD;
        }
        for byte in &mut self.output_buffer[..self.block_length] {
            *byte ^= OPAD;
        }

        self.initialized = true;
        self.digest.update(&self.input_pad);
        Ok(())
    }
}
