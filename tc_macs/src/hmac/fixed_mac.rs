//! HMAC without an allocator.

use core::convert::Infallible;
use core::fmt::{self, Display, Formatter};

use tc_block_cipher::KeyParams;
use tc_digest::Digest;
use tc_zeroize::Zeroizing;

use crate::{Mac, MacError, MacInit};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;
const MINIMUM_BLOCK_LENGTH: usize = 16;
/// A key longer than the block is hashed into a local array of this size.
const MAXIMUM_DIGEST_SIZE: usize = 128;

/// HMAC (RFC 2104) over the cloneable digest `D`, without an allocator;
/// Bouncy Castle's `HMac`.
///
/// The tag is the digest's full output. `init` takes a key of any length
/// through [`KeyParams`] and cannot fail; a key longer than the digest's block
/// is hashed first. After `do_final` the MAC starts the next message under the
/// same key.
///
/// Instead of the pads it keeps the digest states after absorbing each pad,
/// as Bouncy Castle does for memoable digests, so a message restarts by
/// cloning a state rather than hashing a pad block again. The inner hash is
/// held in the caller's output buffer until the outer hash overwrites it.
///
/// Constant time exactly when the digest is: only the key length decides
/// whether the key is hashed first, and only lengths decide the work. The
/// stored states are as sensitive as the key, and they are wiped on drop only
/// if the digest wipes itself, as the digests of `tc_sha` do.
///
/// # Example
///
/// ```
/// use tc_macs::{FixedHmac, KeyRef, Mac, MacInit};
/// use tc_sha::Sha256Digest;
///
/// // RFC 4231, test case 2.
/// let mut mac = FixedHmac::new(Sha256Digest::new());
/// mac.init(&KeyRef::new(b"Jefe"))?;
/// mac.update(b"what do ya want for nothing?")?;
/// let mut tag = [0; 32];
/// assert_eq!(mac.do_final(&mut tag)?, 32);
/// assert_eq!(tag[..4], [0x5b, 0xdc, 0xc1, 0x46]);
/// assert_eq!(mac.to_string(), "SHA-256/HMAC");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedHmac<D> {
    digest: D,
    // The states after absorbing the inner and the outer pad.
    inner: D,
    outer: D,
    digest_size: usize,
    block_length: usize,
    initialized: bool,
}

impl<D: Digest + Clone> FixedHmac<D> {
    /// Wraps `digest` with the block length it reports. Constant time.
    ///
    /// # Panics
    ///
    /// Panics if the block length is shorter than 16 bytes or than the digest
    /// output, or if the digest output is longer than 128 bytes.
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
    /// Panics if `block_length` is shorter than 16 bytes or than the digest
    /// output, or if the digest output is longer than 128 bytes.
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
        assert!(
            digest_size <= MAXIMUM_DIGEST_SIZE,
            "FixedHmac supports digests of up to 128 bytes"
        );
        Self {
            inner: digest.clone(),
            outer: digest.clone(),
            digest,
            digest_size,
            block_length,
            initialized: false,
        }
    }
}

impl<D> FixedHmac<D> {
    /// Returns the digest used by this HMAC. Constant time.
    pub const fn underlying_digest(&self) -> &D {
        &self.digest
    }
}

impl<D: Display> Display for FixedHmac<D> {
    /// Writes the digest's name followed by `/HMAC`, such as
    /// `"SHA-256/HMAC"`, as Bouncy Castle's `AlgorithmName` does.
    /// Constant time: no key material is inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/HMAC", self.digest)
    }
}

impl<D: Digest + Clone> Mac for FixedHmac<D> {
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
        let available = output.len();
        let output = output
            .get_mut(..self.digest_size)
            .ok_or(MacError::OutputTooShort {
                required: self.digest_size,
                available,
            })?;

        // The inner hash waits in the output until the outer hash overwrites
        // it with the tag.
        let inner_length = self.digest.do_final(output);
        debug_assert_eq!(inner_length, self.digest_size);
        self.digest.clone_from(&self.outer);
        self.digest.update(output);
        let written = self.digest.do_final(output);
        debug_assert_eq!(written, self.digest_size);

        self.digest.clone_from(&self.inner);
        Ok(written)
    }

    /// Discards the message and keeps the key. Constant time exactly when
    /// cloning or resetting the digest is.
    fn reset(&mut self) {
        if self.initialized {
            self.digest.clone_from(&self.inner);
        } else {
            self.digest.reset();
        }
    }
}

impl<D, P> MacInit<P> for FixedHmac<D>
where
    D: Digest + Clone,
    P: KeyParams + ?Sized,
{
    type Error = Infallible;

    /// Keys the MAC with a key of any length, hashing one longer than the
    /// block first, and absorbs the inner and outer pads. Constant time exactly
    /// when the digest is: only the key length decides the work.
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        let mut hashed = Zeroizing::new([0u8; MAXIMUM_DIGEST_SIZE]);
        let mut key = params.key();
        if key.len() > self.block_length {
            self.digest.reset();
            self.digest.update(key);
            let written = self.digest.do_final(&mut hashed[..]);
            key = &hashed[..written];
        }

        // The pads are never stored: each byte goes straight into both states.
        // The key length is public.
        self.inner.reset();
        self.outer.reset();
        for index in 0..self.block_length {
            let byte = key.get(index).copied().unwrap_or(0);
            self.inner.update_byte(byte ^ IPAD);
            self.outer.update_byte(byte ^ OPAD);
        }

        self.digest.clone_from(&self.inner);
        self.initialized = true;
        Ok(())
    }
}
