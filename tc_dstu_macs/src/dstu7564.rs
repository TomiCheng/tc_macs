//! The DSTU 7564 MAC.

use alloc::{vec, vec::Vec};
use core::fmt;

use tc_digest::{Digest, TryDigest};
use tc_dstu7564::Dstu7564Digest;
use tc_macs::{InitError, KeyParams, Mac, MacError, MacInit};
use tc_zeroize::Zeroize;

/// The keyed construction of the DSTU 7564 (Kupyna) digest, with a 256-, 384- or
/// 512-bit tag; Bouncy Castle's `Dstu7564Mac`.
///
/// `init` takes a key of at least one byte through [`KeyParams`], and after
/// `do_final` the MAC starts the next message under the same key. A key of a
/// whole number of digest blocks is padded with one more block, where Bouncy
/// Castle's padding overruns its buffer and throws.
///
/// Variable time: the digest indexes its S-boxes with bytes derived from the key
/// and the message, so cache timing can leak them. Use it only where that
/// leakage is outside the threat model. The key and the digest state are wiped
/// on drop.
pub struct Dstu7564Mac {
    digest: Dstu7564Digest,
    mac_size: usize,
    input_length: u64,
    padded_key: Vec<u8>,
    inverted_key: Vec<u8>,
    initialized: bool,
}

impl Dstu7564Mac {
    /// Creates an uninitialized MAC with a 256-, 384- or 512-bit tag.
    /// Constant time: only the public tag length decides the work.
    ///
    /// # Panics
    ///
    /// Panics for any other tag length, as [`Dstu7564Digest::new`] does.
    pub fn new(mac_bits: usize) -> Self {
        Self {
            digest: Dstu7564Digest::new(mac_bits),
            mac_size: mac_bits / 8,
            input_length: 0,
            padded_key: Vec::new(),
            inverted_key: Vec::new(),
            initialized: false,
        }
    }

    fn padded_key(key: &[u8], block_size: usize) -> Vec<u8> {
        let mut extra = block_size - key.len() % block_size;
        if extra < 13 {
            extra += block_size;
        }

        let mut padded = vec![0_u8; key.len() + extra];
        padded[..key.len()].copy_from_slice(key);
        padded[key.len()] = 0x80;

        let length_offset = padded.len() - 12;
        let bit_length = (key.len() as u32).wrapping_mul(8);
        padded[length_offset..length_offset + 4].copy_from_slice(&bit_length.to_le_bytes());
        padded
    }

    fn message_padding(&self) -> Vec<u8> {
        let block_size = self.digest.byte_length();
        let remainder = (self.input_length % block_size as u64) as usize;
        let mut extra = block_size - remainder;
        if extra < 13 {
            extra += block_size;
        }

        let mut padded = vec![0_u8; extra];
        padded[0] = 0x80;
        let length_offset = padded.len() - 12;
        let bit_length = self.input_length.wrapping_mul(8);
        padded[length_offset..length_offset + 8].copy_from_slice(&bit_length.to_le_bytes());
        padded
    }
}

impl fmt::Display for Dstu7564Mac {
    /// Writes `"DSTU7564Mac"`, as Bouncy Castle's `AlgorithmName` does.
    /// Constant time: no key material is inspected.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DSTU7564Mac")
    }
}

impl Mac for Dstu7564Mac {
    type Error = MacError;

    /// Returns the tag length in bytes. Constant time.
    fn mac_size(&self) -> usize {
        self.mac_size
    }

    /// Absorbs `input`. Variable time: the digest indexes its S-boxes with
    /// secret bytes.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }

        self.digest.update(input);
        self.input_length = self.input_length.wrapping_add(input.len() as u64);
        Ok(())
    }

    /// Pads the message, absorbs the inverted key, writes the tag and starts the
    /// next message under the same key. Variable time: the digest indexes its
    /// S-boxes with secret bytes.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        if output.len() < self.mac_size {
            return Err(MacError::OutputTooShort {
                required: self.mac_size,
                available: output.len(),
            });
        }

        self.digest.update(&self.message_padding());
        self.digest.update(&self.inverted_key);
        let written = self.digest.do_final(output);
        self.reset();
        Ok(written)
    }

    /// Discards the message and keeps the key by absorbing the padded key again.
    /// Variable time: the digest indexes its S-boxes with the key.
    fn reset(&mut self) {
        self.input_length = 0;
        self.digest.reset();
        if self.initialized {
            self.digest.update(&self.padded_key);
        }
    }
}

impl<P> MacInit<P> for Dstu7564Mac
where
    P: KeyParams + ?Sized,
{
    type Error = InitError;

    /// Keys the MAC and starts a new message; an empty key is refused and leaves
    /// the MAC uninitialized. Variable time: the digest indexes its S-boxes with
    /// the key.
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.input_length = 0;
        self.digest.reset();
        self.padded_key.zeroize();
        self.inverted_key.zeroize();

        let key = params.key();
        if key.is_empty() {
            return Err(InitError::InvalidKeyLength(0));
        }

        self.padded_key = Self::padded_key(key, self.digest.byte_length());
        self.inverted_key = key.iter().map(|byte| !byte).collect();
        self.initialized = true;
        self.reset();
        Ok(())
    }
}

impl Drop for Dstu7564Mac {
    /// Wipes the key; the digest wipes its own state. Constant time.
    fn drop(&mut self) {
        self.padded_key.zeroize();
        self.inverted_key.zeroize();
    }
}
