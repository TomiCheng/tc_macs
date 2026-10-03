//! CMAC logic shared by the fixed and allocating forms (NIST SP 800-38B,
//! RFC 4493).
//!
//! CMAC's IV is always zero, so it runs CBC over the engine directly rather
//! than through a block mode, and its parameters need only a key.

use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyParams};
use tc_zeroize::{Zeroize, Zeroizing};

use crate::{InitError, MacError};

/// The reduction constants for 64- and 128-bit blocks, as in Bouncy Castle.
const RB_64: u8 = 0x1b;
const RB_128: u8 = 0x87;

/// `B` is a buffer of one block, `[u8; N]` or `Vec<u8>`.
pub(super) struct CmacCore<C, B: Zeroize> {
    cipher: C,
    // CBC's chaining value.
    chain: Zeroizing<B>,
    buffer: Zeroizing<B>,
    buffer_offset: usize,
    // The subkeys: K1 for a complete final block, K2 for a padded one.
    k1: Zeroizing<B>,
    k2: Zeroizing<B>,
    mac_size: usize,
    initialized: bool,
}

impl<C, B> CmacCore<C, B>
where
    B: AsRef<[u8]> + AsMut<[u8]> + Zeroize,
{
    /// `buffers` are four zeroed buffers of one block. Panics unless the block
    /// is 8 or 16 bytes and `mac_size` is in `1..=block size`.
    pub(super) fn new(cipher: C, buffers: [B; 4], mac_size: usize) -> Self {
        let [chain, buffer, k1, k2] = buffers;
        let block_size = chain.as_ref().len();
        assert!(
            block_size == 8 || block_size == 16,
            "CMAC supports 64- and 128-bit block ciphers only"
        );
        assert!(
            mac_size > 0 && mac_size <= block_size,
            "CMAC size must be between 1 and the block size"
        );
        Self {
            cipher,
            chain: Zeroizing::new(chain),
            buffer: Zeroizing::new(buffer),
            buffer_offset: 0,
            k1: Zeroizing::new(k1),
            k2: Zeroizing::new(k2),
            mac_size,
            initialized: false,
        }
    }

    pub(super) fn cipher(&self) -> &C {
        &self.cipher
    }

    pub(super) fn mac_size(&self) -> usize {
        self.mac_size
    }

    fn block_size(&self) -> usize {
        (*self.chain).as_ref().len()
    }

    pub(super) fn clear_message(&mut self) {
        // Wipe the contents only: zeroizing a Vec would also empty it.
        (*self.chain).as_mut().zeroize();
        (*self.buffer).as_mut().zeroize();
        self.buffer_offset = 0;
    }

    fn clear_subkeys(&mut self) {
        (*self.k1).as_mut().zeroize();
        (*self.k2).as_mut().zeroize();
    }
}

impl<C, B> CmacCore<C, B>
where
    C: BlockCipher,
    B: AsRef<[u8]> + AsMut<[u8]> + Zeroize,
{
    pub(super) fn init<P>(
        &mut self,
        params: &P,
    ) -> Result<(), InitError<<C as BlockCipherInit<P>>::Error>>
    where
        C: BlockCipherInit<P>,
        P: KeyParams + ?Sized,
    {
        // A failed init must not leave the previous key usable.
        self.initialized = false;
        self.clear_message();
        self.clear_subkeys();
        let block_size = self.block_size();
        let actual = self.cipher.block_size();
        if actual != block_size {
            return Err(InitError::UnsupportedBlockSize {
                actual,
                required: block_size,
            });
        }
        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(InitError::Cipher)?;

        // L = E_K(0), held in chain for now; buffer is all zeros here.
        if self
            .cipher
            .process_block((*self.buffer).as_ref(), (*self.chain).as_mut())
            .is_err()
        {
            // The engine was just keyed but cannot process a block.
            self.clear_message();
            return Err(InitError::InternalFailure);
        }
        let reduction = if block_size == 16 { RB_128 } else { RB_64 };
        double((*self.chain).as_ref(), (*self.k1).as_mut(), reduction);
        double((*self.k1).as_ref(), (*self.k2).as_mut(), reduction);
        self.clear_message();
        self.initialized = true;
        Ok(())
    }

    pub(super) fn update(&mut self, mut input: &[u8]) -> Result<(), MacError<C::Error>> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        let block_size = self.block_size();
        // A full buffer waits for do_final, where the final block is XORed
        // with a subkey.
        let gap = block_size - self.buffer_offset;
        if input.len() > gap {
            let (head, rest) = input.split_at(gap);
            (*self.buffer).as_mut()[self.buffer_offset..].copy_from_slice(head);
            self.process_buffer()?;
            input = rest;
            while input.len() > block_size {
                let (block, rest) = input.split_at(block_size);
                (*self.buffer).as_mut().copy_from_slice(block);
                self.process_buffer()?;
                input = rest;
            }
        }
        let end = self.buffer_offset + input.len();
        (*self.buffer).as_mut()[self.buffer_offset..end].copy_from_slice(input);
        self.buffer_offset = end;
        Ok(())
    }

    pub(super) fn do_final(&mut self, output: &mut [u8]) -> Result<usize, MacError<C::Error>> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        let available = output.len();
        let output = output
            .get_mut(..self.mac_size)
            .ok_or(MacError::OutputTooShort {
                required: self.mac_size,
                available,
            })?;

        let block_size = self.block_size();
        let offset = self.buffer_offset;
        let buffer = (*self.buffer).as_mut();
        // A complete final block takes K1; a partial one is padded as in
        // ISO/IEC 7816-4, 0x80 and then zeros, and takes K2.
        let subkey = if offset == block_size {
            (*self.k1).as_ref()
        } else {
            buffer[offset] = 0x80;
            buffer[offset + 1..].fill(0);
            (*self.k2).as_ref()
        };
        for (byte, key) in buffer.iter_mut().zip(subkey) {
            *byte ^= key;
        }
        self.process_buffer()?;
        output.copy_from_slice(&(*self.chain).as_ref()[..self.mac_size]);
        self.clear_message();
        Ok(self.mac_size)
    }

    fn process_buffer(&mut self) -> Result<(), MacError<C::Error>> {
        let buffer = (*self.buffer).as_mut();
        for (byte, chain) in buffer.iter_mut().zip((*self.chain).as_ref()) {
            *byte ^= chain;
        }
        self.cipher
            .process_block(buffer, (*self.chain).as_mut())
            .map_err(MacError::Cipher)?;
        buffer.zeroize();
        self.buffer_offset = 0;
        Ok(())
    }
}

/// Multiplies by x in GF(2^n): shifts the block left by one bit and, when the
/// bit shifted out is set, XORs the reduction constant into the last byte. A
/// mask replaces the branch, so the time does not depend on L.
fn double(input: &[u8], output: &mut [u8], reduction: u8) {
    let carry = input[0] >> 7;
    let mut next_bit = 0;
    for (&byte, target) in input.iter().zip(output.iter_mut()).rev() {
        *target = (byte << 1) | next_bit;
        next_bit = byte >> 7;
    }
    let last = output.len() - 1;
    output[last] ^= reduction & 0u8.wrapping_sub(carry);
}
