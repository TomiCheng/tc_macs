//! CFB-MAC logic shared by the fixed and allocating forms: Bouncy Castle's
//! `MacCFBBlockCipher` with buffering.
//!
//! The CFB mode of `tc_block_modes` does not fit: the tag needs the whole block
//! E_K(shift register), and the mode yields only one segment of keystream.

use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_block_modes::IvParams;
use tc_block_padding::BlockCipherPadding;
use tc_zeroize::{Zeroize, Zeroizing};

use crate::{InitError, MacError};

/// `B` is a buffer of one block, `[u8; N]` or `Vec<u8>`.
pub(super) struct CfbMacCore<C, B: Zeroize> {
    cipher: C,
    iv: Zeroizing<B>,
    // CFB's shift register.
    register: Zeroizing<B>,
    keystream: Zeroizing<B>,
    // One segment of input, in the first segment_size bytes only.
    buffer: Zeroizing<B>,
    buffer_offset: usize,
    segment_size: usize,
    mac_size: usize,
    initialized: bool,
}

impl<C, B> CfbMacCore<C, B>
where
    B: AsRef<[u8]> + AsMut<[u8]> + Zeroize,
{
    /// `buffers` are four zeroed buffers of one block. `segment_size` and
    /// `mac_size` are in bytes; panics unless both are in `1..=block size`.
    pub(super) fn new(cipher: C, buffers: [B; 4], segment_size: usize, mac_size: usize) -> Self {
        let [iv, register, keystream, buffer] = buffers;
        let block_size = iv.as_ref().len();
        assert!(
            segment_size > 0 && segment_size <= block_size,
            "CFB-MAC feedback size must be between 1 and the block size"
        );
        assert!(
            mac_size > 0 && mac_size <= block_size,
            "CFB-MAC size must be between 1 and the block size"
        );
        Self {
            cipher,
            iv: Zeroizing::new(iv),
            register: Zeroizing::new(register),
            keystream: Zeroizing::new(keystream),
            buffer: Zeroizing::new(buffer),
            buffer_offset: 0,
            segment_size,
            mac_size,
            initialized: false,
        }
    }

    pub(super) fn cipher(&self) -> &C {
        &self.cipher
    }

    pub(super) fn segment_size(&self) -> usize {
        self.segment_size
    }

    pub(super) fn mac_size(&self) -> usize {
        self.mac_size
    }

    fn block_size(&self) -> usize {
        (*self.iv).as_ref().len()
    }

    pub(super) fn clear_message(&mut self) {
        // Wipe the contents only: zeroizing a Vec would also empty it.
        (*self.register)
            .as_mut()
            .copy_from_slice((*self.iv).as_ref());
        (*self.keystream).as_mut().zeroize();
        (*self.buffer).as_mut().zeroize();
        self.buffer_offset = 0;
    }

    /// Checks what `do_final` needs and returns exactly `mac_size` bytes of
    /// the output.
    fn final_output<'a, E>(&self, output: &'a mut [u8]) -> Result<&'a mut [u8], MacError<E>> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        let available = output.len();
        output
            .get_mut(..self.mac_size)
            .ok_or(MacError::OutputTooShort {
                required: self.mac_size,
                available,
            })
    }
}

impl<C, B> CfbMacCore<C, B>
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
        P: IvParams + ?Sized,
    {
        // A failed init must not leave the previous key usable.
        self.initialized = false;
        let block_size = self.block_size();
        let actual = self.cipher.block_size();
        if actual != block_size {
            return Err(InitError::UnsupportedBlockSize {
                actual,
                required: block_size,
            });
        }
        // Bouncy Castle accepts a shorter IV and prepends zeros; this requires
        // exactly one block.
        let iv = params.iv();
        if iv.len() != block_size {
            return Err(InitError::InvalidIvLength(iv.len()));
        }
        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(InitError::Cipher)?;
        (*self.iv).as_mut().copy_from_slice(iv);
        self.initialized = true;
        self.clear_message();
        Ok(())
    }

    pub(super) fn update(&mut self, mut input: &[u8]) -> Result<(), MacError<C::Error>> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        let segment_size = self.segment_size;
        // A full segment waits for do_final.
        let gap = segment_size - self.buffer_offset;
        if input.len() > gap {
            let (head, rest) = input.split_at(gap);
            (*self.buffer).as_mut()[self.buffer_offset..segment_size].copy_from_slice(head);
            self.process_segment()?;
            input = rest;
            while input.len() > segment_size {
                let (segment, rest) = input.split_at(segment_size);
                (*self.buffer).as_mut()[..segment_size].copy_from_slice(segment);
                self.process_segment()?;
                input = rest;
            }
        }
        let end = self.buffer_offset + input.len();
        (*self.buffer).as_mut()[self.buffer_offset..end].copy_from_slice(input);
        self.buffer_offset = end;
        Ok(())
    }

    /// Without padding, a partial final segment is filled with zeros, as
    /// Bouncy Castle does.
    pub(super) fn do_final(&mut self, output: &mut [u8]) -> Result<usize, MacError<C::Error>> {
        let output = self.final_output(output)?;
        let segment_size = self.segment_size;
        (*self.buffer).as_mut()[self.buffer_offset..segment_size].fill(0);
        self.finish(output)
    }

    /// With padding, only a partial final segment is padded, and a full one is
    /// left as it is.
    ///
    /// This differs from CBC-MAC but is what Bouncy Castle does: it calls
    /// `AddPadding(buffer, buffer.Length)` on a full segment, to which PKCS#7
    /// adds nothing.
    pub(super) fn do_final_padded<P: BlockCipherPadding>(
        &mut self,
        padding: &mut P,
        output: &mut [u8],
    ) -> Result<usize, MacError<C::Error>> {
        let output = self.final_output(output)?;
        let segment_size = self.segment_size;
        let offset = self.buffer_offset;
        if offset < segment_size
            && padding
                .add_padding(&mut (*self.buffer).as_mut()[..segment_size], offset)
                .is_err()
        {
            self.clear_message();
            return Err(MacError::PaddingFailed);
        }
        self.finish(output)
    }

    /// Encrypts one segment: XORs the input with the first `segment_size`
    /// bytes of E_K(register) and shifts the result into the end of the
    /// register.
    fn process_segment(&mut self) -> Result<(), MacError<C::Error>> {
        let segment_size = self.segment_size;
        let block_size = self.block_size();
        self.cipher
            .process_block((*self.register).as_ref(), (*self.keystream).as_mut())
            .map_err(MacError::Cipher)?;
        let buffer = (*self.buffer).as_mut();
        for (byte, key) in buffer[..segment_size]
            .iter_mut()
            .zip((*self.keystream).as_ref())
        {
            *byte ^= key;
        }
        let register = (*self.register).as_mut();
        register.copy_within(segment_size..block_size, 0);
        register[block_size - segment_size..].copy_from_slice(&buffer[..segment_size]);
        buffer[..segment_size].zeroize();
        self.buffer_offset = 0;
        Ok(())
    }

    /// Processes the final segment; the tag is the first `mac_size` bytes of
    /// E_K(register).
    fn finish(&mut self, output: &mut [u8]) -> Result<usize, MacError<C::Error>> {
        self.process_segment()?;
        self.cipher
            .process_block((*self.register).as_ref(), (*self.keystream).as_mut())
            .map_err(MacError::Cipher)?;
        output.copy_from_slice(&(*self.keystream).as_ref()[..self.mac_size]);
        self.clear_message();
        Ok(self.mac_size)
    }
}
