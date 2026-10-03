//! CBC-MAC logic shared by the fixed and allocating forms.

use tc_block_cipher::{BlockCipherInit, CipherDirection};
use tc_block_modes::{BlockCipherMode, BlockModeError, BlockModeInitError};
use tc_block_padding::BlockCipherPadding;
use tc_zeroize::{Zeroize, Zeroizing};

use crate::{InitError, MacError};

/// `M` is the CBC mode and `B` a buffer of one block, `[u8; N]` or `Vec<u8>`.
pub(super) struct CbcMacCore<M, B: Zeroize> {
    mode: M,
    buffer: Zeroizing<B>,
    buffer_offset: usize,
    // The last ciphertext block, which is CBC's chaining value.
    chain: Zeroizing<B>,
    mac_size: usize,
    initialized: bool,
}

impl<M, B> CbcMacCore<M, B>
where
    B: AsRef<[u8]> + AsMut<[u8]> + Zeroize,
{
    /// `mac_size` is in bytes; panics unless it is in `1..=block size`.
    pub(super) fn new(mode: M, buffer: B, chain: B, mac_size: usize) -> Self {
        assert!(
            mac_size > 0 && mac_size <= buffer.as_ref().len(),
            "CBC-MAC size must be between 1 and the block size"
        );
        Self {
            mode,
            buffer: Zeroizing::new(buffer),
            buffer_offset: 0,
            chain: Zeroizing::new(chain),
            mac_size,
            initialized: false,
        }
    }

    pub(super) fn mode(&self) -> &M {
        &self.mode
    }

    pub(super) fn mac_size(&self) -> usize {
        self.mac_size
    }

    fn block_size(&self) -> usize {
        (*self.buffer).as_ref().len()
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

impl<M, B, E> CbcMacCore<M, B>
where
    M: BlockCipherMode<Error = BlockModeError<E>>,
    B: AsRef<[u8]> + AsMut<[u8]> + Zeroize,
{
    pub(super) fn clear_message(&mut self) {
        // Wipe the contents only: zeroizing a Vec would also empty it.
        (*self.buffer).as_mut().zeroize();
        self.buffer_offset = 0;
        (*self.chain).as_mut().zeroize();
        self.mode.reset();
    }

    pub(super) fn init<P, F>(&mut self, params: &P) -> Result<(), InitError<F>>
    where
        M: BlockCipherInit<P, Error = BlockModeInitError<F>>,
        P: ?Sized,
    {
        // A failed init must not leave the previous key usable.
        self.initialized = false;
        self.mode
            .init(CipherDirection::Encrypt, params)
            .map_err(mode_init_error)?;
        self.initialized = true;
        self.clear_message();
        Ok(())
    }

    pub(super) fn update(&mut self, mut input: &[u8]) -> Result<(), MacError<E>> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        let block_size = self.block_size();
        // A full buffer waits for do_final, where the padded forms decide
        // whether to add a block of padding.
        let gap = block_size - self.buffer_offset;
        if input.len() > gap {
            let (head, rest) = input.split_at(gap);
            (*self.buffer).as_mut()[self.buffer_offset..].copy_from_slice(head);
            self.process_buffer()?;
            input = rest;
            while input.len() > block_size {
                let (block, rest) = input.split_at(block_size);
                self.mode
                    .process_block(block, (*self.chain).as_mut())
                    .map_err(mode_error)?;
                input = rest;
            }
        }
        let end = self.buffer_offset + input.len();
        (*self.buffer).as_mut()[self.buffer_offset..end].copy_from_slice(input);
        self.buffer_offset = end;
        Ok(())
    }

    /// Without padding, a partial final block is filled with zeros and a full
    /// one is left as it is, as Bouncy Castle does.
    pub(super) fn do_final(&mut self, output: &mut [u8]) -> Result<usize, MacError<E>> {
        let output = self.final_output(output)?;
        (*self.buffer).as_mut()[self.buffer_offset..].fill(0);
        self.finish(output)
    }

    /// With padding, a full final block is processed first and followed by a
    /// block of padding alone, as Bouncy Castle does.
    pub(super) fn do_final_padded<P: BlockCipherPadding>(
        &mut self,
        padding: &mut P,
        output: &mut [u8],
    ) -> Result<usize, MacError<E>> {
        let output = self.final_output(output)?;
        if self.buffer_offset == self.block_size() {
            self.process_buffer()?;
        }
        let offset = self.buffer_offset;
        if padding
            .add_padding((*self.buffer).as_mut(), offset)
            .is_err()
        {
            // A block may already have been processed, so the message cannot
            // go on.
            self.clear_message();
            return Err(MacError::PaddingFailed);
        }
        self.finish(output)
    }

    fn process_buffer(&mut self) -> Result<(), MacError<E>> {
        self.mode
            .process_block((*self.buffer).as_ref(), (*self.chain).as_mut())
            .map_err(mode_error)?;
        self.buffer_offset = 0;
        Ok(())
    }

    /// Processes the completed final block, writes the tag and returns to the
    /// state right after `init`.
    fn finish(&mut self, output: &mut [u8]) -> Result<usize, MacError<E>> {
        self.process_buffer()?;
        output.copy_from_slice(&(*self.chain).as_ref()[..self.mac_size]);
        self.clear_message();
        Ok(self.mac_size)
    }
}

fn mode_error<E>(error: BlockModeError<E>) -> MacError<E> {
    match error {
        BlockModeError::Cipher(error) => MacError::Cipher(error),
        BlockModeError::NotInitialised => MacError::NotInitialised,
        // Every buffer passed is one block long, so BufferTooShort cannot
        // occur.
        _ => MacError::InternalFailure,
    }
}

fn mode_init_error<E>(error: BlockModeInitError<E>) -> InitError<E> {
    match error {
        BlockModeInitError::Cipher(error) => InitError::Cipher(error),
        BlockModeInitError::InvalidIvLength(bytes) => InitError::InvalidIvLength(bytes),
        BlockModeInitError::UnsupportedBlockSize { actual, required } => {
            InitError::UnsupportedBlockSize { actual, required }
        }
        // CBC has no feedback size, so no other error can occur.
        _ => InitError::InternalFailure,
    }
}
