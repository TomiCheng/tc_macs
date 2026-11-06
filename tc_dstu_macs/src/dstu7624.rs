//! The DSTU 7624 (Kalyna) MAC.

use core::fmt;

use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, KeyParams};
use tc_dstu7624::Dstu7624Engine as Engine;
use tc_macs::{InitError, Mac, MacInit};
use tc_zeroize::Zeroize;

const MAX_BLOCK_BYTES: usize = 64;

/// A failure while constructing a DSTU 7624 MAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Dstu7624MacCreateError {
    /// DSTU 7624 supports 128-, 256- and 512-bit blocks; this one is in bits.
    UnsupportedBlockSize(usize),
    /// The requested tag is empty, is not a whole number of bytes, or is longer
    /// than the block.
    InvalidMacSize {
        /// The requested tag length, in bits.
        requested_bits: usize,
        /// The longest tag the block allows, in bits.
        maximum_bits: usize,
    },
}

impl fmt::Display for Dstu7624MacCreateError {
    /// Writes a description of the failure. Constant time: the fields hold only
    /// public lengths.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedBlockSize(bits) => write!(
                f,
                "DSTU 7624 MAC requires a 128-, 256-, or 512-bit block, got {bits} bits"
            ),
            Self::InvalidMacSize {
                requested_bits,
                maximum_bits,
            } => write!(
                f,
                "invalid DSTU 7624 MAC size: requested {requested_bits} bits, maximum {maximum_bits} bits"
            ),
        }
    }
}

impl core::error::Error for Dstu7624MacCreateError {}

/// A failure while processing a DSTU 7624 MAC.
///
/// Its own type because the block-aligned input DSTU 7624 MAC requires is
/// specific to it; the shared MAC error does not carry that case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Dstu7624MacError {
    /// The MAC has not been initialized.
    NotInitialised,
    /// The output buffer is shorter than required.
    OutputTooShort {
        /// The tag length, in bytes.
        required: usize,
        /// The length of the output buffer, in bytes.
        available: usize,
    },
    /// The message length is not a multiple of the block size.
    InputNotBlockAligned {
        /// The block size, in bytes.
        block_size: usize,
        /// The bytes past the last whole block.
        remainder: usize,
    },
    /// The block cipher failed despite validated internal invariants.
    InternalFailure,
}

impl fmt::Display for Dstu7624MacError {
    /// Writes a description of the failure. Constant time: the fields hold only
    /// public lengths.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("MAC not initialised"),
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Self::InputNotBlockAligned {
                block_size,
                remainder,
            } => write!(
                f,
                "MAC input is not aligned to {block_size}-byte blocks: {remainder} bytes remain"
            ),
            Self::InternalFailure => f.write_str("internal MAC primitive failure"),
        }
    }
}

impl core::error::Error for Dstu7624MacError {}

/// The MAC of the DSTU 7624 (Kalyna) block cipher, whose const parameter is the
/// cipher block size in 64-bit words; Bouncy Castle's `Dstu7624Mac`.
///
/// `init` takes a key the cipher accepts through [`KeyParams`], and after
/// `do_final` the MAC starts the next message under the same key. The message
/// must be a whole number of blocks, and any other length is refused at
/// `do_final`, with the message left in place. The tag is the start of the last
/// chaining block, from one byte up to the whole block.
///
/// Variable time: the cipher indexes its S-boxes with bytes derived from the key
/// and the message, so cache timing can leak them. Use it only where that
/// leakage is outside the threat model. The key schedule and the message state
/// are wiped on drop.
pub struct Dstu7624Mac<const BLOCK_WORDS: usize> {
    cipher: Engine<BLOCK_WORDS>,
    block_size: usize,
    mac_size: usize,
    chain: [u8; MAX_BLOCK_BYTES],
    temporary: [u8; MAX_BLOCK_BYTES],
    delta: [u8; MAX_BLOCK_BYTES],
    buffer: [u8; MAX_BLOCK_BYTES],
    buffer_offset: usize,
    initialized: bool,
}

/// The DSTU 7624 MAC over the 128-bit block cipher.
pub type Dstu7624Mac128 = Dstu7624Mac<2>;
/// The DSTU 7624 MAC over the 256-bit block cipher.
pub type Dstu7624Mac256 = Dstu7624Mac<4>;
/// The DSTU 7624 MAC over the 512-bit block cipher.
pub type Dstu7624Mac512 = Dstu7624Mac<8>;

impl<const BLOCK_WORDS: usize> Dstu7624Mac<BLOCK_WORDS> {
    /// Creates an uninitialized MAC with a `mac_size_bits`-bit tag.
    /// Constant time: only public lengths decide the work.
    pub fn new(mac_size_bits: usize) -> Result<Self, Dstu7624MacCreateError>
    where
        Engine<BLOCK_WORDS>: Default,
    {
        let block_size = BLOCK_WORDS * 8;
        let block_size_bits = block_size * 8;
        if ![128, 256, 512].contains(&block_size_bits) {
            return Err(Dstu7624MacCreateError::UnsupportedBlockSize(
                block_size_bits,
            ));
        }
        if mac_size_bits == 0 || mac_size_bits % 8 != 0 || mac_size_bits > block_size_bits {
            return Err(Dstu7624MacCreateError::InvalidMacSize {
                requested_bits: mac_size_bits,
                maximum_bits: block_size_bits,
            });
        }

        Ok(Self {
            cipher: Engine::default(),
            block_size,
            mac_size: mac_size_bits / 8,
            chain: [0; MAX_BLOCK_BYTES],
            temporary: [0; MAX_BLOCK_BYTES],
            delta: [0; MAX_BLOCK_BYTES],
            buffer: [0; MAX_BLOCK_BYTES],
            buffer_offset: 0,
            initialized: false,
        })
    }

    fn clear_message(&mut self) {
        self.chain.zeroize();
        self.temporary.zeroize();
        self.buffer.zeroize();
        self.buffer_offset = 0;
    }
}

impl<const BLOCK_WORDS: usize> Dstu7624Mac<BLOCK_WORDS>
where
    Engine<BLOCK_WORDS>: BlockCipher<Error = BlockError>,
{
    fn process_buffer(&mut self) -> Result<(), Dstu7624MacError> {
        for index in 0..self.block_size {
            self.temporary[index] = self.chain[index] ^ self.buffer[index];
        }
        self.cipher
            .process_block(
                &self.temporary[..self.block_size],
                &mut self.chain[..self.block_size],
            )
            .map_err(|_| Dstu7624MacError::InternalFailure)?;
        self.buffer[..self.block_size].zeroize();
        self.buffer_offset = 0;
        Ok(())
    }
}

impl<const BLOCK_WORDS: usize> fmt::Display for Dstu7624Mac<BLOCK_WORDS> {
    /// Writes `"Dstu7624Mac"`, as Bouncy Castle's `AlgorithmName` does.
    /// Constant time: no key material is inspected.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Dstu7624Mac")
    }
}

impl<const BLOCK_WORDS: usize> Mac for Dstu7624Mac<BLOCK_WORDS>
where
    Engine<BLOCK_WORDS>: BlockCipher<Error = BlockError>,
{
    type Error = Dstu7624MacError;

    /// Returns the tag length in bytes. Constant time.
    fn mac_size(&self) -> usize {
        self.mac_size
    }

    /// Absorbs `input`, holding back the last block for `do_final`.
    /// Variable time: the cipher indexes its S-boxes with secret bytes.
    fn update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(Dstu7624MacError::NotInitialised);
        }

        let gap = self.block_size - self.buffer_offset;
        if input.len() > gap {
            self.buffer[self.buffer_offset..self.block_size].copy_from_slice(&input[..gap]);
            self.process_buffer()?;
            input = &input[gap..];
            while input.len() > self.block_size {
                self.buffer[..self.block_size].copy_from_slice(&input[..self.block_size]);
                self.buffer_offset = self.block_size;
                self.process_buffer()?;
                input = &input[self.block_size..];
            }
        }

        let end = self.buffer_offset + input.len();
        self.buffer[self.buffer_offset..end].copy_from_slice(input);
        self.buffer_offset = end;
        Ok(())
    }

    /// Encrypts the last block with the key's delta, writes the tag and starts
    /// the next message under the same key. Variable time: the cipher indexes
    /// its S-boxes with secret bytes.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(Dstu7624MacError::NotInitialised);
        }
        if self.buffer_offset != 0 && self.buffer_offset != self.block_size {
            return Err(Dstu7624MacError::InputNotBlockAligned {
                block_size: self.block_size,
                remainder: self.buffer_offset,
            });
        }
        if output.len() < self.mac_size {
            return Err(Dstu7624MacError::OutputTooShort {
                required: self.mac_size,
                available: output.len(),
            });
        }

        for index in 0..self.block_size {
            self.temporary[index] = self.chain[index] ^ self.buffer[index] ^ self.delta[index];
        }
        self.cipher
            .process_block(
                &self.temporary[..self.block_size],
                &mut self.chain[..self.block_size],
            )
            .map_err(|_| Dstu7624MacError::InternalFailure)?;
        output[..self.mac_size].copy_from_slice(&self.chain[..self.mac_size]);
        self.clear_message();
        Ok(self.mac_size)
    }

    /// Discards the message and keeps the key. Constant time: it only wipes the
    /// message state.
    fn reset(&mut self) {
        self.clear_message();
    }
}

impl<P, const BLOCK_WORDS: usize> MacInit<P> for Dstu7624Mac<BLOCK_WORDS>
where
    P: KeyParams + ?Sized,
    Engine<BLOCK_WORDS>:
        BlockCipher<Error = BlockError> + BlockCipherInit<P, Error = tc_block_cipher::InitError>,
{
    type Error = InitError<tc_block_cipher::InitError>;

    /// Keys the MAC and starts a new message; a key the cipher refuses leaves the
    /// MAC uninitialized. Variable time: the key schedule indexes the S-boxes
    /// with the key.
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.clear_message();
        self.delta.zeroize();
        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(InitError::Cipher)?;
        let zeroes = [0_u8; MAX_BLOCK_BYTES];
        self.cipher
            .process_block(
                &zeroes[..self.block_size],
                &mut self.delta[..self.block_size],
            )
            .map_err(|_| InitError::InternalFailure)?;
        self.initialized = true;
        Ok(())
    }
}

impl<const BLOCK_WORDS: usize> Drop for Dstu7624Mac<BLOCK_WORDS> {
    /// Wipes the message state and the delta; the cipher wipes its own key
    /// schedule. Constant time.
    fn drop(&mut self) {
        self.chain.zeroize();
        self.temporary.zeroize();
        self.delta.zeroize();
        self.buffer.zeroize();
    }
}
