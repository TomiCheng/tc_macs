//! The ISO/IEC 9797-1 MAC algorithm 3.

use core::fmt;

use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, KeyRef};
use tc_block_modes::IvParams;
use tc_block_padding::BlockCipherPadding;
use tc_des::{BLOCK_BYTES, DesEngine};
use tc_macs::{InitError, KeyParams, Mac, MacError, MacInit};
use tc_zeroize::Zeroize;

use crate::{Iso9797Alg3MacCreateError, Iso9797Padding, NoPadding, WithPadding};

const DOUBLE_KEY_BYTES: usize = 16;
const TRIPLE_KEY_BYTES: usize = 24;

/// The ISO/IEC 9797-1 MAC algorithm 3 over DES, the ANSI X9.19 retail MAC;
/// Bouncy Castle's `ISO9797Alg3Mac`.
///
/// `init` takes a double- or triple-length DES key, 16 or 24 bytes, and an IV
/// of one DES block, through `tc_block_modes::IvParams`: CBC-DES under the
/// first 8 bytes chains the message, and the last block is decrypted under the
/// second 8 bytes and encrypted again under the third, the first for a
/// double-length key. Bouncy Castle also takes a key alone, with a zero IV;
/// pass an IV of 8 zero bytes for that, as for CBC-MAC in `tc_macs`. After
/// `do_final` the MAC starts the next message under the same key and IV.
///
/// The final block is completed by `P`: [`NoPadding`] fills a partial block
/// with zeros, as Bouncy Castle does by default, and [`WithPadding`] pads with a
/// `tc_block_padding` scheme. The tag is 8 bytes unless a shorter one is asked
/// for.
///
/// Variable time, as DES is: every DES engine looks up S-boxes with secret
/// data. Lengths are public. The key schedules, the IV, the chain and the
/// buffered message are wiped on drop.
pub struct Iso9797Alg3Mac<P = NoPadding> {
    first: DesEngine,
    second: DesEngine,
    third: DesEngine,
    padding: P,
    mac_size: usize,
    iv: [u8; BLOCK_BYTES],
    chain: [u8; BLOCK_BYTES],
    buffer: [u8; BLOCK_BYTES],
    buffer_offset: usize,
    initialized: bool,
}

impl Iso9797Alg3Mac<NoPadding> {
    /// Creates an uninitialized MAC with an 8-byte tag and no padding.
    /// Constant time.
    pub fn new() -> Self {
        Self::build(NoPadding, 64).expect("the full DES block is a valid tag size")
    }

    /// Creates an uninitialized MAC with a tag of `mac_size_bits` and no
    /// padding. `InvalidMacSize` unless the length is a whole number of bytes
    /// from 8 to 64 bits, where Bouncy Castle checks only the whole bytes.
    /// Constant time.
    pub fn with_mac_size_bits(mac_size_bits: usize) -> Result<Self, Iso9797Alg3MacCreateError> {
        Self::build(NoPadding, mac_size_bits)
    }

    /// Creates an uninitialized MAC with an 8-byte tag that pads the final
    /// block with `padding`. Constant time.
    pub fn with_padding<D: BlockCipherPadding>(padding: D) -> Iso9797Alg3Mac<WithPadding<D>> {
        Iso9797Alg3Mac::build(WithPadding(padding), 64)
            .expect("the full DES block is a valid tag size")
    }

    /// Creates an uninitialized MAC with a tag of `mac_size_bits` that pads the
    /// final block with `padding`; `InvalidMacSize` as for
    /// [`with_mac_size_bits`](Self::with_mac_size_bits). Constant time.
    pub fn with_padding_and_mac_size_bits<D: BlockCipherPadding>(
        padding: D,
        mac_size_bits: usize,
    ) -> Result<Iso9797Alg3Mac<WithPadding<D>>, Iso9797Alg3MacCreateError> {
        Iso9797Alg3Mac::build(WithPadding(padding), mac_size_bits)
    }
}

impl Default for Iso9797Alg3Mac<NoPadding> {
    /// The same as [`Iso9797Alg3Mac::new`]. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl<P> Iso9797Alg3Mac<P> {
    fn build(padding: P, mac_size_bits: usize) -> Result<Self, Iso9797Alg3MacCreateError> {
        if mac_size_bits == 0 || mac_size_bits % 8 != 0 || mac_size_bits > BLOCK_BYTES * 8 {
            return Err(Iso9797Alg3MacCreateError::InvalidMacSize(mac_size_bits));
        }
        Ok(Self {
            first: DesEngine::new(),
            second: DesEngine::new(),
            third: DesEngine::new(),
            padding,
            mac_size: mac_size_bits / 8,
            iv: [0; BLOCK_BYTES],
            chain: [0; BLOCK_BYTES],
            buffer: [0; BLOCK_BYTES],
            buffer_offset: 0,
            initialized: false,
        })
    }

    fn clear_message(&mut self) {
        self.chain = self.iv;
        self.buffer.zeroize();
        self.buffer_offset = 0;
    }

    fn process_buffer(&mut self) -> Result<(), MacError<BlockError>> {
        for (byte, chain) in self.buffer.iter_mut().zip(&self.chain) {
            *byte ^= chain;
        }
        self.first
            .process_block(&self.buffer, &mut self.chain)
            .map_err(MacError::Cipher)?;
        self.buffer.zeroize();
        self.buffer_offset = 0;
        Ok(())
    }

    fn key_engine(
        engine: &mut DesEngine,
        direction: CipherDirection,
        key: &[u8],
    ) -> Result<(), InitError<tc_block_cipher::InitError>> {
        engine
            .init(direction, &KeyRef::new(key))
            .map_err(InitError::Cipher)
    }
}

impl<P> fmt::Display for Iso9797Alg3Mac<P> {
    /// Writes `"ISO9797Alg3"`, as Bouncy Castle names it, without touching the
    /// key. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ISO9797Alg3")
    }
}

impl<P: Iso9797Padding> Mac for Iso9797Alg3Mac<P> {
    type Error = MacError<BlockError>;

    /// Returns the tag length in bytes. Constant time.
    fn mac_size(&self) -> usize {
        self.mac_size
    }

    /// Adds `input` to the message, encrypting every block but the last one
    /// buffered. `NotInitialised` before a successful `init`. Variable time, as
    /// DES is.
    fn update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        let gap = BLOCK_BYTES - self.buffer_offset;
        if input.len() > gap {
            self.buffer[self.buffer_offset..].copy_from_slice(&input[..gap]);
            self.process_buffer()?;
            input = &input[gap..];
            while input.len() > BLOCK_BYTES {
                self.buffer.copy_from_slice(&input[..BLOCK_BYTES]);
                self.process_buffer()?;
                input = &input[BLOCK_BYTES..];
            }
        }
        let end = self.buffer_offset + input.len();
        self.buffer[self.buffer_offset..end].copy_from_slice(input);
        self.buffer_offset = end;
        Ok(())
    }

    /// Completes the final block with the padding, writes the tag and starts
    /// the next message under the same key and IV. `NotInitialised` before a
    /// successful `init`, and `OutputTooShort` for an output shorter than the
    /// tag, both with the message left in place; `PaddingFailed` when the
    /// scheme cannot pad, which discards the message. Variable time, as DES
    /// is.
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
        if self.padding.requires_extra_block() && self.buffer_offset == BLOCK_BYTES {
            self.process_buffer()?;
        }
        if !self.padding.pad(&mut self.buffer, self.buffer_offset) {
            // A block may already have been processed, so the message cannot
            // go on.
            self.clear_message();
            return Err(MacError::PaddingFailed);
        }
        self.process_buffer()?;

        let mut temporary = [0_u8; BLOCK_BYTES];
        self.second
            .process_block(&self.chain, &mut temporary)
            .map_err(MacError::Cipher)?;
        self.third
            .process_block(&temporary, &mut self.chain)
            .map_err(MacError::Cipher)?;
        temporary.zeroize();

        output[..self.mac_size].copy_from_slice(&self.chain[..self.mac_size]);
        self.clear_message();
        Ok(self.mac_size)
    }

    /// Discards the message and restarts the chain from the IV, as Bouncy
    /// Castle's Java `reset` does; its C# `Reset` leaves the chain where the
    /// last message ended. Constant time.
    fn reset(&mut self) {
        self.clear_message();
    }
}

impl<P, K> MacInit<K> for Iso9797Alg3Mac<P>
where
    K: KeyParams + IvParams + ?Sized,
{
    type Error = InitError<tc_block_cipher::InitError>;

    /// Keys the three DES steps and sets the IV. `InvalidKeyLength` unless the
    /// key is 16 or 24 bytes, `InvalidIvLength` unless the IV is 8 bytes, and
    /// `Cipher` when DES refuses a key; a failure leaves the MAC uninitialized.
    /// Variable time, as the DES key schedule is.
    fn init(&mut self, params: &K) -> Result<(), Self::Error> {
        self.initialized = false;
        let key = params.key();
        if key.len() != DOUBLE_KEY_BYTES && key.len() != TRIPLE_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if iv.len() != BLOCK_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }
        let third = if key.len() == TRIPLE_KEY_BYTES {
            &key[16..24]
        } else {
            &key[..8]
        };
        Self::key_engine(&mut self.first, CipherDirection::Encrypt, &key[..8])?;
        Self::key_engine(&mut self.second, CipherDirection::Decrypt, &key[8..16])?;
        Self::key_engine(&mut self.third, CipherDirection::Encrypt, third)?;
        self.iv.copy_from_slice(iv);
        self.clear_message();
        self.initialized = true;
        Ok(())
    }
}

impl<P> Drop for Iso9797Alg3Mac<P> {
    /// Wipes the IV, the chain and the buffered message; each DES engine wipes
    /// its own key schedule. Constant time.
    fn drop(&mut self) {
        self.iv.zeroize();
        self.chain.zeroize();
        self.buffer.zeroize();
    }
}
