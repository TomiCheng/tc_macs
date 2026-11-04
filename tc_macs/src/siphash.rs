//! SipHash-c-d.

use core::fmt::{self, Display, Formatter};

use tc_block_cipher::KeyParams;
use tc_zeroize::Zeroize;

use crate::{InitError, Mac, MacError, MacInit};

/// SipHash-c-d, the short-input PRF of Aumasson and Bernstein, with a 16-byte
/// key and an 8-byte tag; Bouncy Castle's `SipHash`.
///
/// Available with the `siphash` feature.
///
/// [`new`](Self::new) gives SipHash-2-4. `init` takes only a key, through
/// [`KeyParams`]; another length is an error. After `do_final` the MAC starts
/// the next message under the same key. An 8-byte tag suits hash tables and
/// other short-lived authenticators, not a general-purpose MAC.
///
/// Constant time: only additions, rotations and XORs, so the running time
/// depends on the message length alone. The key, the state and the buffered
/// bytes are wiped on drop.
///
/// # Example
///
/// ```
/// use tc_macs::{KeyRef, Mac, MacInit, SipHash};
///
/// // The example of the SipHash paper, appendix A.
/// let key: [u8; 16] = core::array::from_fn(|index| index as u8);
/// let message: [u8; 15] = core::array::from_fn(|index| index as u8);
/// let mut mac = SipHash::new();
/// mac.init(&KeyRef::new(&key))?;
/// mac.update(&message)?;
/// let mut tag = [0; SipHash::TAG_BYTES];
/// mac.do_final(&mut tag)?;
/// assert_eq!(u64::from_le_bytes(tag), 0xa129_ca61_49be_45e5);
/// assert_eq!(mac.to_string(), "SipHash-2-4");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct SipHash {
    compression_rounds: usize,
    finalization_rounds: usize,
    key0: u64,
    key1: u64,
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    tail: [u8; 8],
    tail_len: usize,
    message_len: u64,
    initialized: bool,
}

impl SipHash {
    /// The key length, in bytes.
    pub const KEY_BYTES: usize = 16;
    /// The tag length, in bytes.
    pub const TAG_BYTES: usize = 8;

    /// Creates an uninitialized SipHash-2-4. Constant time.
    pub const fn new() -> Self {
        Self::with_rounds(2, 4)
    }

    /// Creates an uninitialized SipHash-c-d with `compression_rounds` and
    /// `finalization_rounds`. Constant time.
    pub const fn with_rounds(compression_rounds: usize, finalization_rounds: usize) -> Self {
        Self {
            compression_rounds,
            finalization_rounds,
            key0: 0,
            key1: 0,
            v0: 0,
            v1: 0,
            v2: 0,
            v3: 0,
            tail: [0; 8],
            tail_len: 0,
            message_len: 0,
            initialized: false,
        }
    }

    fn sip_rounds(&mut self, rounds: usize) {
        for _ in 0..rounds {
            self.v0 = self.v0.wrapping_add(self.v1);
            self.v2 = self.v2.wrapping_add(self.v3);
            self.v1 = self.v1.rotate_left(13) ^ self.v0;
            self.v3 = self.v3.rotate_left(16) ^ self.v2;
            self.v0 = self.v0.rotate_left(32);
            self.v2 = self.v2.wrapping_add(self.v1);
            self.v0 = self.v0.wrapping_add(self.v3);
            self.v1 = self.v1.rotate_left(17) ^ self.v2;
            self.v3 = self.v3.rotate_left(21) ^ self.v0;
            self.v2 = self.v2.rotate_left(32);
        }
    }

    fn process_word(&mut self, word: u64) {
        self.v3 ^= word;
        self.sip_rounds(self.compression_rounds);
        self.v0 ^= word;
    }

    fn start_message(&mut self) {
        self.v0 = self.key0 ^ 0x736f_6d65_7073_6575;
        self.v1 = self.key1 ^ 0x646f_7261_6e64_6f6d;
        self.v2 = self.key0 ^ 0x6c79_6765_6e65_7261;
        self.v3 = self.key1 ^ 0x7465_6462_7974_6573;
        self.tail.zeroize();
        self.tail_len = 0;
        self.message_len = 0;
    }

    fn wipe(&mut self) {
        self.key0.zeroize();
        self.key1.zeroize();
        self.v0.zeroize();
        self.v1.zeroize();
        self.v2.zeroize();
        self.v3.zeroize();
        self.tail.zeroize();
        self.tail_len = 0;
        self.message_len = 0;
    }
}

impl Default for SipHash {
    /// Creates an uninitialized SipHash-2-4. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl Display for SipHash {
    /// Writes the name with the round counts, such as `"SipHash-2-4"`, as
    /// Bouncy Castle's `AlgorithmName` does. Constant time: no key material is
    /// inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SipHash-{}-{}",
            self.compression_rounds, self.finalization_rounds
        )
    }
}

impl Mac for SipHash {
    type Error = MacError;

    /// Returns the tag length, 8 bytes. Constant time.
    fn mac_size(&self) -> usize {
        Self::TAG_BYTES
    }

    /// Absorbs `input`, a word at a time. Constant time: only its length
    /// decides the work.
    fn update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        self.message_len = self.message_len.wrapping_add(input.len() as u64);

        if self.tail_len != 0 {
            let take = (8 - self.tail_len).min(input.len());
            self.tail[self.tail_len..self.tail_len + take].copy_from_slice(&input[..take]);
            self.tail_len += take;
            input = &input[take..];
            if self.tail_len < 8 {
                return Ok(());
            }
            self.process_word(u64::from_le_bytes(self.tail));
            self.tail.zeroize();
            self.tail_len = 0;
        }

        let mut words = input.chunks_exact(8);
        for word in &mut words {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(word);
            self.process_word(u64::from_le_bytes(bytes));
        }
        let remainder = words.remainder();
        self.tail[..remainder.len()].copy_from_slice(remainder);
        self.tail_len = remainder.len();
        Ok(())
    }

    /// Absorbs the buffered bytes and the message length, runs the finalization
    /// rounds, writes the tag and starts the next message under the same key.
    /// Constant time: only the message length decides the work.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        if output.len() < Self::TAG_BYTES {
            return Err(MacError::OutputTooShort {
                required: Self::TAG_BYTES,
                available: output.len(),
            });
        }

        let mut final_word = (self.message_len & 0xff) << 56;
        for (index, &byte) in self.tail[..self.tail_len].iter().enumerate() {
            final_word |= u64::from(byte) << (index * 8);
        }
        self.process_word(final_word);
        final_word.zeroize();
        self.v2 ^= 0xff;
        self.sip_rounds(self.finalization_rounds);
        output[..Self::TAG_BYTES]
            .copy_from_slice(&(self.v0 ^ self.v1 ^ self.v2 ^ self.v3).to_le_bytes());
        self.start_message();
        Ok(Self::TAG_BYTES)
    }

    /// Discards the message and keeps the key. Constant time.
    fn reset(&mut self) {
        if self.initialized {
            self.start_message();
        }
    }
}

impl<P: KeyParams + ?Sized> MacInit<P> for SipHash {
    type Error = InitError;

    /// Keys the MAC with a key of exactly 16 bytes and starts a new message.
    /// Constant time: only the key length decides the work.
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.wipe();

        let key = params.key();
        let (Some(first), Some(second), Self::KEY_BYTES) =
            (key.first_chunk::<8>(), key.last_chunk::<8>(), key.len())
        else {
            return Err(InitError::InvalidKeyLength(key.len()));
        };
        self.key0 = u64::from_le_bytes(*first);
        self.key1 = u64::from_le_bytes(*second);
        self.initialized = true;
        self.start_message();
        Ok(())
    }
}

impl Drop for SipHash {
    /// Wipes the key, the state and the buffered bytes.
    fn drop(&mut self) {
        self.wipe();
    }
}
