//! KMAC128 and KMAC256.

use alloc::vec::Vec;
use core::{convert::Infallible, fmt};

use tc_digest::{Digest, TryDigest, TryXof, Xof};
use tc_keccak::CShakeDigest;
use tc_macs::{KeyParams, Mac, MacError, MacInit};
use tc_zeroize::{Zeroize, Zeroizing};

const FUNCTION_NAME: &[u8] = b"KMAC";
const MAX_RATE_BYTES: usize = 168;

/// KMAC128 or KMAC256 (NIST SP 800-185); Bouncy Castle's `KMac`.
///
/// `init` takes a key of any length through [`KeyParams`], the empty key
/// included, as Bouncy Castle does. Through [`Mac`] the tag is twice the
/// strength, 32 bytes for KMAC128 and 64 for KMAC256, and the output length is
/// bound into it. Through [`TryXof`], `try_output` starts KMACXOF, whose output
/// does not depend on its length, and `try_output_final` or a fixed-length
/// `try_do_final` ends it. After the message is finished the MAC starts the next
/// one under the same key.
///
/// Constant time, as Keccak is; the lengths of the key, the customization and
/// the message are public. The key is wiped on drop, and the cSHAKE state wipes
/// itself when its type does.
pub struct KMac {
    cshake: CShakeDigest,
    bit_length: usize,
    output_length: usize,
    key: Zeroizing<Vec<u8>>,
    initialized: bool,
    first_output: bool,
}

impl KMac {
    /// Creates an uninitialized KMAC128 or KMAC256 with the customization
    /// string, empty unless an application defines one. Constant time with
    /// respect to the contents of the customization; it takes time that depends
    /// on its length.
    ///
    /// # Panics
    ///
    /// Panics unless `bit_length` is 128 or 256, as cSHAKE does.
    pub fn new(bit_length: usize, customization: &[u8]) -> Self {
        assert!(
            matches!(bit_length, 128 | 256),
            "KMAC bit length must be 128 or 256"
        );
        Self {
            cshake: CShakeDigest::new(bit_length, FUNCTION_NAME, customization),
            bit_length,
            output_length: bit_length / 4,
            key: Zeroizing::new(Vec::new()),
            initialized: false,
            first_output: true,
        }
    }

    fn start_message(&mut self) {
        self.cshake.reset();
        self.first_output = true;
        if !self.initialized {
            return;
        }
        // SP 800-185's bytepad(encode_string(K), rate).
        let rate = self.cshake.byte_length();
        let (width, width_length) = left_encode(rate as u64);
        let (key_bits, key_bits_length) = left_encode((self.key.len() as u64).wrapping_mul(8));
        self.cshake.update(&width[..width_length]);
        self.cshake.update(&key_bits[..key_bits_length]);
        self.cshake.update(&self.key);

        let remainder = (width_length + key_bits_length + self.key.len()) % rate;
        if remainder != 0 {
            self.cshake.update(&[0; MAX_RATE_BYTES][..rate - remainder]);
        }
    }

    fn output(&mut self, output: &mut [u8]) -> Result<usize, MacError> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        if self.first_output {
            // KMACXOF binds an output length of zero.
            let (encoding, length) = right_encode(0);
            self.cshake.update(&encoding[..length]);
            self.first_output = false;
        }
        Ok(self.cshake.output(output))
    }

    fn output_final(&mut self, output: &mut [u8]) -> Result<usize, MacError> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        if self.first_output {
            let (encoding, length) = right_encode((output.len() as u64).wrapping_mul(8));
            self.cshake.update(&encoding[..length]);
        }
        let written = self.cshake.output_final(output);
        self.start_message();
        Ok(written)
    }
}

impl fmt::Display for KMac {
    /// Writes `"KMAC128"` or `"KMAC256"`, as Bouncy Castle names it, without
    /// touching the key. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KMAC{}", self.bit_length)
    }
}

impl Mac for KMac {
    type Error = MacError;

    /// Returns the tag length in bytes, 32 for KMAC128 and 64 for KMAC256.
    /// Constant time.
    fn mac_size(&self) -> usize {
        self.output_length
    }

    /// Adds `input` to the message. `NotInitialised` before `init`.
    /// Constant time.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        self.cshake.update(input);
        Ok(())
    }

    /// Writes the tag of `mac_size` bytes, with that length bound into it, and
    /// starts the next message under the same key. `NotInitialised` before
    /// `init`, and `OutputTooShort` for an output shorter than the tag, both
    /// with the message left in place. Constant time.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        if output.len() < self.output_length {
            return Err(MacError::OutputTooShort {
                required: self.output_length,
                available: output.len(),
            });
        }
        self.output_final(&mut output[..self.output_length])
    }

    /// Discards the message, KMACXOF output included, and keeps the key.
    /// Constant time.
    fn reset(&mut self) {
        self.start_message();
    }
}

impl<P: KeyParams + ?Sized> MacInit<P> for KMac {
    type Error = Infallible;

    /// Takes the key and starts a new message. Never fails: any key length is
    /// accepted, as Bouncy Castle does. Constant time with respect to the
    /// contents of the key; it takes time that depends on its length.
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.key.zeroize();
        self.key.extend_from_slice(params.key());
        self.initialized = true;
        self.start_message();
        Ok(())
    }
}

impl TryDigest for KMac {
    type Error = MacError;

    /// Returns the length `try_do_final` writes, the tag length. Constant time.
    fn digest_size(&self) -> usize {
        self.output_length
    }

    /// Returns the cSHAKE rate in bytes, 168 for KMAC128 and 136 for KMAC256.
    /// Constant time.
    fn byte_length(&self) -> usize {
        self.cshake.byte_length()
    }

    /// The same as [`Mac::update`]. Constant time.
    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        Mac::update(self, input)
    }

    /// The same as [`Mac::do_final`]. Constant time.
    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        Mac::do_final(self, output)
    }

    /// The same as [`Mac::reset`]; never fails. Constant time.
    fn try_reset(&mut self) -> Result<(), Self::Error> {
        Mac::reset(self);
        Ok(())
    }
}

impl TryXof for KMac {
    /// Writes the next `output.len()` bytes of KMACXOF; the first call binds
    /// an output length of zero, so the bytes do not depend on how much is
    /// read. `NotInitialised` before `init`. Constant time.
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.output(output)
    }

    /// Writes the last bytes and starts the next message under the same key.
    /// Without an earlier `try_output`, this is KMAC with an output of
    /// `output.len()` bytes, bound into it. `NotInitialised` before `init`.
    /// Constant time.
    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.output_final(output)
    }
}

// SP 800-185's left_encode, of a value that fits in a u64.
fn left_encode(value: u64) -> ([u8; 9], usize) {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&byte| byte != 0).unwrap_or(7);
    let length = 8 - first;
    let mut output = [0_u8; 9];
    output[0] = length as u8;
    output[1..=length].copy_from_slice(&bytes[first..]);
    (output, length + 1)
}

// SP 800-185's right_encode, of a value that fits in a u64.
fn right_encode(value: u64) -> ([u8; 9], usize) {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&byte| byte != 0).unwrap_or(7);
    let length = 8 - first;
    let mut output = [0_u8; 9];
    output[..length].copy_from_slice(&bytes[first..]);
    output[length] = length as u8;
    (output, length + 1)
}
