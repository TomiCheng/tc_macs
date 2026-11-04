//! VMPC-MAC.

use core::fmt::{self, Display, Formatter};

use tc_block_cipher::KeyParams;
use tc_block_modes::IvParams;
use tc_zeroize::Zeroize;

use crate::{InitError, Mac, MacError, MacInit};

const STATE_BYTES: usize = 256;
const TABLE_BYTES: usize = 32;
const KSA_STEPS: usize = 768;
const MIN_KEY_BYTES: usize = 16;
const MAX_KEY_BYTES: usize = 64;
const MIN_IV_BYTES: usize = 16;
const MAX_IV_BYTES: usize = 64;

/// VMPC-MAC, the MAC of Bartosz Zoltak's VMPC stream cipher, with a key and an
/// IV of 16 to 64 bytes and a 20-byte tag; Bouncy Castle's `VmpcMac`.
///
/// Available with the `vmpc-mac` feature.
///
/// `init` takes a key through [`KeyParams`] and an IV through [`IvParams`],
/// both required, as Bouncy Castle requires them. After `do_final` the MAC
/// starts the next message under the same key and IV, running the key schedule
/// again.
///
/// Variable time: every step indexes the permutation with bytes derived from
/// the key and the message, so cache timing can leak them. Use it only where
/// that leakage is outside the threat model. The key, the IV, the permutation
/// and the rest of the state are wiped on drop.
///
/// # Example
///
/// ```
/// use tc_macs::{KeyWithIvRef, Mac, MacInit, VmpcMac};
///
/// let mut mac = VmpcMac::new();
/// mac.init(&KeyWithIvRef::new(&[0x42; 16], &[0x24; 16]))?;
/// mac.update(b"attack at dawn")?;
/// let mut tag = [0; VmpcMac::TAG_BYTES];
/// assert_eq!(mac.do_final(&mut tag)?, 20);
/// assert_eq!(mac.to_string(), "VMPC-MAC");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct VmpcMac {
    permutation: [u8; STATE_BYTES],
    table: [u8; TABLE_BYTES],
    key: [u8; MAX_KEY_BYTES],
    key_len: usize,
    iv: [u8; MAX_IV_BYTES],
    iv_len: usize,
    g: u8,
    n: u8,
    s: u8,
    x1: u8,
    x2: u8,
    x3: u8,
    x4: u8,
    initialized: bool,
}

impl VmpcMac {
    /// The tag length, in bytes.
    pub const TAG_BYTES: usize = 20;

    /// Creates an uninitialized VMPC-MAC. Constant time.
    pub const fn new() -> Self {
        Self {
            permutation: [0; STATE_BYTES],
            table: [0; TABLE_BYTES],
            key: [0; MAX_KEY_BYTES],
            key_len: 0,
            iv: [0; MAX_IV_BYTES],
            iv_len: 0,
            g: 0,
            n: 0,
            s: 0,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            initialized: false,
        }
    }

    fn ksa_round(permutation: &mut [u8; STATE_BYTES], s: &mut u8, input: &[u8]) {
        for step in 0..KSA_STEPS {
            let index = step & 0xff;
            *s = permutation[s
                .wrapping_add(permutation[index])
                .wrapping_add(input[step % input.len()]) as usize];
            permutation.swap(index, *s as usize);
        }
    }

    fn start_message(&mut self) {
        self.n = 0;
        self.s = 0;
        for (index, byte) in self.permutation.iter_mut().enumerate() {
            *byte = index as u8;
        }
        Self::ksa_round(
            &mut self.permutation,
            &mut self.s,
            &self.key[..self.key_len],
        );
        Self::ksa_round(&mut self.permutation, &mut self.s, &self.iv[..self.iv_len]);
        self.g = 0;
        self.x1 = 0;
        self.x2 = 0;
        self.x3 = 0;
        self.x4 = 0;
        self.table.zeroize();
    }

    fn absorb_table(&mut self) {
        self.table[self.g as usize] ^= self.x1;
        self.table[self.g.wrapping_add(1) as usize & 0x1f] ^= self.x2;
        self.table[self.g.wrapping_add(2) as usize & 0x1f] ^= self.x3;
        self.table[self.g.wrapping_add(3) as usize & 0x1f] ^= self.x4;
        self.g = self.g.wrapping_add(4) & 0x1f;
    }

    fn update_byte(&mut self, input: u8) {
        let n = self.n as usize;
        let pn = self.permutation[n];
        self.s = self.permutation[self.s.wrapping_add(pn) as usize];
        let ps = self.permutation[self.s as usize];
        let cipher_byte =
            input ^ self.permutation[self.permutation[ps as usize].wrapping_add(1) as usize];

        self.x4 = self.permutation[self.x4.wrapping_add(self.x3) as usize];
        self.x3 = self.permutation[self.x3.wrapping_add(self.x2) as usize];
        self.x2 = self.permutation[self.x2.wrapping_add(self.x1) as usize];
        self.x1 = self.permutation[self.x1.wrapping_add(self.s).wrapping_add(cipher_byte) as usize];
        self.absorb_table();

        self.permutation[n] = ps;
        self.permutation[self.s as usize] = pn;
        self.n = self.n.wrapping_add(1);
    }

    fn wipe(&mut self) {
        self.permutation.zeroize();
        self.table.zeroize();
        self.key.zeroize();
        self.key_len = 0;
        self.iv.zeroize();
        self.iv_len = 0;
        self.g.zeroize();
        self.n.zeroize();
        self.s.zeroize();
        self.x1.zeroize();
        self.x2.zeroize();
        self.x3.zeroize();
        self.x4.zeroize();
    }
}

impl Default for VmpcMac {
    /// Creates an uninitialized VMPC-MAC. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl Display for VmpcMac {
    /// Writes `"VMPC-MAC"`, as Bouncy Castle's `AlgorithmName` does.
    /// Constant time: no key material is inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("VMPC-MAC")
    }
}

impl Mac for VmpcMac {
    type Error = MacError;

    /// Returns the tag length, 20 bytes. Constant time.
    fn mac_size(&self) -> usize {
        Self::TAG_BYTES
    }

    /// Absorbs `input` a byte at a time. Variable time: each byte indexes the
    /// permutation.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        for &byte in input {
            self.update_byte(byte);
        }
        Ok(())
    }

    /// Runs the post-processing phase, writes the tag and starts the next
    /// message under the same key and IV. Variable time: each step indexes the
    /// permutation with secret bytes.
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

        for round in 1_u8..25 {
            self.s =
                self.permutation[self.s.wrapping_add(self.permutation[self.n as usize]) as usize];
            self.x4 = self.permutation[self.x4.wrapping_add(self.x3).wrapping_add(round) as usize];
            self.x3 = self.permutation[self.x3.wrapping_add(self.x2).wrapping_add(round) as usize];
            self.x2 = self.permutation[self.x2.wrapping_add(self.x1).wrapping_add(round) as usize];
            self.x1 = self.permutation[self.x1.wrapping_add(self.s).wrapping_add(round) as usize];
            self.absorb_table();
            self.permutation.swap(self.n as usize, self.s as usize);
            self.n = self.n.wrapping_add(1);
        }

        for step in 0..KSA_STEPS {
            let index = step & 0xff;
            self.s = self.permutation[self
                .s
                .wrapping_add(self.permutation[index])
                .wrapping_add(self.table[step & 0x1f])
                as usize];
            self.permutation.swap(index, self.s as usize);
        }

        for (index, byte) in output[..Self::TAG_BYTES].iter_mut().enumerate() {
            self.s = self.permutation[self.s.wrapping_add(self.permutation[index]) as usize];
            *byte = self.permutation[self.permutation[self.permutation[self.s as usize] as usize]
                .wrapping_add(1) as usize];
            self.permutation.swap(index, self.s as usize);
        }

        self.start_message();
        Ok(Self::TAG_BYTES)
    }

    /// Discards the message and keeps the key and IV by running the key
    /// schedule again. Variable time: the schedule indexes the permutation with
    /// the key.
    fn reset(&mut self) {
        if self.initialized {
            self.start_message();
        }
    }
}

impl<P: KeyParams + IvParams + ?Sized> MacInit<P> for VmpcMac {
    type Error = InitError;

    /// Keys the MAC with a key and an IV of 16 to 64 bytes each and starts a new
    /// message. Variable time: the key schedule indexes the permutation with
    /// the key and the IV.
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.wipe();

        let key = params.key();
        if !(MIN_KEY_BYTES..=MAX_KEY_BYTES).contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if !(MIN_IV_BYTES..=MAX_IV_BYTES).contains(&iv.len()) {
            return Err(InitError::InvalidIvLength(iv.len()));
        }

        self.key[..key.len()].copy_from_slice(key);
        self.key_len = key.len();
        self.iv[..iv.len()].copy_from_slice(iv);
        self.iv_len = iv.len();
        self.initialized = true;
        self.start_message();
        Ok(())
    }
}

impl Drop for VmpcMac {
    /// Wipes the key, the IV, the permutation and the rest of the state.
    fn drop(&mut self) {
        self.wipe();
    }
}
