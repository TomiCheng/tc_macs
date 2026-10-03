//! Raw Poly1305 MAC.

use core::fmt;
use core::fmt::{Display, Formatter};
use tc_macs::{InitError, KeyParams, Mac, MacError, MacInit};
use tc_zeroize::Zeroize;

use crate::{BLOCK_BYTES, KEY_BYTES, TAG_BYTES};

const LIMB_MASK: u32 = 0x03ff_ffff;
const FULL_BLOCK_HIGH_BIT: u32 = 1 << 24;

/// Raw Poly1305 message authentication code (RFC 8439); Bouncy Castle's
/// `Poly1305` without a block cipher.
///
/// Initialization accepts any [`KeyParams`] implementation that supplies a
/// 32-byte one-time key. No Poly1305-specific parameter wrapper is required.
/// The tag is 16 bytes.
///
/// # Security
///
/// A Poly1305 key must never authenticate two different messages, so
/// [`do_final`](Mac::do_final) consumes it: the key is wiped and the MAC is
/// left uninitialized until a fresh one-time key is supplied. This is stricter
/// than Bouncy Castle, which keeps the key. [`reset`](Mac::reset) before
/// `do_final` discards the message and keeps the key, since no tag has been
/// released yet.
///
/// Constant time: the accumulator is multiplied in 26-bit limbs with 64-bit
/// products, carries and the final reduction use arithmetic instead of
/// branches, and only lengths decide the work.
///
/// The key and the message state are wiped on drop. A clone is another copy of
/// the key.
#[derive(Clone)]
pub struct Poly1305 {
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    r4: u32,
    s1: u32,
    s2: u32,
    s3: u32,
    s4: u32,
    k0: u32,
    k1: u32,
    k2: u32,
    k3: u32,
    block: [u8; BLOCK_BYTES],
    block_offset: usize,
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    initialized: bool,
}

impl Poly1305 {
    /// Creates an uninitialized Poly1305 MAC. Constant time.
    pub const fn new() -> Self {
        Self {
            r0: 0,
            r1: 0,
            r2: 0,
            r3: 0,
            r4: 0,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            k0: 0,
            k1: 0,
            k2: 0,
            k3: 0,
            block: [0; BLOCK_BYTES],
            block_offset: 0,
            h0: 0,
            h1: 0,
            h2: 0,
            h3: 0,
            h4: 0,
            initialized: false,
        }
    }

    #[inline]
    fn load_u32(input: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            input[offset],
            input[offset + 1],
            input[offset + 2],
            input[offset + 3],
        ])
    }

    fn clear_key(&mut self) {
        for limb in [
            &mut self.r0,
            &mut self.r1,
            &mut self.r2,
            &mut self.r3,
            &mut self.r4,
            &mut self.s1,
            &mut self.s2,
            &mut self.s3,
            &mut self.s4,
            &mut self.k0,
            &mut self.k1,
            &mut self.k2,
            &mut self.k3,
        ] {
            limb.zeroize();
        }
    }

    fn clear_message(&mut self) {
        self.block.zeroize();
        self.block_offset = 0;
        for limb in [
            &mut self.h0,
            &mut self.h1,
            &mut self.h2,
            &mut self.h3,
            &mut self.h4,
        ] {
            limb.zeroize();
        }
    }

    fn set_key(&mut self, key: &[u8; KEY_BYTES]) {
        let t0 = Self::load_u32(key, 0);
        let t1 = Self::load_u32(key, 4);
        let t2 = Self::load_u32(key, 8);
        let t3 = Self::load_u32(key, 12);

        // These masks perform the Poly1305 key clamp without modifying the
        // caller's key bytes.
        self.r0 = t0 & 0x03ff_ffff;
        self.r1 = ((t0 >> 26) | (t1 << 6)) & 0x03ff_ff03;
        self.r2 = ((t1 >> 20) | (t2 << 12)) & 0x03ff_c0ff;
        self.r3 = ((t2 >> 14) | (t3 << 18)) & 0x03f0_3fff;
        self.r4 = (t3 >> 8) & 0x000f_ffff;

        self.s1 = self.r1 * 5;
        self.s2 = self.r2 * 5;
        self.s3 = self.r3 * 5;
        self.s4 = self.r4 * 5;

        self.k0 = Self::load_u32(key, 16);
        self.k1 = Self::load_u32(key, 20);
        self.k2 = Self::load_u32(key, 24);
        self.k3 = Self::load_u32(key, 28);
    }

    fn process_block(&mut self, block: &[u8], high_bit: u32) {
        let t0 = Self::load_u32(block, 0);
        let t1 = Self::load_u32(block, 4);
        let t2 = Self::load_u32(block, 8);
        let t3 = Self::load_u32(block, 12);

        self.h0 += t0 & LIMB_MASK;
        self.h1 += ((t1 << 6) | (t0 >> 26)) & LIMB_MASK;
        self.h2 += ((t2 << 12) | (t1 >> 20)) & LIMB_MASK;
        self.h3 += ((t3 << 18) | (t2 >> 14)) & LIMB_MASK;
        self.h4 += high_bit | (t3 >> 8);

        let tp0 = u64::from(self.h0) * u64::from(self.r0)
            + u64::from(self.h1) * u64::from(self.s4)
            + u64::from(self.h2) * u64::from(self.s3)
            + u64::from(self.h3) * u64::from(self.s2)
            + u64::from(self.h4) * u64::from(self.s1);
        let mut tp1 = u64::from(self.h0) * u64::from(self.r1)
            + u64::from(self.h1) * u64::from(self.r0)
            + u64::from(self.h2) * u64::from(self.s4)
            + u64::from(self.h3) * u64::from(self.s3)
            + u64::from(self.h4) * u64::from(self.s2);
        let mut tp2 = u64::from(self.h0) * u64::from(self.r2)
            + u64::from(self.h1) * u64::from(self.r1)
            + u64::from(self.h2) * u64::from(self.r0)
            + u64::from(self.h3) * u64::from(self.s4)
            + u64::from(self.h4) * u64::from(self.s3);
        let mut tp3 = u64::from(self.h0) * u64::from(self.r3)
            + u64::from(self.h1) * u64::from(self.r2)
            + u64::from(self.h2) * u64::from(self.r1)
            + u64::from(self.h3) * u64::from(self.r0)
            + u64::from(self.h4) * u64::from(self.s4);
        let mut tp4 = u64::from(self.h0) * u64::from(self.r4)
            + u64::from(self.h1) * u64::from(self.r3)
            + u64::from(self.h2) * u64::from(self.r2)
            + u64::from(self.h3) * u64::from(self.r1)
            + u64::from(self.h4) * u64::from(self.r0);

        self.h0 = tp0 as u32 & LIMB_MASK;
        tp1 += tp0 >> 26;
        self.h1 = tp1 as u32 & LIMB_MASK;
        tp2 += tp1 >> 26;
        self.h2 = tp2 as u32 & LIMB_MASK;
        tp3 += tp2 >> 26;
        self.h3 = tp3 as u32 & LIMB_MASK;
        tp4 += tp3 >> 26;
        self.h4 = tp4 as u32 & LIMB_MASK;
        self.h0 += (tp4 >> 26) as u32 * 5;
        self.h1 += self.h0 >> 26;
        self.h0 &= LIMB_MASK;
    }

    fn write_tag(&mut self, output: &mut [u8]) {
        self.h0 += 5;
        self.h1 += self.h0 >> 26;
        self.h0 &= LIMB_MASK;
        self.h2 += self.h1 >> 26;
        self.h1 &= LIMB_MASK;
        self.h3 += self.h2 >> 26;
        self.h2 &= LIMB_MASK;
        self.h4 += self.h3 >> 26;
        self.h3 &= LIMB_MASK;

        let mut carry = (i64::from(self.h4 >> 26) - 1) * 5;
        carry += i64::from(self.k0) + i64::from(self.h0 | (self.h1 << 26));
        output[..4].copy_from_slice(&(carry as u32).to_le_bytes());
        carry >>= 32;
        carry += i64::from(self.k1) + i64::from((self.h1 >> 6) | (self.h2 << 20));
        output[4..8].copy_from_slice(&(carry as u32).to_le_bytes());
        carry >>= 32;
        carry += i64::from(self.k2) + i64::from((self.h2 >> 12) | (self.h3 << 14));
        output[8..12].copy_from_slice(&(carry as u32).to_le_bytes());
        carry >>= 32;
        carry += i64::from(self.k3) + i64::from((self.h3 >> 18) | (self.h4 << 8));
        output[12..TAG_BYTES].copy_from_slice(&(carry as u32).to_le_bytes());
    }
}

impl Default for Poly1305 {
    /// Creates an uninitialized Poly1305 MAC, as [`new`](Self::new) does.
    /// Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl Display for Poly1305 {
    /// Writes `Poly1305`, as Bouncy Castle's `AlgorithmName` does for raw
    /// Poly1305. Constant time: no key material is inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("Poly1305")
    }
}

impl Mac for Poly1305 {
    type Error = MacError;

    /// Returns the tag length, 16 bytes. Constant time.
    fn mac_size(&self) -> usize {
        TAG_BYTES
    }

    /// Absorbs every block that `input` completes and buffers the rest.
    /// Constant time: only the input length decides the work.
    fn update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }

        if self.block_offset != 0 {
            let available = BLOCK_BYTES - self.block_offset;
            let take = available.min(input.len());
            self.block[self.block_offset..self.block_offset + take].copy_from_slice(&input[..take]);
            self.block_offset += take;
            input = &input[take..];

            if self.block_offset < BLOCK_BYTES {
                return Ok(());
            }

            let mut block = self.block;
            self.process_block(&block, FULL_BLOCK_HIGH_BIT);
            block.zeroize();
            self.block_offset = 0;
        }

        while input.len() >= BLOCK_BYTES {
            self.process_block(&input[..BLOCK_BYTES], FULL_BLOCK_HIGH_BIT);
            input = &input[BLOCK_BYTES..];
        }

        self.block[..input.len()].copy_from_slice(input);
        self.block_offset = input.len();
        Ok(())
    }

    /// Absorbs a partial final block, writes the tag and wipes the key, which
    /// leaves the MAC uninitialized. A short output buffer is refused before
    /// anything changes. Constant time.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        if output.len() < TAG_BYTES {
            return Err(MacError::OutputTooShort {
                required: TAG_BYTES,
                available: output.len(),
            });
        }

        if self.block_offset != 0 {
            let mut block = self.block;
            block[self.block_offset] = 1;
            block[self.block_offset + 1..].fill(0);
            self.process_block(&block, 0);
            block.zeroize();
        }

        debug_assert_eq!(self.h4 >> 26, 0);
        self.write_tag(output);
        // The one-time key is used up: wipe it, so that the next message needs
        // a fresh init.
        self.clear_message();
        self.clear_key();
        self.initialized = false;
        Ok(TAG_BYTES)
    }

    /// Discards the message and keeps the key, which no tag has used yet.
    /// After `do_final` the MAC stays uninitialized. Constant time.
    fn reset(&mut self) {
        self.clear_message();
    }
}

impl<P> MacInit<P> for Poly1305
where
    P: KeyParams + ?Sized,
{
    type Error = InitError;

    /// Installs a 32-byte one-time key and starts a message. Any other length
    /// is refused with `InvalidKeyLength` and leaves the MAC uninitialized.
    /// Constant time: the key is clamped with masks.
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.reset();
        self.clear_key();

        let key = params.key();
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| InitError::InvalidKeyLength(key.len()))?;

        self.set_key(key);
        self.initialized = true;
        self.reset();
        Ok(())
    }
}

impl Drop for Poly1305 {
    /// Wipes the key, the accumulator and the buffered block. Constant time.
    fn drop(&mut self) {
        self.clear_message();
        self.clear_key();
    }
}
