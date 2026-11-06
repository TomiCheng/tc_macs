//! The owned parameters of the GOST 28147 MAC.

use alloc::vec::Vec;
use core::fmt;

use tc_block_cipher::KeyParams;
use tc_block_modes::IvParams;
use tc_gost28147::{Gost28147Params, s_box};
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

/// Owned GOST 28147 MAC parameters: a key, an S-box and an 8-byte IV, all wiped
/// on drop.
///
/// Available with the `alloc` feature. Construction takes the vectors without
/// copying them, and [`new`](Self::new) copies the CryptoPro E-A S-box into a new
/// vector. An all-zero IV gives Bouncy Castle's form keyed without one. The
/// lengths are judged by `init`, not here. The S-box may itself be secret in some
/// profiles and the IV is wiped to keep one rule, so all three are wiped with the
/// key. Wiping does not erase copies held elsewhere. `Debug` prints the lengths,
/// never the bytes.
///
/// Constant time: no method inspects the key, the S-box or the IV.
///
/// # Example
///
/// ```
/// use tc_gost28147_mac::{Gost28147Mac, Gost28147MacParamsOwned};
/// use tc_macs::{Mac, MacInit};
///
/// let params = Gost28147MacParamsOwned::new(vec![0x42; 32], vec![0x24; 8]);
/// let mut mac = Gost28147Mac::new();
/// mac.init(&params)?;
/// mac.update(b"attack at dawn")?;
/// let mut tag = [0; 4];
/// assert_eq!(mac.do_final(&mut tag)?, tag.len());
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Gost28147MacParamsOwned {
    key: Vec<u8>,
    s_box: Vec<u8>,
    iv: Vec<u8>,
}

impl Gost28147MacParamsOwned {
    /// Takes a key and an IV, with a copy of the CryptoPro E-A S-box.
    /// Constant time: moves the vectors without inspecting them and copies a
    /// public table.
    pub fn new(key: Vec<u8>, iv: Vec<u8>) -> Self {
        Self {
            key,
            s_box: s_box::E_A.to_vec(),
            iv,
        }
    }

    /// Selects another S-box, wiping the one it replaces. Constant time: the
    /// length of the old table alone decides the work.
    pub fn with_s_box(mut self, s_box: Vec<u8>) -> Self {
        self.s_box.zeroize();
        self.s_box = s_box;
        self
    }
}

impl KeyParams for Gost28147MacParamsOwned {
    /// Returns the stored key without copying it. Constant time.
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl Gost28147Params for Gost28147MacParamsOwned {
    /// Returns the stored S-box without copying it. Constant time.
    fn s_box(&self) -> &[u8] {
        &self.s_box
    }
}

impl IvParams for Gost28147MacParamsOwned {
    /// Returns the stored IV without copying it. Constant time.
    fn iv(&self) -> &[u8] {
        &self.iv
    }
}

impl fmt::Debug for Gost28147MacParamsOwned {
    /// Writes the lengths, never the bytes. Constant time with respect to their
    /// contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gost28147MacParamsOwned")
            .field("key_len", &self.key.len())
            .field("s_box_len", &self.s_box.len())
            .field("iv_len", &self.iv.len())
            .finish()
    }
}

impl Zeroize for Gost28147MacParamsOwned {
    /// Overwrites the key, the S-box and the IV with zeros and leaves them empty.
    /// Constant time: only their lengths decide the work.
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.s_box.zeroize();
        self.iv.zeroize();
    }
}

impl Drop for Gost28147MacParamsOwned {
    /// Wipes the key, the S-box and the IV. Constant time: only their lengths
    /// decide the work.
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Gost28147MacParamsOwned {}
