//! The borrowed parameters of the GOST 28147 MAC.

use tc_block_cipher::KeyParams;
use tc_block_modes::IvParams;
use tc_gost28147::{Gost28147Params, s_box};

/// Borrowed GOST 28147 MAC parameters: a key, an S-box and an 8-byte IV.
///
/// An all-zero IV gives Bouncy Castle's form keyed without one. The lengths are
/// judged by `init`, not here. It has no `Debug`, which would show the key.
/// Constant time: it only holds references.
#[derive(Clone, Copy)]
pub struct Gost28147MacParamsRef<'a> {
    key: &'a [u8],
    s_box: &'a [u8],
    iv: &'a [u8],
}

impl<'a> Gost28147MacParamsRef<'a> {
    /// Borrows a key and an IV, with the CryptoPro E-A S-box. Constant time.
    pub const fn new(key: &'a [u8], iv: &'a [u8]) -> Self {
        Self {
            key,
            s_box: &s_box::E_A,
            iv,
        }
    }

    /// Selects another S-box. Constant time.
    pub const fn with_s_box(mut self, s_box: &'a [u8]) -> Self {
        self.s_box = s_box;
        self
    }
}

impl KeyParams for Gost28147MacParamsRef<'_> {
    /// Returns the key. Constant time.
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl Gost28147Params for Gost28147MacParamsRef<'_> {
    /// Returns the S-box. Constant time.
    fn s_box(&self) -> &[u8] {
        self.s_box
    }
}

impl IvParams for Gost28147MacParamsRef<'_> {
    /// Returns the IV. Constant time.
    fn iv(&self) -> &[u8] {
        self.iv
    }
}
