//! CMAC sized at run time.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Display, Formatter};

use tc_block_cipher::{BlockCipher, BlockCipherInit, KeyParams};

use super::shared::CmacCore;
use crate::{InitError, Mac, MacError, MacInit};

/// CMAC (NIST SP 800-38B, RFC 4493) over the block cipher `C`, with buffers
/// sized from its block size at run time; Bouncy Castle's `CMac`.
///
/// Available with the `cmac` and `alloc` features.
///
/// It computes the same tags as [`FixedCmac`](crate::FixedCmac) and, like it,
/// supports 64- and 128-bit block ciphers only.
///
/// Constant time exactly when the cipher is. The chaining value, the buffered
/// block and the subkeys are wiped on drop, and the cipher wipes its own key
/// schedule when its type does.
///
/// # Example
///
/// ```
/// use tc_des::DesEdeEngine;
/// use tc_macs::{Cmac, KeyRef, Mac, MacInit};
///
/// let mut mac = Cmac::new(DesEdeEngine::new());
/// mac.init(&KeyRef::new(&[0x42; 24]))?;
/// mac.update(b"attack at dawn")?;
/// let mut tag = vec![0; mac.mac_size()];
/// assert_eq!(mac.do_final(&mut tag)?, 8);
/// assert_eq!(mac.to_string(), "DESede/CMAC");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Cmac<C> {
    core: CmacCore<C, Vec<u8>>,
}

impl<C: BlockCipher> Cmac<C> {
    /// Wraps `cipher` with a tag of a whole block, as Bouncy Castle does.
    /// Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless the cipher's block size is 8 or 16 bytes.
    pub fn new(cipher: C) -> Self {
        let mac_size = cipher.block_size();
        Self::with_mac_size(cipher, mac_size)
    }

    /// Wraps `cipher` with a tag of `mac_size` bytes. Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless the cipher's block size is 8 or 16 bytes and `mac_size`
    /// is between 1 and the block size.
    pub fn with_mac_size(cipher: C, mac_size: usize) -> Self {
        let block_size = cipher.block_size();
        let buffers = core::array::from_fn(|_| vec![0; block_size]);
        Self {
            core: CmacCore::new(cipher, buffers, mac_size),
        }
    }
}

impl<C: Display> Display for Cmac<C> {
    /// Writes the cipher's name followed by `/CMAC`, such as `"AES/CMAC"`.
    /// Bouncy Castle writes the name of its inner CBC mode, which CBC-MAC
    /// shares. Constant time: no key material is inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/CMAC", self.core.cipher())
    }
}

impl<C> Mac for Cmac<C>
where
    C: BlockCipher,
    C::Error: 'static,
{
    type Error = MacError<C::Error>;

    /// Returns the tag length in bytes. Constant time.
    fn mac_size(&self) -> usize {
        self.core.mac_size()
    }

    /// Encrypts every block that `input` completes but a final one, which waits
    /// for `do_final`. Constant time exactly when the cipher is.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.core.update(input)
    }

    /// Masks the final block with the first subkey, or pads it and masks it
    /// with the second, encrypts it, writes the tag and starts the next message
    /// under the same key. Constant time exactly when the cipher is.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.core.do_final(output)
    }

    /// Discards the message and keeps the key. Constant time.
    fn reset(&mut self) {
        self.core.clear_message();
    }
}

impl<C, P> MacInit<P> for Cmac<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: KeyParams + ?Sized,
    <C as BlockCipherInit<P>>::Error: 'static,
{
    type Error = InitError<<C as BlockCipherInit<P>>::Error>;

    /// Keys the cipher for encryption and derives the subkeys from the
    /// encryption of a zero block. Constant time exactly when the cipher's key
    /// setup and block encryption are.
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.core.init(params)
    }
}
