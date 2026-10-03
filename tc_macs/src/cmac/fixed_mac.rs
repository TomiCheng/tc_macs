//! CMAC without an allocator.

use core::fmt::{self, Display, Formatter};

use tc_block_cipher::{BlockCipher, BlockCipherInit, KeyParams};

use super::shared::CmacCore;
use crate::{InitError, Mac, MacError, MacInit};

/// CMAC (NIST SP 800-38B, RFC 4493), also known as OMAC1, over the block
/// cipher `C` with blocks of `N` bytes, keeping its buffers inline for builds
/// without an allocator; Bouncy Castle's `CMac`.
///
/// CMAC supports 64- and 128-bit block ciphers, so `N` is 8 or 16. The tag is
/// the first [`mac_size`](Mac::mac_size) bytes of the full CMAC, a whole block
/// unless sized otherwise. Unlike CBC-MAC, CMAC is secure for messages of any
/// length. `init` takes only a key, through [`KeyParams`]; the IV is always
/// zero. After `do_final` the MAC starts the next message under the same key.
///
/// Constant time exactly when the cipher is: the subkeys are derived with
/// masks rather than branches, and only the message length decides whether the
/// final block is padded. The chaining value, the buffered block and the
/// subkeys are wiped on drop, and the cipher wipes its own key schedule when
/// its type does.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_macs::{FixedCmac, KeyRef, Mac, MacInit};
///
/// // RFC 4493, example 2.
/// let key = [
///     0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
///     0x3c,
/// ];
/// let message = [
///     0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
///     0x2a,
/// ];
/// let mut mac = FixedCmac::<_, 16>::new(AesEngine::new());
/// mac.init(&KeyRef::new(&key))?;
/// mac.update(&message)?;
/// let mut tag = [0; 16];
/// mac.do_final(&mut tag)?;
/// assert_eq!(
///     tag,
///     [
///         0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
///         0x28, 0x7c,
///     ]
/// );
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedCmac<C, const N: usize> {
    core: CmacCore<C, [u8; N]>,
}

impl<C, const N: usize> FixedCmac<C, N> {
    /// Wraps `cipher` with a tag of a whole block, as Bouncy Castle does.
    /// Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `N` is 8 or 16.
    pub fn new(cipher: C) -> Self {
        Self::with_mac_size(cipher, N)
    }

    /// Wraps `cipher` with a tag of `mac_size` bytes. Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `N` is 8 or 16 and `mac_size` is in `1..=N`.
    pub fn with_mac_size(cipher: C, mac_size: usize) -> Self {
        Self {
            core: CmacCore::new(cipher, [[0; N]; 4], mac_size),
        }
    }
}

impl<C: Display, const N: usize> Display for FixedCmac<C, N> {
    /// Writes the cipher's name followed by `/CMAC`, such as `"AES/CMAC"`.
    /// Bouncy Castle writes the name of its inner CBC mode, which CBC-MAC
    /// shares. Constant time: no key material is inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/CMAC", self.core.cipher())
    }
}

impl<C, const N: usize> Mac for FixedCmac<C, N>
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

impl<C, P, const N: usize> MacInit<P> for FixedCmac<C, N>
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
