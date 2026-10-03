//! CBC-MAC without an allocator.

use core::fmt::{self, Display, Formatter};

use tc_block_cipher::{BlockCipher, BlockCipherInit};
use tc_block_modes::{FixedCbcBlockCipher, IvParams};
use tc_block_padding::BlockCipherPadding;

use super::shared::CbcMacCore;
use crate::{InitError, Mac, MacError, MacInit};

/// CBC-MAC over the block cipher `C` with blocks of `N` bytes, keeping its
/// buffers inline for builds without an allocator; Bouncy Castle's
/// `CbcBlockCipherMac` without padding.
///
/// The tag is the first [`mac_size`](Mac::mac_size) bytes of the last block of
/// the CBC encryption of the message, half a block unless sized otherwise. A
/// partial final block is filled with zeros, and a full one is left as it is.
/// `init` takes a key and an IV through `tc_block_modes::IvParams`; an all-zero
/// IV gives the classic CBC-MAC and matches Bouncy Castle keyed without one.
/// After `do_final` the MAC starts the next message under the same key and IV.
///
/// CBC-MAC is secure only for messages of one fixed length: from tags of
/// variable-length messages an attacker can forge others, and with zero fill a
/// message and the same message followed by zero bytes up to the block
/// boundary share a tag. Use [`FixedCmac`](crate::FixedCmac) where lengths
/// vary.
///
/// Constant time exactly when the cipher is: CBC adds only XORs and copies,
/// and only lengths decide the work. The buffers are wiped on drop, the CBC mode
/// wipes its IV and chaining value, and the cipher wipes its own key schedule
/// when its type does.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_modes::KeyWithIvRef;
/// use tc_macs::{FixedCbcMac, Mac, MacInit};
///
/// let mut mac = FixedCbcMac::<_, 16>::with_mac_size(AesEngine::new(), 16);
/// mac.init(&KeyWithIvRef::new(&[0x42; 16], &[0; 16]))?;
/// mac.update(b"exactly thirty-two bytes long!!!")?;
/// let mut tag = [0; 16];
/// assert_eq!(mac.do_final(&mut tag)?, 16);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedCbcMac<C, const N: usize> {
    core: CbcMacCore<FixedCbcBlockCipher<C, N>, [u8; N]>,
}

impl<C, const N: usize> FixedCbcMac<C, N> {
    /// Wraps `cipher` with a tag of half a block, as Bouncy Castle does.
    /// Constant time.
    ///
    /// # Panics
    ///
    /// Panics if `N` is less than 2.
    pub fn new(cipher: C) -> Self {
        Self::with_mac_size(cipher, N / 2)
    }

    /// Wraps `cipher` with a tag of `mac_size` bytes. Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `mac_size` is in `1..=N`.
    pub fn with_mac_size(cipher: C, mac_size: usize) -> Self {
        Self {
            core: CbcMacCore::new(FixedCbcBlockCipher::new(cipher), [0; N], [0; N], mac_size),
        }
    }
}

impl<C: Display, const N: usize> Display for FixedCbcMac<C, N> {
    /// Writes the name of the CBC mode, such as `"AES/CBC"`, as Bouncy
    /// Castle's `AlgorithmName` does. Constant time: no key material is
    /// inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.core.mode().fmt(f)
    }
}

impl<C, const N: usize> Mac for FixedCbcMac<C, N>
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

    /// Fills a partial final block with zeros, encrypts it, writes the tag and
    /// starts the next message under the same key and IV. Constant time
    /// exactly when the cipher is.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.core.do_final(output)
    }

    /// Discards the message and restarts the chain from the IV. Constant time.
    fn reset(&mut self) {
        self.core.clear_message();
    }
}

impl<C, P, const N: usize> MacInit<P> for FixedCbcMac<C, N>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
    <C as BlockCipherInit<P>>::Error: 'static,
{
    type Error = InitError<<C as BlockCipherInit<P>>::Error>;

    /// Keys the cipher for encryption and sets the IV, which must be one block
    /// long. Constant time exactly when the cipher's key setup is.
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.core.init(params)
    }
}

/// CBC-MAC over the block cipher `C` with blocks of `N` bytes that pads the
/// final block with `P`, keeping its buffers inline for builds without an
/// allocator; Bouncy Castle's `CbcBlockCipherMac` with padding.
///
/// It behaves as [`FixedCbcMac`] but for the final block: a partial one is
/// padded, and a full one is followed by a block of padding alone, whatever
/// the scheme. Padding keeps a message and its zero-extended form apart, but
/// the other limits of CBC-MAC remain: use [`FixedCmac`](crate::FixedCmac)
/// where lengths vary.
///
/// Constant time exactly when the cipher and the padding are; the schemes of
/// `tc_block_padding` pad in constant time with respect to the block contents.
/// The buffers are wiped on drop, as for `FixedCbcMac`.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_modes::KeyWithIvRef;
/// use tc_block_padding::Pkcs7Padding;
/// use tc_macs::{FixedPaddedCbcMac, Mac, MacInit};
///
/// let mut mac = FixedPaddedCbcMac::<_, 16, _>::new(AesEngine::new(), Pkcs7Padding);
/// mac.init(&KeyWithIvRef::new(&[0x42; 16], &[0; 16]))?;
/// mac.update(b"attack at dawn")?;
/// let mut tag = [0; 8];
/// assert_eq!(mac.do_final(&mut tag)?, 8);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedPaddedCbcMac<C, const N: usize, P> {
    mac: FixedCbcMac<C, N>,
    padding: P,
}

impl<C, const N: usize, P> FixedPaddedCbcMac<C, N, P> {
    /// Wraps `cipher` and `padding` with a tag of half a block, as Bouncy
    /// Castle does. Constant time.
    ///
    /// # Panics
    ///
    /// Panics if `N` is less than 2.
    pub fn new(cipher: C, padding: P) -> Self {
        Self::with_mac_size(cipher, N / 2, padding)
    }

    /// Wraps `cipher` and `padding` with a tag of `mac_size` bytes.
    /// Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `mac_size` is in `1..=N`.
    pub fn with_mac_size(cipher: C, mac_size: usize, padding: P) -> Self {
        Self {
            mac: FixedCbcMac::with_mac_size(cipher, mac_size),
            padding,
        }
    }

    /// Returns the padding scheme. Constant time.
    pub fn padding(&self) -> &P {
        &self.padding
    }
}

impl<C: Display, const N: usize, P> Display for FixedPaddedCbcMac<C, N, P> {
    /// Writes the name of the CBC mode, such as `"AES/CBC"`; as in Bouncy
    /// Castle, the padding is not named. Constant time: no key material is
    /// inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.mac.fmt(f)
    }
}

impl<C, const N: usize, P> Mac for FixedPaddedCbcMac<C, N, P>
where
    C: BlockCipher,
    C::Error: 'static,
    P: BlockCipherPadding,
{
    type Error = MacError<C::Error>;

    /// Returns the tag length in bytes. Constant time.
    fn mac_size(&self) -> usize {
        self.mac.mac_size()
    }

    /// Encrypts every block that `input` completes but a final one, which waits
    /// for `do_final`. Constant time exactly when the cipher is.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.mac.update(input)
    }

    /// Pads the final block, after a full one in a block of its own, encrypts
    /// it, writes the tag and starts the next message under the same key and
    /// IV. A padding failure discards the message. Constant time exactly when
    /// the cipher and the padding are.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.mac.core.do_final_padded(&mut self.padding, output)
    }

    /// Discards the message and restarts the chain from the IV. Constant time.
    fn reset(&mut self) {
        self.mac.reset();
    }
}

impl<C, const N: usize, P, Q> MacInit<Q> for FixedPaddedCbcMac<C, N, P>
where
    C: BlockCipher + BlockCipherInit<Q>,
    Q: IvParams + ?Sized,
    <C as BlockCipherInit<Q>>::Error: 'static,
{
    type Error = InitError<<C as BlockCipherInit<Q>>::Error>;

    /// Keys the cipher for encryption and sets the IV, which must be one block
    /// long. Constant time exactly when the cipher's key setup is.
    fn init(&mut self, params: &Q) -> Result<(), Self::Error> {
        self.mac.init(params)
    }
}
