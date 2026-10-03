//! CBC-MAC sized at run time.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Display, Formatter};

use tc_block_cipher::{BlockCipher, BlockCipherInit};
use tc_block_modes::{CbcBlockCipher, IvParams};
use tc_block_padding::BlockCipherPadding;

use super::shared::CbcMacCore;
use crate::{InitError, Mac, MacError, MacInit};

/// CBC-MAC over the block cipher `C`, with buffers sized from its block size
/// at run time; Bouncy Castle's `CbcBlockCipherMac` without padding. Requires
/// the `alloc` feature.
///
/// It computes the same tags as [`FixedCbcMac`](crate::FixedCbcMac) and shares
/// its limits: CBC-MAC is secure only for messages of one fixed length, and
/// zero fill gives a message and its zero-extended form the same tag. Use
/// `Cmac` where lengths vary.
///
/// Constant time exactly when the cipher is. The buffers are wiped on drop, the
/// CBC mode wipes its IV and chaining value, and the cipher wipes its own key
/// schedule when its type does.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_modes::KeyWithIvRef;
/// use tc_macs::{CbcMac, Mac, MacInit};
///
/// let mut mac = CbcMac::with_mac_size(AesEngine::new(), 16);
/// mac.init(&KeyWithIvRef::new(&[0x42; 16], &[0; 16]))?;
/// mac.update(b"exactly thirty-two bytes long!!!")?;
/// let mut tag = vec![0; mac.mac_size()];
/// assert_eq!(mac.do_final(&mut tag)?, 16);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct CbcMac<C> {
    core: CbcMacCore<CbcBlockCipher<C>, Vec<u8>>,
}

impl<C: BlockCipher> CbcMac<C> {
    /// Wraps `cipher` with a tag of half a block, as Bouncy Castle does.
    /// Constant time.
    ///
    /// # Panics
    ///
    /// Panics if the cipher's block size is less than 2 bytes.
    pub fn new(cipher: C) -> Self {
        let mac_size = cipher.block_size() / 2;
        Self::with_mac_size(cipher, mac_size)
    }

    /// Wraps `cipher` with a tag of `mac_size` bytes. Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `mac_size` is between 1 and the cipher's block size.
    pub fn with_mac_size(cipher: C, mac_size: usize) -> Self {
        let block_size = cipher.block_size();
        Self {
            core: CbcMacCore::new(
                CbcBlockCipher::new(cipher),
                vec![0; block_size],
                vec![0; block_size],
                mac_size,
            ),
        }
    }
}

impl<C: Display> Display for CbcMac<C> {
    /// Writes the name of the CBC mode, such as `"AES/CBC"`, as Bouncy
    /// Castle's `AlgorithmName` does. Constant time: no key material is
    /// inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.core.mode().fmt(f)
    }
}

impl<C> Mac for CbcMac<C>
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

impl<C, P> MacInit<P> for CbcMac<C>
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

/// CBC-MAC over the block cipher `C` that pads the final block with `P`, with
/// buffers sized from its block size at run time; Bouncy Castle's
/// `CbcBlockCipherMac` with padding. Requires the `alloc` feature.
///
/// It computes the same tags as
/// [`FixedPaddedCbcMac`](crate::FixedPaddedCbcMac): a partial final block is
/// padded, and a full one is followed by a block of padding alone, whatever the
/// scheme.
///
/// Constant time exactly when the cipher and the padding are; the schemes of
/// `tc_block_padding` pad in constant time with respect to the block contents.
/// The buffers are wiped on drop, as for `CbcMac`.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_modes::KeyWithIvRef;
/// use tc_block_padding::Pkcs7Padding;
/// use tc_macs::{Mac, MacInit, PaddedCbcMac};
///
/// let mut mac = PaddedCbcMac::new(AesEngine::new(), Pkcs7Padding);
/// mac.init(&KeyWithIvRef::new(&[0x42; 16], &[0; 16]))?;
/// mac.update(b"attack at dawn")?;
/// let mut tag = vec![0; mac.mac_size()];
/// assert_eq!(mac.do_final(&mut tag)?, 8);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct PaddedCbcMac<C, P> {
    mac: CbcMac<C>,
    padding: P,
}

impl<C: BlockCipher, P> PaddedCbcMac<C, P> {
    /// Wraps `cipher` and `padding` with a tag of half a block, as Bouncy
    /// Castle does. Constant time.
    ///
    /// # Panics
    ///
    /// Panics if the cipher's block size is less than 2 bytes.
    pub fn new(cipher: C, padding: P) -> Self {
        Self {
            mac: CbcMac::new(cipher),
            padding,
        }
    }

    /// Wraps `cipher` and `padding` with a tag of `mac_size` bytes.
    /// Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `mac_size` is between 1 and the cipher's block size.
    pub fn with_mac_size(cipher: C, mac_size: usize, padding: P) -> Self {
        Self {
            mac: CbcMac::with_mac_size(cipher, mac_size),
            padding,
        }
    }
}

impl<C, P> PaddedCbcMac<C, P> {
    /// Returns the padding scheme. Constant time.
    pub fn padding(&self) -> &P {
        &self.padding
    }
}

impl<C: Display, P> Display for PaddedCbcMac<C, P> {
    /// Writes the name of the CBC mode, such as `"AES/CBC"`; as in Bouncy
    /// Castle, the padding is not named. Constant time: no key material is
    /// inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.mac.fmt(f)
    }
}

impl<C, P> Mac for PaddedCbcMac<C, P>
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

impl<C, P, Q> MacInit<Q> for PaddedCbcMac<C, P>
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
