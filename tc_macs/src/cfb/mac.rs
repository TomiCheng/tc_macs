//! CFB-MAC sized at run time.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Display, Formatter};

use tc_block_cipher::{BlockCipher, BlockCipherInit};
use tc_block_modes::IvParams;
use tc_block_padding::BlockCipherPadding;

use super::shared::CfbMacCore;
use crate::{InitError, Mac, MacError, MacInit};

/// CFB-MAC over the block cipher `C`, with buffers sized from its block size at
/// run time; Bouncy Castle's `CfbBlockCipherMac` without padding.
///
/// Available with the `cfb-mac` and `alloc` features.
///
/// It computes the same tags as [`FixedCfbMac`](crate::FixedCfbMac) and shares
/// its limits: CFB-MAC is secure only for messages of one fixed length. Use
/// `Cmac` where lengths vary.
///
/// Constant time exactly when the cipher is. The IV, the shift register, the
/// keystream and the buffered segment are wiped on drop, and the cipher wipes
/// its own key schedule when its type does.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_modes::KeyWithIvRef;
/// use tc_macs::{CfbMac, Mac, MacInit};
///
/// let mut mac = CfbMac::new(AesEngine::new());
/// mac.init(&KeyWithIvRef::new(&[0x42; 16], &[0x24; 16]))?;
/// mac.update(b"attack at dawn")?;
/// let mut tag = vec![0; mac.mac_size()];
/// assert_eq!(mac.do_final(&mut tag)?, 8);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct CfbMac<C> {
    core: CfbMacCore<C, Vec<u8>>,
}

impl<C: BlockCipher> CfbMac<C> {
    /// Wraps `cipher` with 8-bit feedback and a tag of half a block, as Bouncy
    /// Castle does. Constant time.
    ///
    /// # Panics
    ///
    /// Panics if the cipher's block size is less than 2 bytes.
    pub fn new(cipher: C) -> Self {
        let mac_size = cipher.block_size() / 2;
        Self::with_sizes(cipher, 1, mac_size)
    }

    /// Wraps `cipher` with segments of `feedback_size` bytes and a tag of
    /// `mac_size` bytes. Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `feedback_size` and `mac_size` are both between 1 and the
    /// cipher's block size.
    pub fn with_sizes(cipher: C, feedback_size: usize, mac_size: usize) -> Self {
        let block_size = cipher.block_size();
        let buffers = core::array::from_fn(|_| vec![0; block_size]);
        Self {
            core: CfbMacCore::new(cipher, buffers, feedback_size, mac_size),
        }
    }
}

impl<C: Display> Display for CfbMac<C> {
    /// Writes the cipher's name followed by `/CFB` and the feedback size in
    /// bits, such as `"DES/CFB8"`, as Bouncy Castle's `AlgorithmName` does.
    /// Constant time: no key material is inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/CFB{}",
            self.core.cipher(),
            self.core.segment_size() * 8
        )
    }
}

impl<C> Mac for CfbMac<C>
where
    C: BlockCipher,
    C::Error: 'static,
{
    type Error = MacError<C::Error>;

    /// Returns the tag length in bytes. Constant time.
    fn mac_size(&self) -> usize {
        self.core.mac_size()
    }

    /// Encrypts every segment that `input` completes but a final one, which
    /// waits for `do_final`. Constant time exactly when the cipher is.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.core.update(input)
    }

    /// Fills a partial final segment with zeros, encrypts it, writes the tag
    /// and starts the next message under the same key and IV. Constant time
    /// exactly when the cipher is.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.core.do_final(output)
    }

    /// Discards the message and restarts the shift register from the IV.
    /// Constant time.
    fn reset(&mut self) {
        self.core.clear_message();
    }
}

impl<C, P> MacInit<P> for CfbMac<C>
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

/// CFB-MAC over the block cipher `C` that pads a partial final segment with
/// `P`, with buffers sized from its block size at run time; Bouncy Castle's
/// `CfbBlockCipherMac` with padding.
///
/// Available with the `cfb-mac` and `alloc` features.
///
/// It computes the same tags as
/// [`FixedPaddedCfbMac`](crate::FixedPaddedCfbMac): only a partial final
/// segment is padded, so with the default one-byte segments only the empty
/// message is.
///
/// Constant time exactly when the cipher and the padding are; the schemes of
/// `tc_block_padding` pad in constant time with respect to the block contents.
/// The buffers are wiped on drop, as for `CfbMac`.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_modes::KeyWithIvRef;
/// use tc_block_padding::Pkcs7Padding;
/// use tc_macs::{Mac, MacInit, PaddedCfbMac};
///
/// let mut mac = PaddedCfbMac::with_sizes(AesEngine::new(), 16, 16, Pkcs7Padding);
/// mac.init(&KeyWithIvRef::new(&[0x42; 16], &[0x24; 16]))?;
/// mac.update(b"attack at dawn")?;
/// let mut tag = vec![0; mac.mac_size()];
/// assert_eq!(mac.do_final(&mut tag)?, 16);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct PaddedCfbMac<C, P> {
    mac: CfbMac<C>,
    padding: P,
}

impl<C: BlockCipher, P> PaddedCfbMac<C, P> {
    /// Wraps `cipher` and `padding` with 8-bit feedback and a tag of half a
    /// block, as Bouncy Castle does. Constant time.
    ///
    /// # Panics
    ///
    /// Panics if the cipher's block size is less than 2 bytes.
    pub fn new(cipher: C, padding: P) -> Self {
        Self {
            mac: CfbMac::new(cipher),
            padding,
        }
    }

    /// Wraps `cipher` and `padding` with segments of `feedback_size` bytes and
    /// a tag of `mac_size` bytes. Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `feedback_size` and `mac_size` are both between 1 and the
    /// cipher's block size.
    pub fn with_sizes(cipher: C, feedback_size: usize, mac_size: usize, padding: P) -> Self {
        Self {
            mac: CfbMac::with_sizes(cipher, feedback_size, mac_size),
            padding,
        }
    }
}

impl<C, P> PaddedCfbMac<C, P> {
    /// Returns the padding scheme. Constant time.
    pub fn padding(&self) -> &P {
        &self.padding
    }
}

impl<C: Display, P> Display for PaddedCfbMac<C, P> {
    /// Writes the cipher's name followed by `/CFB` and the feedback size in
    /// bits, such as `"DES/CFB8"`; as in Bouncy Castle, the padding is not
    /// named. Constant time: no key material is inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.mac.fmt(f)
    }
}

impl<C, P> Mac for PaddedCfbMac<C, P>
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

    /// Encrypts every segment that `input` completes but a final one, which
    /// waits for `do_final`. Constant time exactly when the cipher is.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.mac.update(input)
    }

    /// Pads a partial final segment, encrypts it, writes the tag and starts
    /// the next message under the same key and IV. A padding failure discards
    /// the message. Constant time exactly when the cipher and the padding are.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.mac.core.do_final_padded(&mut self.padding, output)
    }

    /// Discards the message and restarts the shift register from the IV.
    /// Constant time.
    fn reset(&mut self) {
        self.mac.reset();
    }
}

impl<C, P, Q> MacInit<Q> for PaddedCfbMac<C, P>
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
