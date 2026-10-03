//! CFB-MAC without an allocator.

use core::fmt::{self, Display, Formatter};

use tc_block_cipher::{BlockCipher, BlockCipherInit};
use tc_block_modes::IvParams;
use tc_block_padding::BlockCipherPadding;

use super::shared::CfbMacCore;
use crate::{InitError, Mac, MacError, MacInit};

/// CFB-MAC over the block cipher `C` with blocks of `N` bytes, keeping its
/// buffers inline for builds without an allocator; Bouncy Castle's
/// `CfbBlockCipherMac` without padding.
///
/// Available with the `cfb-mac` feature.
///
/// The message is encrypted in CFB mode with segments of the feedback size,
/// one byte unless sized otherwise, and the tag is the first
/// [`mac_size`](Mac::mac_size) bytes of the encryption of the final shift
/// register, half a block unless sized otherwise. A partial final segment is
/// filled with zeros. `init` takes a key and an IV of one block through
/// `tc_block_modes::IvParams`. After `do_final` the MAC starts the next message
/// under the same key and IV.
///
/// Like CBC-MAC, CFB-MAC is secure only for messages of one fixed length. Use
/// `FixedCmac` where lengths vary.
///
/// Constant time exactly when the cipher is: CFB adds only XORs and copies,
/// and only lengths decide the work. The IV, the shift register, the keystream
/// and the buffered segment are wiped on drop, and the cipher wipes its own key
/// schedule when its type does.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_modes::KeyWithIvRef;
/// use tc_macs::{FixedCfbMac, Mac, MacInit};
///
/// let mut mac = FixedCfbMac::<_, 16>::new(AesEngine::new());
/// mac.init(&KeyWithIvRef::new(&[0x42; 16], &[0x24; 16]))?;
/// mac.update(b"attack at dawn")?;
/// let mut tag = [0; 8];
/// assert_eq!(mac.do_final(&mut tag)?, 8);
/// assert_eq!(mac.to_string(), "AES/CFB8");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedCfbMac<C, const N: usize> {
    core: CfbMacCore<C, [u8; N]>,
}

impl<C, const N: usize> FixedCfbMac<C, N> {
    /// Wraps `cipher` with 8-bit feedback and a tag of half a block, as Bouncy
    /// Castle does. Constant time.
    ///
    /// # Panics
    ///
    /// Panics if `N` is less than 2.
    pub fn new(cipher: C) -> Self {
        Self::with_sizes(cipher, 1, N / 2)
    }

    /// Wraps `cipher` with segments of `feedback_size` bytes and a tag of
    /// `mac_size` bytes. Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `feedback_size` and `mac_size` are both in `1..=N`.
    pub fn with_sizes(cipher: C, feedback_size: usize, mac_size: usize) -> Self {
        Self {
            core: CfbMacCore::new(cipher, [[0; N]; 4], feedback_size, mac_size),
        }
    }
}

impl<C: Display, const N: usize> Display for FixedCfbMac<C, N> {
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

impl<C, const N: usize> Mac for FixedCfbMac<C, N>
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

impl<C, P, const N: usize> MacInit<P> for FixedCfbMac<C, N>
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

/// CFB-MAC over the block cipher `C` with blocks of `N` bytes that pads a
/// partial final segment with `P`, keeping its buffers inline for builds
/// without an allocator; Bouncy Castle's `CfbBlockCipherMac` with padding.
///
/// Available with the `cfb-mac` feature.
///
/// It behaves as [`FixedCfbMac`] but pads a partial final segment instead of
/// filling it with zeros. A full final segment is left as it is, unlike in
/// CBC-MAC but as in Bouncy Castle, so with the default one-byte segments only
/// the empty message is padded.
///
/// Constant time exactly when the cipher and the padding are; the schemes of
/// `tc_block_padding` pad in constant time with respect to the block contents.
/// The buffers are wiped on drop, as for `FixedCfbMac`.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_modes::KeyWithIvRef;
/// use tc_block_padding::Pkcs7Padding;
/// use tc_macs::{FixedPaddedCfbMac, Mac, MacInit};
///
/// let mut mac = FixedPaddedCfbMac::<_, 16, _>::with_sizes(AesEngine::new(), 16, 16, Pkcs7Padding);
/// mac.init(&KeyWithIvRef::new(&[0x42; 16], &[0x24; 16]))?;
/// mac.update(b"attack at dawn")?;
/// let mut tag = [0; 16];
/// assert_eq!(mac.do_final(&mut tag)?, 16);
/// assert_eq!(mac.to_string(), "AES/CFB128");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedPaddedCfbMac<C, const N: usize, P> {
    mac: FixedCfbMac<C, N>,
    padding: P,
}

impl<C, const N: usize, P> FixedPaddedCfbMac<C, N, P> {
    /// Wraps `cipher` and `padding` with 8-bit feedback and a tag of half a
    /// block, as Bouncy Castle does. Constant time.
    ///
    /// # Panics
    ///
    /// Panics if `N` is less than 2.
    pub fn new(cipher: C, padding: P) -> Self {
        Self::with_sizes(cipher, 1, N / 2, padding)
    }

    /// Wraps `cipher` and `padding` with segments of `feedback_size` bytes and
    /// a tag of `mac_size` bytes. Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `feedback_size` and `mac_size` are both in `1..=N`.
    pub fn with_sizes(cipher: C, feedback_size: usize, mac_size: usize, padding: P) -> Self {
        Self {
            mac: FixedCfbMac::with_sizes(cipher, feedback_size, mac_size),
            padding,
        }
    }

    /// Returns the padding scheme. Constant time.
    pub fn padding(&self) -> &P {
        &self.padding
    }
}

impl<C: Display, const N: usize, P> Display for FixedPaddedCfbMac<C, N, P> {
    /// Writes the cipher's name followed by `/CFB` and the feedback size in
    /// bits, such as `"DES/CFB8"`; as in Bouncy Castle, the padding is not
    /// named. Constant time: no key material is inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.mac.fmt(f)
    }
}

impl<C, const N: usize, P> Mac for FixedPaddedCfbMac<C, N, P>
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

impl<C, const N: usize, P, Q> MacInit<Q> for FixedPaddedCfbMac<C, N, P>
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
