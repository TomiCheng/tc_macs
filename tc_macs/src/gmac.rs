//! GMAC: GCM over associated data alone (NIST SP 800-38D), as Bouncy Castle's
//! `GMac`.

use core::fmt::{self, Display, Formatter};

use tc_aead_cipher::{AeadBlockCipher, AeadCipher, AeadError, AeadInitError, GcmBlockCipher};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyParams};
use tc_block_modes::IvParams;

use crate::{InitError, Mac, MacError, MacInit};

/// The tag sizes GCM accepts, 32 to 128 bits as in Bouncy Castle.
const MIN_MAC_SIZE: usize = 4;
const MAX_MAC_SIZE: usize = 16;

/// GMAC (NIST SP 800-38D) over the 128-bit block cipher `C`: GCM that
/// authenticates the message as associated data and encrypts nothing; Bouncy
/// Castle's `GMac`. It needs no allocator.
///
/// Available with the `gmac` feature.
///
/// The tag is 4 to 16 bytes, 16 unless sized otherwise. `init` takes a key and
/// an IV through [`KeyParams`] and [`IvParams`](crate::IvParams), such as
/// [`KeyWithIvRef`](crate::KeyWithIvRef); the IV is GCM's nonce, of any length
/// but zero, and 12 bytes is the length NIST recommends.
///
/// The nonce must never repeat under one key: two tags under the same key and
/// nonce let an attacker forge others. The GCM it wraps refuses at `init` the
/// key and nonce of the previous `init`, but nothing tracks nonces across
/// instances. After `do_final` the MAC stays finalized, reporting
/// `NotInitialised`, until it is initialized with a fresh nonce; `reset` before
/// `do_final` discards the message and keeps the nonce.
///
/// Constant time exactly when the cipher is: GCM's GHASH multiplies with masks
/// in a fixed number of steps, and only lengths decide the work. GCM wipes its
/// state on drop, and the cipher wipes its own key schedule when its type does.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_macs::{Gmac, KeyWithIvRef, Mac, MacInit};
///
/// let mut mac = Gmac::new(AesEngine::new());
/// mac.init(&KeyWithIvRef::new(&[0x42; 16], &[0x24; 12]))?;
/// mac.update(b"attack at dawn")?;
/// let mut tag = [0; 16];
/// assert_eq!(mac.do_final(&mut tag)?, 16);
/// assert_eq!(mac.to_string(), "AES-GMAC");
///
/// // The next message needs a fresh nonce.
/// mac.init(&KeyWithIvRef::new(&[0x42; 16], &[0x25; 12]))?;
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Gmac<C> {
    cipher: GcmBlockCipher<C>,
    mac_size: usize,
}

impl<C> Gmac<C> {
    /// Wraps `cipher` with a tag of 16 bytes, as Bouncy Castle does.
    /// Constant time.
    pub fn new(cipher: C) -> Self {
        Self::with_mac_size(cipher, MAX_MAC_SIZE)
    }

    /// Wraps `cipher` with a tag of `mac_size` bytes. Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `mac_size` is in `4..=16`.
    pub fn with_mac_size(cipher: C, mac_size: usize) -> Self {
        assert!(
            (MIN_MAC_SIZE..=MAX_MAC_SIZE).contains(&mac_size),
            "GMAC size must be between 4 and 16 bytes"
        );
        Self {
            cipher: GcmBlockCipher::new(cipher),
            mac_size,
        }
    }
}

impl<C> Display for Gmac<C>
where
    C: BlockCipher + Display,
    C::Error: 'static,
{
    /// Writes the cipher's name followed by `-GMAC`, such as `"AES-GMAC"`, as
    /// Bouncy Castle's `AlgorithmName` does. Constant time: no key material is
    /// inspected.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}-GMAC", self.cipher.underlying_cipher())
    }
}

impl<C> Mac for Gmac<C>
where
    C: BlockCipher,
    C::Error: 'static,
{
    type Error = MacError<C::Error>;

    /// Returns the tag length in bytes. Constant time.
    fn mac_size(&self) -> usize {
        self.mac_size
    }

    /// Authenticates `input` as GCM's associated data. Constant time exactly
    /// when the cipher is: only its length decides the work.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.cipher.process_aad_bytes(input).map_err(gcm_error)
    }

    /// Writes the tag and finalizes the MAC until the next `init` with a fresh
    /// nonce. Constant time exactly when the cipher is.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        // With no plaintext, the output of encryption is the tag alone.
        self.cipher.do_final(output).map_err(gcm_error)
    }

    /// Discards the message and keeps the nonce, unless `do_final` has used it
    /// up. Constant time.
    fn reset(&mut self) {
        self.cipher.reset();
    }
}

impl<C, P> MacInit<P> for Gmac<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: KeyParams + IvParams + ?Sized,
    <C as BlockCipherInit<P>>::Error: 'static,
{
    type Error = InitError<<C as BlockCipherInit<P>>::Error>;

    /// Keys the cipher and starts a message under the IV as GCM's nonce,
    /// refusing the key and nonce of the previous `init` with `NonceReuse`.
    /// Constant time exactly when the cipher's key setup and block encryption
    /// are: the nonce-reuse check compares in fixed time.
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.cipher
            .init_with_parts(
                CipherDirection::Encrypt,
                params,
                params.iv(),
                &[],
                self.mac_size,
            )
            .map_err(gcm_init_error)
    }
}

fn gcm_error<E>(error: AeadError<E>) -> MacError<E> {
    match error {
        // After do_final GCM needs a fresh nonce, so for a MAC it is not
        // initialized.
        AeadError::NotInitialized | AeadError::AlreadyFinalized => MacError::NotInitialised,
        AeadError::OutputTooShort {
            required,
            available,
        } => MacError::OutputTooShort {
            required,
            available,
        },
        AeadError::AadTooLong { .. } | AeadError::InputTooLong => MacError::InputTooLong,
        AeadError::Cipher(error) => MacError::Cipher(error),
        // Only associated data goes in, so no other error can occur.
        _ => MacError::InternalFailure,
    }
}

fn gcm_init_error<E>(error: AeadInitError<E>) -> InitError<E> {
    match error {
        AeadInitError::InvalidNonceLength { actual } => InitError::InvalidIvLength(actual),
        AeadInitError::InvalidKeyLength { actual } => InitError::InvalidKeyLength(actual),
        AeadInitError::InvalidBlockSize { actual, required } => {
            InitError::UnsupportedBlockSize { actual, required }
        }
        AeadInitError::NonceReuse => InitError::NonceReuse,
        AeadInitError::Cipher(error) => InitError::Cipher(error),
        // The tag size is checked at construction and the initial associated
        // data is empty, so no other error can occur.
        _ => InitError::InternalFailure,
    }
}
