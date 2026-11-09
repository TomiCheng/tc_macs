//! Skein-MAC.

use core::fmt;

use tc_macs::{InitError, Mac, MacError, MacInit};
use tc_skein::{SkeinEngine, SkeinParams};

const MIN_KEY_BYTES: usize = 16;

/// Skein-MAC with a 256-, 512- or 1024-bit state; Bouncy Castle's `SkeinMac`.
///
/// `init` takes the key, and any other Skein parameter, through
/// [`SkeinParams`]; the key must be at least 16 bytes, as Bouncy Castle's
/// Skein requires. After `do_final` the MAC starts the next message under the
/// same parameters.
///
/// Constant time, as Skein is; the lengths of the parameters and the message
/// are public. The Skein state, which holds the keyed chaining value, wipes
/// itself on drop.
#[derive(Clone)]
pub struct SkeinMac {
    engine: SkeinEngine,
    initialized: bool,
}

impl SkeinMac {
    /// The 256-bit state size, in bits.
    pub const SKEIN_256: usize = SkeinEngine::SKEIN_256;
    /// The 512-bit state size, in bits.
    pub const SKEIN_512: usize = SkeinEngine::SKEIN_512;
    /// The 1024-bit state size, in bits.
    pub const SKEIN_1024: usize = SkeinEngine::SKEIN_1024;

    /// Creates an uninitialized MAC with a state of `state_size_bits` and a tag
    /// of `output_size_bits`. Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless the state is 256, 512 or 1024 bits and the tag a whole
    /// number of bytes from 8 bits on, as Bouncy Castle throws.
    pub fn new(state_size_bits: usize, output_size_bits: usize) -> Self {
        Self {
            engine: SkeinEngine::new(state_size_bits, output_size_bits),
            initialized: false,
        }
    }
}

impl fmt::Display for SkeinMac {
    /// Writes the Bouncy Castle name, such as `"Skein-MAC-512-256"`, without
    /// touching the key. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Skein-MAC-{}-{}",
            self.engine.block_size() * 8,
            self.engine.output_size() * 8
        )
    }
}

impl Mac for SkeinMac {
    type Error = MacError;

    /// Returns the tag length in bytes. Constant time.
    fn mac_size(&self) -> usize {
        self.engine.output_size()
    }

    /// Adds `input` to the message. `NotInitialised` before a successful
    /// `init`. Constant time.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        self.engine.update(input);
        Ok(())
    }

    /// Writes the tag and starts the next message under the same parameters.
    /// `NotInitialised` before a successful `init`, and `OutputTooShort` for an
    /// output shorter than the tag, both with the message left in place.
    /// Constant time.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        let required = self.engine.output_size();
        if output.len() < required {
            return Err(MacError::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        Ok(self.engine.do_final(output))
    }

    /// Discards the message and keeps the parameters. Constant time.
    fn reset(&mut self) {
        self.engine.reset();
    }
}

impl<P: SkeinParams + ?Sized> MacInit<P> for SkeinMac {
    type Error = InitError;

    /// Applies `params` and starts a new message. `InvalidKeyLength` for no key
    /// or one shorter than 16 bytes, as Bouncy Castle throws; a failure leaves
    /// the MAC uninitialized. Constant time with respect to the contents of the
    /// parameters; their lengths are public.
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        let key_length = params.key().map_or(0, <[u8]>::len);
        if key_length < MIN_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key_length));
        }
        self.engine
            .init(params)
            .map_err(|_| InitError::InternalFailure)?;
        self.initialized = true;
        Ok(())
    }
}
