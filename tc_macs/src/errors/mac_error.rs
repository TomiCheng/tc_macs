//! MAC processing error type.

use core::convert::Infallible;
use core::error::Error;
use core::fmt;

/// A failure while processing or finalizing a message authentication code.
///
/// `E` is the error of the underlying primitive; a MAC that wraps none keeps
/// the default `Infallible`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacError<E = Infallible> {
    /// The MAC has not been initialized, or its `do_final` used up the key or
    /// nonce that `init` supplied.
    NotInitialised,
    /// The output buffer is shorter than required.
    OutputTooShort {
        /// The tag length, in bytes.
        required: usize,
        /// The length of the output buffer that was supplied, in bytes.
        available: usize,
    },
    /// A private primitive failed despite validated internal invariants.
    InternalFailure,
    /// The padding scheme could not pad the final block.
    PaddingFailed,
    /// The algorithm's input-length limit would be exceeded.
    InputTooLong,
    /// The underlying primitive failed; [`source`](Error::source) returns its
    /// error.
    Cipher(E),
}

impl<E> fmt::Display for MacError<E> {
    /// Writes a description of this layer only; the primitive's error is
    /// reachable through `source`. Constant time: the fields hold only public
    /// lengths.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("MAC not initialised"),
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Self::InternalFailure => f.write_str("internal MAC primitive failure"),
            Self::PaddingFailed => f.write_str("MAC padding could not be added"),
            Self::InputTooLong => f.write_str("MAC input exceeds the algorithm's length limit"),
            Self::Cipher(_) => f.write_str("MAC primitive failed"),
        }
    }
}

impl<E: Error + 'static> Error for MacError<E> {
    /// Returns the primitive's error for `Cipher`, and `None` otherwise.
    /// Constant time.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Cipher(error) => Some(error),
            _ => None,
        }
    }
}
