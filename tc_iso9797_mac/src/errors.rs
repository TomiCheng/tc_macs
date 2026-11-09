//! The errors of `Iso9797Alg3Mac` beyond those of `tc_macs`.

use core::fmt;

/// A tag length that `Iso9797Alg3Mac` cannot produce: it must be a whole number
/// of bytes from 8 to 64 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Iso9797Alg3MacCreateError {
    /// The tag length asked for, in bits.
    InvalidMacSize(usize),
}

impl fmt::Display for Iso9797Alg3MacCreateError {
    /// Describes the failure with the tag length asked for. Constant time.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMacSize(bits) => {
                write!(f, "invalid ISO9797Alg3 MAC size: {bits} bits")
            }
        }
    }
}

impl core::error::Error for Iso9797Alg3MacCreateError {}
