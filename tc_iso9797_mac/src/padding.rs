//! How `Iso9797Alg3Mac` completes the final block.

use tc_block_padding::BlockCipherPadding;

mod sealed {
    pub trait Sealed {}
}

/// How [`Iso9797Alg3Mac`](crate::Iso9797Alg3Mac) completes the final block:
/// [`NoPadding`] or [`WithPadding`]. Sealed; the constructors of the MAC choose
/// one.
pub trait Iso9797Padding: sealed::Sealed {
    /// Whether a full final block is followed by a block of padding alone.
    /// Constant time.
    fn requires_extra_block(&self) -> bool;

    /// Completes `block` from `position`, and returns whether it could.
    /// Constant time exactly when the padding scheme is.
    fn pad(&mut self, block: &mut [u8], position: usize) -> bool;
}

/// Fills a partial final block with zeros and leaves a full one as it is, as
/// Bouncy Castle does without padding. Constant time.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPadding;

impl sealed::Sealed for NoPadding {}

impl Iso9797Padding for NoPadding {
    /// Never: a full final block is the last. Constant time.
    fn requires_extra_block(&self) -> bool {
        false
    }

    /// Fills the rest of the block with zeros. Constant time.
    fn pad(&mut self, block: &mut [u8], position: usize) -> bool {
        block[position..].fill(0);
        true
    }
}

/// Pads the final block with a `tc_block_padding` scheme, and follows a full
/// final block with a block of padding alone, as Bouncy Castle does.
/// Constant time exactly when the scheme is.
#[derive(Clone, Copy, Debug)]
pub struct WithPadding<P>(pub(crate) P);

impl<P> sealed::Sealed for WithPadding<P> {}

impl<P: BlockCipherPadding> Iso9797Padding for WithPadding<P> {
    /// Always: padding needs room in the final block. Constant time.
    fn requires_extra_block(&self) -> bool {
        true
    }

    /// Adds the padding of the scheme. Constant time exactly when the scheme
    /// is; the schemes of `tc_block_padding` pad in constant time with respect to
    /// the block contents.
    fn pad(&mut self, block: &mut [u8], position: usize) -> bool {
        self.0.add_padding(block, position).is_ok()
    }
}
