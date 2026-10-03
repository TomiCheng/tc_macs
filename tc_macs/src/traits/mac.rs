//! Message-authentication-code contracts.

use core::error::Error;

/// A message authentication code that takes a message in pieces of any size
/// and writes its tag in [`do_final`](Self::do_final); the Rust form of
/// Bouncy Castle's `IMac`.
///
/// The contract uses caller-provided output buffers, so it needs neither an
/// allocator nor the standard library. Keying is the separate [`MacInit`]
/// contract; generic code that needs both asks for `M: Mac + MacInit<P>`, and
/// MACs with the same [`Error`](Self::Error) type can be used as
/// `dyn Mac<Error = E>` once keyed.
///
/// The traits carry no algorithm name: each MAC writes it through `Display`,
/// as Bouncy Castle's `AlgorithmName` does, and generic code that needs it adds
/// a `Display` bound.
///
/// Each implementation documents its timing; this contract adds no work of its
/// own.
pub trait Mac {
    /// The error returned while processing or finalizing a message.
    type Error: Error;

    /// Returns the length of the tag that [`do_final`](Self::do_final) writes,
    /// in bytes.
    fn mac_size(&self) -> usize;

    /// Adds `input` to the message.
    ///
    /// Fails before a successful [`MacInit::init`].
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    /// Finishes the message, writes the tag to the front of `output` and
    /// returns its length, [`mac_size`](Self::mac_size).
    ///
    /// `output` must hold at least `mac_size` bytes; a shorter buffer is an
    /// error that leaves the message in place for another call. What follows a
    /// successful call belongs to the MAC: most start the next message under
    /// the same key, while one whose key or nonce must not be used twice stays
    /// unusable until the next `init`.
    ///
    /// To verify a received tag, compare it with this one in constant time,
    /// for example with `tc_constant_time::fixed_time_eq`, not with `==` on
    /// slices, which stops at the first difference.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Discards the message and returns to the state right after `init`,
    /// keeping the key. A MAC that is not initialized, or whose `do_final`
    /// used up its key or nonce, stays unusable.
    fn reset(&mut self);
}

/// Keys a [`Mac`] from parameters of type `P`.
///
/// Keeping `P` as a trait parameter lets one caller-owned parameter value,
/// such as a key with an IV, flow through layers of constructions; the MAC or
/// the cipher it wraps validates it.
pub trait MacInit<P: ?Sized> {
    /// The error returned when `init` rejects the parameters or the underlying
    /// primitive fails to key itself.
    type Error: Error;

    /// Keys the MAC with `params` and starts a new message, discarding any
    /// previous one.
    ///
    /// A failed `init` leaves the MAC uninitialized, so it never goes on under
    /// the previous key.
    fn init(&mut self, params: &P) -> Result<(), Self::Error>;
}
