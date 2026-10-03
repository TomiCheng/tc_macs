mod fixed_mac;
#[cfg(feature = "alloc")]
mod mac;
mod shared;

pub use fixed_mac::FixedCbcMac;
pub use fixed_mac::FixedPaddedCbcMac;

#[cfg(feature = "alloc")]
pub use mac::CbcMac;
#[cfg(feature = "alloc")]
pub use mac::PaddedCbcMac;
