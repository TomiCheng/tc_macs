mod fixed_mac;
#[cfg(feature = "alloc")]
mod mac;
mod shared;

pub use fixed_mac::FixedCfbMac;
pub use fixed_mac::FixedPaddedCfbMac;

#[cfg(feature = "alloc")]
pub use mac::CfbMac;
#[cfg(feature = "alloc")]
pub use mac::PaddedCfbMac;
