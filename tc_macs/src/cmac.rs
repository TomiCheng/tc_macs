mod fixed_mac;
#[cfg(feature = "alloc")]
mod mac;
mod shared;

pub use fixed_mac::FixedCmac;

#[cfg(feature = "alloc")]
pub use mac::Cmac;
