mod fixed_mac;
#[cfg(feature = "alloc")]
mod mac;

pub use fixed_mac::FixedHmac;
#[cfg(feature = "alloc")]
pub use mac::Hmac;
