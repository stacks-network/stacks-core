#[cfg(not(target_family = "wasm"))]
mod native;

#[cfg(not(target_family = "wasm"))]
pub use self::native::*;

#[cfg(target_family = "wasm")]
mod wasm;

#[cfg(target_family = "wasm")]
pub use self::wasm::*;

pub const MESSAGE_SIGNATURE_ENCODED_SIZE: u32 = 65;

pub struct MessageSignature(pub [u8; 65]);
impl_array_newtype!(MessageSignature, u8, 65);
impl_array_hexstring_fmt!(MessageSignature);
impl_byte_array_newtype!(MessageSignature, u8, 65);
impl_byte_array_serde!(MessageSignature);

pub struct SchnorrSignature(pub [u8; 65]);
impl_array_newtype!(SchnorrSignature, u8, 65);
impl_array_hexstring_fmt!(SchnorrSignature);
impl_byte_array_newtype!(SchnorrSignature, u8, 65);
impl_byte_array_serde!(SchnorrSignature);
pub const SCHNORR_SIGNATURE_ENCODED_SIZE: u32 = 65;

impl Default for SchnorrSignature {
    /// Creates a default Schnorr Signature. Note this is not a valid signature.
    fn default() -> Self {
        Self([0u8; 65])
    }
}
