#[cfg(not(feature = "wasm"))]
mod secp256k1;

use wsts::common::Signature as WSTSSignature;
use wsts::curve::point::{Compressed, Point};
use wsts::curve::scalar::Scalar;

#[cfg(not(feature = "wasm"))]
pub use self::secp256k1::*;

#[cfg(feature = "wasm")]
mod libsecp256k1;

#[cfg(feature = "wasm")]
pub use self::libsecp256k1::*;

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

impl SchnorrSignature {
    /// Attempt to convert a Schnorr signature to a WSTS Signature
    pub fn to_wsts_signature(&self) -> Option<WSTSSignature> {
        // TODO: update wsts to add a TryFrom for a [u8; 65] and a slice to a Signature
        let point_bytes: [u8; 33] = self.0[..33].try_into().ok()?;
        let scalar_bytes: [u8; 32] = self.0[33..].try_into().ok()?;
        let point = Point::try_from(&Compressed::from(point_bytes)).ok()?;
        let scalar = Scalar::from(scalar_bytes);
        Some(WSTSSignature {
            R: point,
            z: scalar,
        })
    }
}

/// Convert a WSTS Signature to a SchnorrSignature
impl From<&WSTSSignature> for SchnorrSignature {
    fn from(signature: &WSTSSignature) -> Self {
        let mut buf = [0u8; 65];
        buf[..33].copy_from_slice(&signature.R.compress().data);
        buf[33..].copy_from_slice(&signature.z.to_bytes());
        SchnorrSignature(buf)
    }
}
