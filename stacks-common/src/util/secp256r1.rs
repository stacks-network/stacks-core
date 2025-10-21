// Copyright (C) 2025 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use thiserror::Error;

use crate::util::hash::{hex_bytes, to_hex, Sha256Sum};

pub const MESSAGE_SIGNATURE_ENCODED_SIZE: u32 = 64;

pub struct MessageSignature(pub [u8; 64]);
impl_array_newtype!(MessageSignature, u8, 64);
impl_array_hexstring_fmt!(MessageSignature);
impl_byte_array_newtype!(MessageSignature, u8, 64);
impl_byte_array_serde!(MessageSignature);

#[derive(Debug, PartialEq, Eq, Clone, Error)]
pub enum Secp256r1Error {
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Invalid recovery ID")]
    InvalidRecoveryId,
    #[error("Signing failed")]
    SigningFailed,
}

/// A Secp256r1 public key
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Secp256r1PublicKey {
    key: P256VerifyingKey,
    compressed: bool,
}
impl_byte_array_serde!(Secp256r1PublicKey);

/// A Secp256r1 private key
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Secp256r1PrivateKey {
    key: P256SigningKey,
    compress_public: bool,
}
impl_byte_array_serde!(Secp256r1PrivateKey);

impl MessageSignature {
    /// Creates an "empty" signature (all zeros). Note this is not a valid signature.
    pub fn empty() -> MessageSignature {
        // NOTE: this cannot be a valid signature
        MessageSignature([0u8; 64])
    }

    /// Generates place-holder data (for testing purposes only)
    #[cfg(any(test, feature = "testing"))]
    pub fn from_raw(sig: &[u8]) -> MessageSignature {
        let mut buf = [0u8; 64];
        if sig.len() < 64 {
            buf[..sig.len()].copy_from_slice(sig);
        } else {
            buf.copy_from_slice(&sig[..64]);
        }
        MessageSignature(buf)
    }

    /// Converts from a p256::ecdsa::Signature to our MessageSignature
    pub fn from_p256_signature(sig: &P256Signature) -> MessageSignature {
        let sig_bytes = sig.to_bytes();
        let mut ret_bytes = [0u8; 64];
        ret_bytes.copy_from_slice(&sig_bytes);
        MessageSignature(ret_bytes)
    }

    /// Converts to a p256::ecdsa::Signature
    pub fn to_p256_signature(&self) -> Result<P256Signature, Secp256r1Error> {
        P256Signature::from_slice(&self.0).map_err(|_| Secp256r1Error::InvalidSignature)
    }

    /// Converts to DER format
    pub fn to_der(&self) -> Vec<u8> {
        if let Ok(sig) = self.to_p256_signature() {
            sig.to_der().as_bytes().to_vec()
        } else {
            vec![]
        }
    }
}

impl Secp256r1PublicKey {
    /// Generates a new random public key (for testing purposes only).
    #[cfg(any(test, feature = "testing"))]
    pub fn random() -> Secp256r1PublicKey {
        Secp256r1PublicKey::from_private(&Secp256r1PrivateKey::random())
    }

    /// Creates a Secp256r1PublicKey from a hex string representation.
    pub fn from_hex(hex_string: &str) -> Result<Secp256r1PublicKey, &'static str> {
        let data = hex_bytes(hex_string).map_err(|_e| "Failed to decode hex public key")?;
        Secp256r1PublicKey::from_slice(&data[..]).map_err(|_e| "Invalid public key hex string")
    }

    /// Creates a Secp256r1PublicKey from a byte slice.
    pub fn from_slice(data: &[u8]) -> Result<Secp256r1PublicKey, &'static str> {
        let encoded_point = EncodedPoint::from_bytes(data)
            .map_err(|_| "Invalid public key: failed to parse encoded point")?;

        let public_key =
            Option::<P256PublicKey>::from(P256PublicKey::from_encoded_point(&encoded_point))
                .ok_or("Invalid public key: failed to decode point")?;

        let verifying_key = P256VerifyingKey::from(public_key);

        Ok(Secp256r1PublicKey {
            key: verifying_key,
            compressed: data.len() == 33, // 33 bytes = compressed, 65 bytes = uncompressed
        })
    }

    /// Creates a Secp256r1PublicKey from a Secp256r1PrivateKey.
    pub fn from_private(privk: &Secp256r1PrivateKey) -> Secp256r1PublicKey {
        let verifying_key = privk.key.verifying_key();
        Secp256r1PublicKey {
            key: *verifying_key,
            compressed: privk.compress_public,
        }
    }

    /// Converts the public key to a hex string representation.
    pub fn to_hex(&self) -> String {
        to_hex(&self.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let public_key = P256PublicKey::from(&self.key);
        let encoded_point = public_key.to_encoded_point(self.compressed);
        encoded_point.as_bytes().to_vec()
    }

    /// Converts the public key to a compressed byte representation.
    pub fn to_bytes_compressed(&self) -> Vec<u8> {
        let public_key = P256PublicKey::from(&self.key);
        let encoded_point = public_key.to_encoded_point(true); // true = compressed
        encoded_point.as_bytes().to_vec()
    }

    /// Returns whether the public key should be in compressed format when serialized.
    pub fn compressed(&self) -> bool {
        self.compressed
    }

    /// Sets whether the public key should be in compressed format when serialized.
    pub fn set_compressed(&mut self, value: bool) {
        self.compressed = value;
    }

    /// Verify a signature against a message hash.
    /// Returns Ok(()) if the signature is valid, or an error otherwise.
    pub fn verify_digest(
        &self,
        msg_hash: &[u8],
        sig: &MessageSignature,
    ) -> Result<(), Secp256r1Error> {
        if msg_hash.len() != 32 {
            return Err(Secp256r1Error::InvalidMessage);
        }

        let p256_sig = sig
            .to_p256_signature()
            .map_err(|_| Secp256r1Error::InvalidSignature)?;

        // Verify the signature
        self.key
            .verify(msg_hash, &p256_sig)
            .map_err(|_| Secp256r1Error::InvalidSignature)
    }
}

#[cfg(any(test, feature = "testing"))]
impl Default for Secp256r1PublicKey {
    fn default() -> Self {
        Self::random()
    }
}

impl Secp256r1PrivateKey {
    /// Generates a new random private key.
    #[cfg(feature = "rand")]
    pub fn random() -> Secp256r1PrivateKey {
        let secret_key = P256SecretKey::random(&mut rand::thread_rng());
        let signing_key = P256SigningKey::from(secret_key);
        Secp256r1PrivateKey {
            key: signing_key,
            compress_public: true,
        }
    }

    /// Creates a Secp256r1PrivateKey from seed bytes by repeatedly
    ///  SHA256 hashing the seed bytes until a private key is found.
    ///
    /// If `seed` is a valid private key, it will be returned without hashing.
    /// The returned private key's compress_public flag will be `true`.
    pub fn from_seed(seed: &[u8]) -> Secp256r1PrivateKey {
        let mut re_hashed_seed = Vec::from(seed);
        loop {
            if let Ok(mut sk) = Secp256r1PrivateKey::from_slice(&re_hashed_seed[..]) {
                sk.set_compress_public(true);
                return sk;
            } else {
                re_hashed_seed = Sha256Sum::from_data(&re_hashed_seed[..])
                    .as_bytes()
                    .to_vec()
            }
        }
    }

    /// Creates a Secp256r1PrivateKey from a hex string representation.
    pub fn from_hex(hex_string: &str) -> Result<Secp256r1PrivateKey, &'static str> {
        let data = hex_bytes(hex_string).map_err(|_e| "Failed to decode hex private key")?;
        Secp256r1PrivateKey::from_slice(&data[..]).map_err(|_e| "Invalid private key hex string")
    }

    /// Creates a Secp256r1PrivateKey from a byte slice.
    pub fn from_slice(data: &[u8]) -> Result<Secp256r1PrivateKey, &'static str> {
        if data.len() < 32 {
            return Err("Invalid private key: shorter than 32 bytes");
        }
        if data.len() > 33 {
            return Err("Invalid private key: greater than 33 bytes");
        }
        let compress_public = if data.len() == 33 {
            // compressed byte tag?
            if data[32] != 0x01 {
                return Err("Invalid private key: invalid compressed byte marker");
            }
            true
        } else {
            false
        };

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&data[0..32]);

        let secret_key = P256SecretKey::from_bytes(&GenericArray::from(key_bytes))
            .map_err(|_| "Invalid private key: failed to load")?;
        let signing_key = P256SigningKey::from(secret_key);

        Ok(Secp256r1PrivateKey {
            key: signing_key,
            compress_public,
        })
    }

    /// Returns whether the corresponding public key should be in compressed format when
    /// serialized.
    pub fn compress_public(&self) -> bool {
        self.compress_public
    }

    /// Sets whether the corresponding public key should be in compressed format when serialized.
    pub fn set_compress_public(&mut self, value: bool) {
        self.compress_public = value;
    }

    /// Converts the private key to a hex string representation.
    pub fn to_hex(&self) -> String {
        let mut bytes = self.key.to_bytes().to_vec();
        if self.compress_public {
            bytes.push(1);
        }
        to_hex(&bytes)
    }

    /// Converts the private key to a byte vector representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bits = self.key.to_bytes().to_vec();
        if self.compress_public {
            bits.push(0x01);
        }
        bits
    }

    /// Sign a message hash, returning the signature.
    /// The message must be a 32-byte hash.
    pub fn sign(&self, data_hash: &[u8]) -> Result<MessageSignature, &'static str> {
        if data_hash.len() != 32 {
            return Err("Invalid message: must be a 32-byte hash");
        }

        let signature: P256Signature = self.key.sign(data_hash);
        Ok(MessageSignature::from_p256_signature(&signature))
    }
}

/// Verify a secp256r1 signature.
/// The message must be a 32-byte hash.
/// The signature must be a 64-byte compact signature
pub fn secp256r1_verify(
    message_arr: &[u8],
    signature_arr: &[u8],
    pubkey_arr: &[u8],
) -> Result<(), Secp256r1Error> {
    let msg: &[u8; 32] = message_arr
        .try_into()
        .map_err(|_| Secp256r1Error::InvalidMessage)?;
    let sig_bytes: &[u8; 64] = signature_arr
        .try_into()
        .map_err(|_| Secp256r1Error::InvalidSignature)?;

    let pk = Secp256r1PublicKey::from_slice(pubkey_arr).map_err(|_| Secp256r1Error::InvalidKey)?;
    let sig = MessageSignature::from_bytes(sig_bytes).ok_or(Secp256r1Error::InvalidSignature)?;
    pk.verify_digest(msg, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_serialize_compressed() {
        let mut t1 = Secp256r1PrivateKey::random();
        t1.set_compress_public(true);
        let h_comp = t1.to_hex();
        t1.set_compress_public(false);
        let h_uncomp = t1.to_hex();

        assert!(h_comp != h_uncomp);
        assert_eq!(h_comp.len(), 66);
        assert_eq!(h_uncomp.len(), 64);

        let (uncomp, comp_value) = h_comp.split_at(64);
        assert_eq!(comp_value, "01");
        assert_eq!(uncomp, &h_uncomp);

        assert!(Secp256r1PrivateKey::from_hex(&h_comp)
            .unwrap()
            .compress_public());
        assert!(!Secp256r1PrivateKey::from_hex(&h_uncomp)
            .unwrap()
            .compress_public());

        assert_eq!(Secp256r1PrivateKey::from_hex(&h_uncomp), Ok(t1.clone()));

        t1.set_compress_public(true);

        assert_eq!(Secp256r1PrivateKey::from_hex(&h_comp), Ok(t1));
    }

    #[test]
    fn test_from_seed() {
        let sk = Secp256r1PrivateKey::from_seed(&[2; 32]);
        let pubk = Secp256r1PublicKey::from_private(&sk);

        // Test that from_seed is deterministic
        let sk2 = Secp256r1PrivateKey::from_seed(&[2; 32]);
        let pubk2 = Secp256r1PublicKey::from_private(&sk2);

        assert_eq!(sk.to_hex(), sk2.to_hex());
        assert_eq!(pubk.to_hex(), pubk2.to_hex());
    }

    #[test]
    fn test_roundtrip_sign_verify() {
        let privk = Secp256r1PrivateKey::random();
        let pubk = Secp256r1PublicKey::from_private(&privk);

        let msg = b"hello world";
        let msg_hash = Sha256Sum::from_data(msg).as_bytes().to_vec();

        let sig = privk.sign(&msg_hash).unwrap();
        pubk.verify_digest(&msg_hash, &sig)
            .expect("invalid signature");
    }

    #[test]
    fn test_verify_with_different_key() {
        let privk1 = Secp256r1PrivateKey::random();
        let privk2 = Secp256r1PrivateKey::random();
        let pubk2 = Secp256r1PublicKey::from_private(&privk2);

        let msg = b"hello world";
        let msg_hash = Sha256Sum::from_data(msg).as_bytes().to_vec();

        let sig = privk1.sign(&msg_hash).unwrap();
        let e = pubk2
            .verify_digest(&msg_hash, &sig)
            .expect_err("expected an error");
        assert_eq!(e, Secp256r1Error::InvalidSignature);
    }

    #[test]
    fn test_public_key_compression() {
        let privk = Secp256r1PrivateKey::random();
        let mut pubk = Secp256r1PublicKey::from_private(&privk);

        pubk.set_compressed(true);
        let compressed_bytes = pubk.to_bytes();
        assert_eq!(compressed_bytes.len(), 33);

        pubk.set_compressed(false);
        let uncompressed_bytes = pubk.to_bytes();
        assert_eq!(uncompressed_bytes.len(), 65);

        // Both should parse back to the same key
        let pubk_from_compressed = Secp256r1PublicKey::from_slice(&compressed_bytes).unwrap();
        let pubk_from_uncompressed = Secp256r1PublicKey::from_slice(&uncompressed_bytes).unwrap();

        assert_eq!(pubk_from_compressed.key, pubk_from_uncompressed.key);
    }

    #[test]
    fn test_high_s_signature() {
        use crate::util::hash::Sha256Sum;

        let privk = Secp256r1PrivateKey::random();
        let pubk = Secp256r1PublicKey::from_private(&privk);

        let msg = b"stacks secp256r1 high-s test____";
        let msg_hash = Sha256Sum::from_data(msg).as_bytes().to_vec();

        // Sign the message
        let sig = privk.sign(&msg_hash).unwrap();
        let pubkey_bytes = pubk.to_bytes();

        // Get the underlying P256Signature to work with r,s components
        let original_sig = P256Signature::from_slice(&sig.0).unwrap();

        // Always get the low-s version first
        let low_sig = if let Some(normalized) = original_sig.normalize_s() {
            normalized // Original was high-s, use the normalized (low-s) version
        } else {
            original_sig // Original was already low-s
        };

        // Now create high-s version from the low-s signature
        let (r, s) = (low_sig.r(), low_sig.s());
        let high_sig = {
            // Make high-s by negating s (s' = -s mod n)
            let s_hi = -(*s);
            P256Signature::from_scalars(*r, s_hi).expect("valid (r, -s)")
        };

        let low_bytes = low_sig.to_bytes();
        let high_bytes = high_sig.to_bytes();

        // Verify our assumptions about which is which
        let low_is_low_s = low_sig.normalize_s().is_none();
        let high_is_high_s = high_sig.normalize_s().is_some();

        assert!(low_is_low_s, "Low signature should be low-s");
        assert!(high_is_high_s, "High signature should be high-s");

        // Low-s signature should pass verification
        let low_result = secp256r1_verify(&msg_hash, &low_bytes, &pubkey_bytes);
        assert!(
            low_result.is_ok(),
            "Low-s signature should pass verification"
        );

        // High-s signature should pass verification
        let high_result = secp256r1_verify(&msg_hash, &high_bytes, &pubkey_bytes);
        assert!(
            high_result.is_ok(),
            "High-s signature should pass verification"
        );

        // Test normalization: high-s should pass when normalized to low-s
        if let Some(normalized_sig) = high_sig.normalize_s() {
            let normalized_bytes = normalized_sig.to_bytes();
            let normalized_result = secp256r1_verify(&msg_hash, &normalized_bytes, &pubkey_bytes);
            assert!(
                normalized_result.is_ok(),
                "Normalized (low-s) signature should pass verification"
            );

            // The normalized signature should be the same as our low signature
            assert_eq!(
                normalized_bytes, low_bytes,
                "Normalized signature should match our low signature"
            );
        } else {
            panic!("High-s signature should normalize to low-s");
        }
    }
}
