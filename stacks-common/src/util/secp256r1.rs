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

use std::fmt;

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use serde::de::{Deserialize, Error as de_Error};
use serde::Serialize;

use crate::util::hash::{hex_bytes, to_hex, Sha256Sum};

pub const MESSAGE_SIGNATURE_ENCODED_SIZE: u32 = 64;

pub struct MessageSignature(pub [u8; 64]);
impl_array_newtype!(MessageSignature, u8, 64);
impl_array_hexstring_fmt!(MessageSignature);
impl_byte_array_newtype!(MessageSignature, u8, 64);
impl_byte_array_serde!(MessageSignature);

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Secp256r1Error {
    InvalidKey,
    InvalidSignature,
    InvalidMessage,
    InvalidRecoveryId,
    SigningFailed,
    RecoveryFailed,
}

impl fmt::Display for Secp256r1Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Secp256r1Error::InvalidKey => write!(f, "Invalid key"),
            Secp256r1Error::InvalidSignature => write!(f, "Invalid signature"),
            Secp256r1Error::InvalidMessage => write!(f, "Invalid message"),
            Secp256r1Error::InvalidRecoveryId => write!(f, "Invalid recovery ID"),
            Secp256r1Error::SigningFailed => write!(f, "Signing failed"),
            Secp256r1Error::RecoveryFailed => write!(f, "Recovery failed"),
        }
    }
}

/// A Secp256r1 public key
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Secp256r1PublicKey {
    #[serde(
        serialize_with = "secp256r1_pubkey_serialize",
        deserialize_with = "secp256r1_pubkey_deserialize"
    )]
    key: P256VerifyingKey,
    compressed: bool,
}

/// A Secp256r1 private key
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Secp256r1PrivateKey {
    #[serde(
        serialize_with = "secp256r1_privkey_serialize",
        deserialize_with = "secp256r1_privkey_deserialize"
    )]
    key: P256SigningKey,
    compress_public: bool,
}

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
    pub fn new() -> Secp256r1PublicKey {
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
    pub fn verify_digest(
        &self,
        msg_hash: &[u8],
        sig: &MessageSignature,
    ) -> Result<bool, &'static str> {
        if msg_hash.len() != 32 {
            return Err("Invalid message: must be a 32-byte hash");
        }

        let p256_sig = sig
            .to_p256_signature()
            .map_err(|_| "Invalid signature: failed to decode signature")?;

        // Verify the signature
        match self.key.verify(msg_hash, &p256_sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Default for Secp256r1PublicKey {
    fn default() -> Self {
        Self::new()
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
                // set this to true: LocalPeer will be doing this anyways,
                //  and that's currently the only way this method is used
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

fn secp256r1_pubkey_serialize<S: serde::Serializer>(
    pubk: &P256VerifyingKey,
    s: S,
) -> Result<S::Ok, S::Error> {
    let public_key = P256PublicKey::from(pubk);
    let encoded_point = public_key.to_encoded_point(true); // always serialize as compressed
    let key_hex = to_hex(encoded_point.as_bytes());
    s.serialize_str(key_hex.as_str())
}

fn secp256r1_pubkey_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<P256VerifyingKey, D::Error> {
    let key_hex = String::deserialize(d)?;
    let key_bytes = hex_bytes(&key_hex).map_err(de_Error::custom)?;

    let encoded_point = EncodedPoint::from_bytes(&key_bytes).map_err(de_Error::custom)?;
    let public_key =
        Option::<P256PublicKey>::from(P256PublicKey::from_encoded_point(&encoded_point))
            .ok_or_else(|| de_Error::custom("Invalid public key"))?;
    Ok(P256VerifyingKey::from(public_key))
}

fn secp256r1_privkey_serialize<S: serde::Serializer>(
    privk: &P256SigningKey,
    s: S,
) -> Result<S::Ok, S::Error> {
    let key_hex = to_hex(privk.to_bytes().as_slice());
    s.serialize_str(key_hex.as_str())
}

fn secp256r1_privkey_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<P256SigningKey, D::Error> {
    let key_hex = String::deserialize(d)?;
    let key_bytes = hex_bytes(&key_hex).map_err(de_Error::custom)?;

    if key_bytes.len() != 32 {
        return Err(de_Error::custom("Private key must be 32 bytes"));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);

    let secret_key =
        P256SecretKey::from_bytes(&GenericArray::from(key_array)).map_err(de_Error::custom)?;

    Ok(P256SigningKey::from(secret_key))
}

/// Verify a secp256r1 signature.
/// The message must be a 32-byte hash.
/// The signature must be a 64-byte compact signature
pub fn secp256r1_verify(
    message_arr: &[u8],
    signature_arr: &[u8],
    pubkey_arr: &[u8],
) -> Result<(), Secp256r1Error> {
    if message_arr.len() != 32 {
        return Err(Secp256r1Error::InvalidMessage);
    }

    if signature_arr.len() != 64 {
        return Err(Secp256r1Error::InvalidSignature);
    }

    let encoded_point =
        EncodedPoint::from_bytes(pubkey_arr).map_err(|_| Secp256r1Error::InvalidKey)?;

    let public_key =
        Option::<P256PublicKey>::from(P256PublicKey::from_encoded_point(&encoded_point))
            .ok_or(Secp256r1Error::InvalidKey)?;
    let verifying_key = P256VerifyingKey::from(public_key);

    let signature =
        P256Signature::from_slice(signature_arr).map_err(|_| Secp256r1Error::InvalidSignature)?;

    verifying_key
        .verify(message_arr, &signature)
        .map_err(|_| Secp256r1Error::InvalidSignature)
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
        let valid = pubk.verify_digest(&msg_hash, &sig).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_verify_with_different_key() {
        let privk1 = Secp256r1PrivateKey::random();
        let privk2 = Secp256r1PrivateKey::random();
        let pubk2 = Secp256r1PublicKey::from_private(&privk2);

        let msg = b"hello world";
        let msg_hash = Sha256Sum::from_data(msg).as_bytes().to_vec();

        let sig = privk1.sign(&msg_hash).unwrap();
        let valid = pubk2.verify_digest(&msg_hash, &sig).unwrap();

        assert!(!valid);
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
}
