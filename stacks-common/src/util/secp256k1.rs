// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2025 Stacks Open Internet Foundation
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
use std::hash::{Hash, Hasher};

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{
    RecoveryId as K256RecoveryId, Signature as K256Signature, SigningKey as K256SigningKey,
    VerifyingKey as K256VerifyingKey,
};
use k256::elliptic_curve::generic_array::GenericArray;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{EncodedPoint, PublicKey as K256PublicKey, SecretKey as K256SecretKey};
use serde::de::{Deserialize, Error as de_Error};
use serde::Serialize;

use crate::types::{PrivateKey, PublicKey};
use crate::util::hash::{hex_bytes, to_hex, Sha256Sum};

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

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Secp256k1Error {
    InvalidKey,
    InvalidSignature,
    InvalidMessage,
    InvalidRecoveryId,
    SigningFailed,
    RecoveryFailed,
}

impl fmt::Display for Secp256k1Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Secp256k1Error::InvalidKey => write!(f, "Invalid key"),
            Secp256k1Error::InvalidSignature => write!(f, "Invalid signature"),
            Secp256k1Error::InvalidMessage => write!(f, "Invalid message"),
            Secp256k1Error::InvalidRecoveryId => write!(f, "Invalid recovery ID"),
            Secp256k1Error::SigningFailed => write!(f, "Signing failed"),
            Secp256k1Error::RecoveryFailed => write!(f, "Recovery failed"),
        }
    }
}

/// An ECDSA recoverable signature, which includes the recovery ID.
pub struct RecoverableSignature {
    signature: K256Signature,
    recovery_id: K256RecoveryId,
}

impl RecoverableSignature {
    /// Converts a recoverable signature to a non-recoverable one.
    pub fn to_standard(&self) -> SignatureCompat {
        SignatureCompat {
            signature: self.signature,
        }
    }

    /// Serializes the signature in compact format.
    pub fn serialize_compact(&self) -> (K256RecoveryId, [u8; 64]) {
        (self.recovery_id, self.signature.to_bytes().into())
    }
}

/// Compatibility wrapper to provide missing methods.
pub struct SignatureCompat {
    signature: K256Signature,
}

impl SignatureCompat {
    /// Serializes the signature in DER format.
    pub fn serialize_der(&self) -> Vec<u8> {
        self.signature.to_der().as_bytes().to_vec()
    }
}

impl From<(K256Signature, K256RecoveryId)> for RecoverableSignature {
    fn from((signature, recovery_id): (K256Signature, K256RecoveryId)) -> Self {
        RecoverableSignature {
            signature,
            recovery_id,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Secp256k1PublicKey {
    // serde is broken for secp256k1, so do it ourselves
    #[serde(
        serialize_with = "secp256k1_pubkey_serialize",
        deserialize_with = "secp256k1_pubkey_deserialize"
    )]
    key: K256VerifyingKey,
    compressed: bool,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Secp256k1PrivateKey {
    // serde is broken for secp256k1, so do it ourselves
    #[serde(
        serialize_with = "secp256k1_privkey_serialize",
        deserialize_with = "secp256k1_privkey_deserialize"
    )]
    key: K256SigningKey,
    compress_public: bool,
}

impl Hash for Secp256k1PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash based on the compressed public key bytes for consistency
        self.to_bytes_compressed().hash(state);
    }
}

impl MessageSignature {
    /// Creates an "empty" signature (all zeros). Note this is not a valid signature.
    pub fn empty() -> MessageSignature {
        // NOTE: this cannot be a valid signature
        MessageSignature([0u8; 65])
    }

    /// Generates place-holder data (for testing purposes only).
    #[cfg(any(test, feature = "testing"))]
    pub fn from_raw(sig: &[u8]) -> MessageSignature {
        let mut buf = [0u8; 65];
        if sig.len() < 65 {
            buf[..sig.len()].copy_from_slice(sig);
        } else {
            buf.copy_from_slice(&sig[..65]);
        }
        MessageSignature(buf)
    }

    /// Converts from a secp256k1::ecdsa::RecoverableSignature to our MessageSignature.
    pub fn from_secp256k1_recoverable(sig: &RecoverableSignature) -> MessageSignature {
        let (recid, bytes) = sig.serialize_compact();
        let mut ret_bytes = [0u8; 65];
        let recovery_id_byte = recid.to_byte();
        ret_bytes[0] = recovery_id_byte;
        ret_bytes[1..=64].copy_from_slice(&bytes[..64]);
        MessageSignature(ret_bytes)
    }

    /// Converts to a secp256k1::ecdsa::RecoverableSignature.
    pub fn to_secp256k1_recoverable(&self) -> Option<RecoverableSignature> {
        let recovery_id = K256RecoveryId::from_byte(self.0[0])?;
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..64].copy_from_slice(&self.0[1..=64]);
        let signature = K256Signature::from_slice(&sig_bytes).ok()?;
        Some(RecoverableSignature {
            signature,
            recovery_id,
        })
    }

    /// Converts from VRS to RSV.
    pub fn to_rsv(&self) -> Vec<u8> {
        [&self.0[1..], &self.0[0..1]].concat()
    }
}

impl Secp256k1PublicKey {
    /// Generates a new random public key (for testing purposes only).
    #[cfg(any(test, feature = "testing"))]
    pub fn new() -> Secp256k1PublicKey {
        Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::random())
    }

    /// Creates a Secp256k1PublicKey from a hex string representation.
    pub fn from_hex(hex_string: &str) -> Result<Secp256k1PublicKey, &'static str> {
        let data = hex_bytes(hex_string).map_err(|_e| "Failed to decode hex public key")?;
        Secp256k1PublicKey::from_slice(&data[..]).map_err(|_e| "Invalid public key hex string")
    }

    /// Creates a Secp256k1PublicKey from a byte slice.
    pub fn from_slice(data: &[u8]) -> Result<Secp256k1PublicKey, &'static str> {
        let encoded_point = EncodedPoint::from_bytes(data)
            .map_err(|_| "Invalid public key: failed to parse encoded point")?;

        let public_key =
            Option::<K256PublicKey>::from(K256PublicKey::from_encoded_point(&encoded_point))
                .ok_or("Invalid public key: failed to decode point")?;

        let verifying_key = K256VerifyingKey::from(public_key);

        Ok(Secp256k1PublicKey {
            key: verifying_key,
            compressed: data.len() == 33, // 33 bytes = compressed, 65 bytes = uncompressed
        })
    }

    /// Creates a Secp256k1PublicKey from a Secp256k1PrivateKey.
    pub fn from_private(privk: &Secp256k1PrivateKey) -> Secp256k1PublicKey {
        let verifying_key = privk.key.verifying_key();
        Secp256k1PublicKey {
            key: *verifying_key,
            compressed: privk.compress_public,
        }
    }

    /// Converts the public key to a hex string representation.
    pub fn to_hex(&self) -> String {
        to_hex(&self.to_bytes())
    }

    /// Converts the public key to a compressed byte representation.
    pub fn to_bytes_compressed(&self) -> Vec<u8> {
        let public_key = K256PublicKey::from(&self.key);
        let encoded_point = public_key.to_encoded_point(true); // true = compressed
        encoded_point.as_bytes().to_vec()
    }

    /// Returns whether the public key is in compressed format.
    pub fn compressed(&self) -> bool {
        self.compressed
    }

    /// Sets whether the public key should be in compressed format when serialized.
    pub fn set_compressed(&mut self, value: bool) {
        self.compressed = value;
    }

    /// Recovers message and signature to public key (will be compressed).
    pub fn recover_to_pubkey(
        _msg: &[u8],
        _sig: &MessageSignature,
    ) -> Result<Secp256k1PublicKey, &'static str> {
        if _msg.len() != 32 {
            return Err("Invalid message: failed to decode data hash: must be a 32-byte hash");
        }

        let recoverable_sig = _sig
            .to_secp256k1_recoverable()
            .ok_or("Invalid signature: failed to decode recoverable signature")?;

        let recovered_key = K256VerifyingKey::recover_from_prehash(
            _msg,
            &recoverable_sig.signature,
            recoverable_sig.recovery_id,
        )
        .map_err(|_| "Invalid signature: failed to recover public key")?;

        Ok(Secp256k1PublicKey {
            key: recovered_key,
            compressed: true,
        })
    }

    // For benchmarking
    #[cfg(test)]
    pub fn recover_benchmark(
        msg: &[u8; 32],
        sig: &RecoverableSignature,
    ) -> Result<K256VerifyingKey, &'static str> {
        K256VerifyingKey::recover_from_prehash(msg, &sig.signature, sig.recovery_id)
            .map_err(|_| "Invalid signature: failed to recover public key")
    }
}

#[cfg(any(test, feature = "testing"))]
impl Default for Secp256k1PublicKey {
    fn default() -> Self {
        Self::new()
    }
}

impl PublicKey for Secp256k1PublicKey {
    /// Converts the public key to a byte representation.
    fn to_bytes(&self) -> Vec<u8> {
        let public_key = K256PublicKey::from(&self.key);
        let encoded_point = public_key.to_encoded_point(self.compressed);
        encoded_point.as_bytes().to_vec()
    }

    /// Verifies a signature against the public key.
    fn verify(&self, data_hash: &[u8], sig: &MessageSignature) -> Result<bool, &'static str> {
        if data_hash.len() != 32 {
            return Err("Invalid message: failed to decode data hash: must be a 32-byte hash");
        }

        let recoverable_sig = sig
            .to_secp256k1_recoverable()
            .ok_or("Invalid signature: failed to decode recoverable signature")?;

        let recovered_pubkey = K256VerifyingKey::recover_from_prehash(
            data_hash,
            &recoverable_sig.signature,
            recoverable_sig.recovery_id,
        )
        .map_err(|_| "Invalid signature: failed to recover public key")?;

        if recovered_pubkey != self.key {
            test_debug!("{:?} != {:?}", &recovered_pubkey, &self.key);
            return Ok(false);
        }

        // Verify the signature is normalized (low-S)
        if recoverable_sig.signature.normalize_s().is_some() {
            return Err("Invalid signature: high-S");
        }

        Ok(true)
    }
}

impl Secp256k1PrivateKey {
    /// Generates a new random private key.
    #[cfg(feature = "rand")]
    pub fn random() -> Secp256k1PrivateKey {
        let secret_key = K256SecretKey::random(&mut rand::thread_rng());
        let signing_key = K256SigningKey::from(secret_key);
        Secp256k1PrivateKey {
            key: signing_key,
            compress_public: true,
        }
    }

    /// Creates a new Secp256k1PrivateKey.
    #[cfg(feature = "rand")]
    pub fn new() -> Secp256k1PrivateKey {
        Self::random()
    }

    /// Creates a Secp256k1PrivateKey from seed bytes by repeatedly
    ///  SHA256 hashing the seed bytes until a private key is found.
    ///
    /// If `seed` is a valid private key, it will be returned without hashing.
    /// The returned private key's compress_public flag will be `true`.
    pub fn from_seed(seed: &[u8]) -> Secp256k1PrivateKey {
        let mut re_hashed_seed = Vec::from(seed);
        loop {
            if let Ok(mut sk) = Secp256k1PrivateKey::from_slice(&re_hashed_seed[..]) {
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

    /// Creates a Secp256k1PrivateKey from a hex string representation.
    pub fn from_hex(hex_string: &str) -> Result<Secp256k1PrivateKey, &'static str> {
        let data = hex_bytes(hex_string).map_err(|_e| "Failed to decode hex private key")?;
        Secp256k1PrivateKey::from_slice(&data[..]).map_err(|_e| "Invalid private key hex string")
    }

    /// Creates a Secp256k1PrivateKey from a byte slice.
    pub fn from_slice(data: &[u8]) -> Result<Secp256k1PrivateKey, &'static str> {
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

        let secret_key = K256SecretKey::from_bytes(&GenericArray::from(key_bytes))
            .map_err(|_| "Invalid private key: failed to load")?;
        let signing_key = K256SigningKey::from(secret_key);

        Ok(Secp256k1PrivateKey {
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

    /// Converts the private key to a 32-byte array representation.
    pub fn as_slice(&self) -> [u8; 32] {
        self.key.to_bytes().into()
    }
}

impl Default for Secp256k1PrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateKey for Secp256k1PrivateKey {
    /// Converts the private key to a byte representation.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bits = self.key.to_bytes().to_vec();
        if self.compress_public {
            bits.push(0x01);
        }
        bits
    }

    /// Signs a message hash with the private key, producing a recoverable signature.
    fn sign(&self, data_hash: &[u8]) -> Result<MessageSignature, &'static str> {
        if data_hash.len() != 32 {
            return Err("Invalid message: failed to decode data hash: must be a 32-byte hash");
        }

        let signature: K256Signature = self
            .key
            .sign_prehash(data_hash)
            .map_err(|_| "Signing failed")?;

        // Try each recovery ID to find the correct one
        for recovery_id in 0..4 {
            if let Some(recovery_id) = K256RecoveryId::from_byte(recovery_id) {
                if let Ok(recovered_key) =
                    K256VerifyingKey::recover_from_prehash(data_hash, &signature, recovery_id)
                {
                    if recovered_key == *self.key.verifying_key() {
                        let recoverable_sig = RecoverableSignature {
                            signature,
                            recovery_id,
                        };
                        return Ok(MessageSignature::from_secp256k1_recoverable(
                            &recoverable_sig,
                        ));
                    }
                }
            }
        }

        Err("Failed to determine recovery ID")
    }
}

fn secp256k1_pubkey_serialize<S: serde::Serializer>(
    pubk: &K256VerifyingKey,
    s: S,
) -> Result<S::Ok, S::Error> {
    let public_key = K256PublicKey::from(pubk);
    let encoded_point = public_key.to_encoded_point(true); // always serialize as compressed
    let key_hex = to_hex(encoded_point.as_bytes());
    s.serialize_str(key_hex.as_str())
}

fn secp256k1_pubkey_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<K256VerifyingKey, D::Error> {
    let key_hex = String::deserialize(d)?;
    let key_bytes = hex_bytes(&key_hex).map_err(de_Error::custom)?;

    let encoded_point = EncodedPoint::from_bytes(&key_bytes).map_err(de_Error::custom)?;
    let public_key =
        Option::<K256PublicKey>::from(K256PublicKey::from_encoded_point(&encoded_point))
            .ok_or_else(|| de_Error::custom("Invalid public key"))?;
    Ok(K256VerifyingKey::from(public_key))
}

fn secp256k1_privkey_serialize<S: serde::Serializer>(
    privk: &K256SigningKey,
    s: S,
) -> Result<S::Ok, S::Error> {
    let key_hex = to_hex(privk.to_bytes().as_slice());
    s.serialize_str(key_hex.as_str())
}

fn secp256k1_privkey_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<K256SigningKey, D::Error> {
    let key_hex = String::deserialize(d)?;
    let key_bytes = hex_bytes(&key_hex).map_err(de_Error::custom)?;

    if key_bytes.len() != 32 {
        return Err(de_Error::custom("Private key must be 32 bytes"));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);

    let secret_key =
        K256SecretKey::from_bytes(&GenericArray::from(key_array)).map_err(de_Error::custom)?;

    Ok(K256SigningKey::from(secret_key))
}

/// Recovers a public key from a message hash and a recoverable signature.
/// The returned public key is in compressed format (33 bytes).
pub fn secp256k1_recover(
    message_arr: &[u8],
    serialized_signature_arr: &[u8],
) -> Result<[u8; 33], Secp256k1Error> {
    if message_arr.len() != 32 {
        return Err(Secp256k1Error::InvalidMessage);
    }

    if serialized_signature_arr.len() < 65 {
        return Err(Secp256k1Error::InvalidSignature);
    }

    let recovery_id = K256RecoveryId::from_byte(serialized_signature_arr[64])
        .ok_or(Secp256k1Error::InvalidRecoveryId)?;

    let signature = K256Signature::from_slice(&serialized_signature_arr[..64])
        .map_err(|_| Secp256k1Error::InvalidSignature)?;

    let recovered_pub =
        K256VerifyingKey::recover_from_prehash(message_arr, &signature, recovery_id)
            .map_err(|_| Secp256k1Error::RecoveryFailed)?;

    let public_key = K256PublicKey::from(&recovered_pub);
    let encoded_point = public_key.to_encoded_point(true); // compressed
    let mut result = [0u8; 33];
    result.copy_from_slice(encoded_point.as_bytes());

    Ok(result)
}

/// Verifies a message hash against a signature and a public key.
pub fn secp256k1_verify(
    message_arr: &[u8],
    serialized_signature_arr: &[u8],
    pubkey_arr: &[u8],
) -> Result<(), Secp256k1Error> {
    if message_arr.len() != 32 {
        return Err(Secp256k1Error::InvalidMessage);
    }

    if serialized_signature_arr.len() < 64 {
        return Err(Secp256k1Error::InvalidSignature);
    }

    let encoded_point =
        EncodedPoint::from_bytes(pubkey_arr).map_err(|_| Secp256k1Error::InvalidKey)?;

    let public_key =
        Option::<K256PublicKey>::from(K256PublicKey::from_encoded_point(&encoded_point))
            .ok_or(Secp256k1Error::InvalidKey)?;
    let verifying_key = K256VerifyingKey::from(public_key);

    let signature = K256Signature::from_slice(&serialized_signature_arr[..64])
        .map_err(|_| Secp256k1Error::InvalidSignature)?;

    verifying_key
        .verify_prehash(message_arr, &signature)
        .map_err(|_| Secp256k1Error::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_serialize_compressed() {
        let mut t1 = Secp256k1PrivateKey::random();
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

        assert!(Secp256k1PrivateKey::from_hex(&h_comp)
            .unwrap()
            .compress_public());
        assert!(!Secp256k1PrivateKey::from_hex(&h_uncomp)
            .unwrap()
            .compress_public());

        assert_eq!(Secp256k1PrivateKey::from_hex(&h_uncomp), Ok(t1.clone()));

        t1.set_compress_public(true);

        assert_eq!(Secp256k1PrivateKey::from_hex(&h_comp), Ok(t1));
    }

    #[test]
    fn test_from_seed() {
        let sk = Secp256k1PrivateKey::from_seed(&[2; 32]);
        let pubk = Secp256k1PublicKey::from_private(&sk);

        // Test that from_seed is deterministic
        let sk2 = Secp256k1PrivateKey::from_seed(&[2; 32]);
        let pubk2 = Secp256k1PublicKey::from_private(&sk2);

        assert_eq!(sk.to_hex(), sk2.to_hex());
        assert_eq!(pubk.to_hex(), pubk2.to_hex());
    }

    #[test]
    fn test_roundtrip_sign_verify() {
        let privk = Secp256k1PrivateKey::random();
        let pubk = Secp256k1PublicKey::from_private(&privk);

        let msg = b"hello world";
        let msg_hash = Sha256Sum::from_data(msg).as_bytes().to_vec();

        let sig = privk.sign(&msg_hash).unwrap();
        let valid = pubk.verify(&msg_hash, &sig).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_verify_with_different_key() {
        let privk1 = Secp256k1PrivateKey::random();
        let privk2 = Secp256k1PrivateKey::random();
        let pubk2 = Secp256k1PublicKey::from_private(&privk2);

        let msg = b"hello world";
        let msg_hash = Sha256Sum::from_data(msg).as_bytes().to_vec();

        let sig = privk1.sign(&msg_hash).unwrap();
        let valid = pubk2.verify(&msg_hash, &sig).unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_public_key_compression() {
        let privk = Secp256k1PrivateKey::random();
        let mut pubk = Secp256k1PublicKey::from_private(&privk);

        pubk.set_compressed(true);
        let compressed_bytes = pubk.to_bytes();
        assert_eq!(compressed_bytes.len(), 33);

        pubk.set_compressed(false);
        let uncompressed_bytes = pubk.to_bytes();
        assert_eq!(uncompressed_bytes.len(), 65);

        // Both should parse back to the same key
        let pubk_from_compressed = Secp256k1PublicKey::from_slice(&compressed_bytes).unwrap();
        let pubk_from_uncompressed = Secp256k1PublicKey::from_slice(&uncompressed_bytes).unwrap();

        assert_eq!(pubk_from_compressed.key, pubk_from_uncompressed.key);
    }

    #[test]
    fn test_recovery() {
        let privk = Secp256k1PrivateKey::random();
        let pubk = Secp256k1PublicKey::from_private(&privk);

        let msg = b"hello world";
        let msg_hash = Sha256Sum::from_data(msg).as_bytes().to_vec();

        let sig = privk.sign(&msg_hash).unwrap();
        let recovered_pubk = Secp256k1PublicKey::recover_to_pubkey(&msg_hash, &sig).unwrap();

        // Both should have the same compressed public key bytes
        assert_eq!(
            pubk.to_bytes_compressed(),
            recovered_pubk.to_bytes_compressed()
        );
    }

    #[test]
    fn test_high_s_signature() {
        let privk = Secp256k1PrivateKey::random();
        let pubk = Secp256k1PublicKey::from_private(&privk);

        let msg = b"stacks secp256k1 high-s test____";
        let msg_hash = Sha256Sum::from_data(msg).as_bytes().to_vec();

        // Sign the message
        let sig = privk.sign(&msg_hash).unwrap();
        let pubkey_bytes = pubk.to_bytes();

        // Get the underlying Signature to work with r,s components
        let recoverable_sig = sig.to_secp256k1_recoverable().unwrap();

        // Always get the low-s version first
        let low_sig = if let Some(normalized) = recoverable_sig.signature.normalize_s() {
            normalized // Original was high-s, use the normalized (low-s) version
        } else {
            recoverable_sig.signature // Original was already low-s
        };

        // Now create high-s version from the low-s signature
        let (r, s) = (low_sig.r(), low_sig.s());
        let high_sig = {
            // Make high-s by negating s (s' = -s mod n)
            let s_hi = -(*s);
            K256Signature::from_scalars(*r, s_hi).expect("valid (r, -s)")
        };

        let low_bytes = low_sig.to_bytes();
        let high_bytes = high_sig.to_bytes();

        // Verify our assumptions about which is which
        let low_is_low_s = low_sig.normalize_s().is_none();
        let high_is_high_s = high_sig.normalize_s().is_some();

        assert!(low_is_low_s, "Low signature should be low-s");
        assert!(high_is_high_s, "High signature should be high-s");

        // Low-s signature should pass verification
        let low_result = secp256k1_verify(&msg_hash, &low_bytes, &pubkey_bytes);
        assert!(
            low_result.is_ok(),
            "Low-s signature should pass verification"
        );

        // High-s signature should fail verification
        let high_result = secp256k1_verify(&msg_hash, &high_bytes, &pubkey_bytes);
        assert!(
            high_result.is_err(),
            "High-s signature should fail verification"
        );

        // Test normalization: high-s should pass when normalized to low-s
        if let Some(normalized_sig) = high_sig.normalize_s() {
            let normalized_bytes = normalized_sig.to_bytes();
            let normalized_result = secp256k1_verify(&msg_hash, &normalized_bytes, &pubkey_bytes);
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
