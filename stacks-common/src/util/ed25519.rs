// Copyright (C) 2026 Stacks Open Internet Foundation
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

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

use crate::util::hash::{hex_bytes, to_hex, Sha256Sum};

pub const MESSAGE_SIGNATURE_ENCODED_SIZE: u32 = 64;

pub struct MessageSignature(pub [u8; 64]);
impl_array_newtype!(MessageSignature, u8, 64);
impl_array_hexstring_fmt!(MessageSignature);
impl_byte_array_newtype!(MessageSignature, u8, 64);
impl_byte_array_serde!(MessageSignature);

#[derive(Debug, PartialEq, Eq, Clone, Error)]
pub enum Ed25519Error {
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

/// A Ed25519 public key
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ed25519PublicKey {
    key: VerifyingKey,
}
impl_byte_array_serde!(Ed25519PublicKey);

/// A Ed25519 private key
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ed25519PrivateKey {
    key: SigningKey,
}
impl_byte_array_serde!(Ed25519PrivateKey);

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

    /// Converts from a ed25519_dalek::Signature to our MessageSignature
    pub fn from_ed25519_signature(sig: &Signature) -> MessageSignature {
        let sig_bytes = sig.to_bytes();
        let mut ret_bytes = [0u8; 64];
        ret_bytes.copy_from_slice(&sig_bytes);
        MessageSignature(ret_bytes)
    }

    /// Converts to a ed25519_dalek::Signature
    pub fn to_ed25519_signature(&self) -> Signature {
        Signature::from_bytes(&self.0)
    }
}

impl Ed25519PublicKey {
    /// Generates a new random public key (for testing purposes only).
    #[cfg(any(test, feature = "testing"))]
    pub fn random() -> Ed25519PublicKey {
        Ed25519PublicKey::from_private(&Ed25519PrivateKey::random())
    }

    /// Creates a Ed25519PublicKey from a hex string representation.
    pub fn from_hex(hex_string: &str) -> Result<Ed25519PublicKey, &'static str> {
        let data = hex_bytes(hex_string).map_err(|_e| "Failed to decode hex public key")?;
        Ed25519PublicKey::from_slice(&data[..]).map_err(|_e| "Invalid public key hex string")
    }

    /// Creates a Ed25519PublicKey from a byte slice.
    pub fn from_slice(data: &[u8]) -> Result<Ed25519PublicKey, &'static str> {
        let data32: [u8; 32] = data
            .try_into()
            .map_err(|_| "Invalid public key: length must be 32 bytes")?;

        let verifying_key =
            VerifyingKey::from_bytes(&data32).map_err(|_| "Invalid public key: failed to load")?;

        Ok(Ed25519PublicKey { key: verifying_key })
    }

    /// Creates a Ed25519PublicKey from a Ed25519PrivateKey.
    pub fn from_private(privk: &Ed25519PrivateKey) -> Ed25519PublicKey {
        let verifying_key = privk.key.verifying_key();
        Ed25519PublicKey { key: verifying_key }
    }

    /// Converts the public key to a hex string representation.
    pub fn to_hex(&self) -> String {
        to_hex(&self.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }

    /// Verify a signature (in strict mode) against a message.
    /// Returns Ok(()) if the signature is valid, or an error otherwise.
    pub fn verify(&self, msg: &[u8], sig: &MessageSignature) -> Result<(), Ed25519Error> {
        let ed25519_sig = sig.to_ed25519_signature();

        // Verify the signature
        self.key
            .verify_strict(msg, &ed25519_sig)
            .map_err(|_| Ed25519Error::InvalidSignature)
    }
}

#[cfg(any(test, feature = "testing"))]
impl Default for Ed25519PublicKey {
    fn default() -> Self {
        Self::random()
    }
}

impl Ed25519PrivateKey {
    /// Generates a new random private key.
    #[cfg(feature = "rand")]
    pub fn random() -> Ed25519PrivateKey {
        use rand::RngCore as _;
        let mut rng = rand::thread_rng();
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);

        let signing_key = SigningKey::from_bytes(&sk_bytes);
        Ed25519PrivateKey { key: signing_key }
    }

    /// Creates a Ed25519PrivateKey from seed bytes by repeatedly
    ///  SHA256 hashing the seed bytes until a private key is found.
    ///
    /// If `seed` is a valid private key, it will be returned without hashing.
    pub fn from_seed(seed: &[u8]) -> Ed25519PrivateKey {
        let mut re_hashed_seed = Vec::from(seed);
        loop {
            if let Ok(sk) = Ed25519PrivateKey::from_slice(&re_hashed_seed[..]) {
                return sk;
            } else {
                re_hashed_seed = Sha256Sum::from_data(&re_hashed_seed[..])
                    .as_bytes()
                    .to_vec()
            }
        }
    }

    /// Creates a Ed25519PrivateKey from a hex string representation.
    pub fn from_hex(hex_string: &str) -> Result<Ed25519PrivateKey, &'static str> {
        let data = hex_bytes(hex_string).map_err(|_e| "Failed to decode hex private key")?;
        Ed25519PrivateKey::from_slice(&data[..]).map_err(|_e| "Invalid private key hex string")
    }

    /// Creates a Ed25519PrivateKey from a byte slice.
    pub fn from_slice(data: &[u8]) -> Result<Ed25519PrivateKey, &'static str> {
        if data.len() != 32 {
            return Err("Invalid private key: not 32 bytes");
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&data[0..32]);

        let signing_key = SigningKey::from_bytes(&key_bytes);

        Ok(Ed25519PrivateKey { key: signing_key })
    }

    /// Converts the private key to a hex string representation.
    pub fn to_hex(&self) -> String {
        let bytes = self.key.to_bytes().to_vec();
        to_hex(&bytes)
    }

    /// Converts the private key to a byte vector representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }

    /// Sign a message
    pub fn sign(&self, data: &[u8]) -> Result<MessageSignature, &'static str> {
        let signature: Signature = self
            .key
            .try_sign(data)
            .map_err(|_| "Failed to sign message")?;
        Ok(MessageSignature::from_ed25519_signature(&signature))
    }
}

/// Verify a ed25519 signature against the message
/// The signature must be a 64-byte signature
pub fn ed25519_verify(
    message_arr: &[u8],
    signature_arr: &[u8],
    pubkey_arr: &[u8],
) -> Result<(), Ed25519Error> {
    let sig_bytes: &[u8; 64] = signature_arr
        .try_into()
        .map_err(|_| Ed25519Error::InvalidSignature)?;

    let pk = Ed25519PublicKey::from_slice(pubkey_arr).map_err(|_| Ed25519Error::InvalidKey)?;
    let sig = MessageSignature::from_bytes(sig_bytes).ok_or(Ed25519Error::InvalidSignature)?;
    pk.verify(message_arr, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_seed() {
        let sk = Ed25519PrivateKey::from_seed(&[2; 32]);
        let pubk = Ed25519PublicKey::from_private(&sk);

        // Test that from_seed is deterministic
        let sk2 = Ed25519PrivateKey::from_seed(&[2; 32]);
        let pubk2 = Ed25519PublicKey::from_private(&sk2);

        assert_eq!(sk.to_hex(), sk2.to_hex());
        assert_eq!(pubk.to_hex(), pubk2.to_hex());
    }

    #[test]
    fn test_roundtrip_sign_verify() {
        let privk = Ed25519PrivateKey::random();
        let pubk = Ed25519PublicKey::from_private(&privk);

        let msg = b"hello world";

        let sig = privk.sign(msg).unwrap();
        pubk.verify(msg, &sig).expect("invalid signature");
    }

    #[test]
    fn test_roundtrip_sign_verify_with_zero() {
        let privk = Ed25519PrivateKey::random();
        let pubk = Ed25519PublicKey::from_private(&privk);

        let msg = b"";

        let sig = privk.sign(msg).unwrap();
        pubk.verify(msg, &sig).expect("invalid signature");
    }

    #[test]
    fn test_verify_with_different_key() {
        let privk1 = Ed25519PrivateKey::random();
        let privk2 = Ed25519PrivateKey::random();
        let pubk2 = Ed25519PublicKey::from_private(&privk2);

        let msg = b"hello world";

        let sig = privk1.sign(msg).unwrap();
        let e = pubk2.verify(msg, &sig).expect_err("expected an error");
        assert_eq!(e, Ed25519Error::InvalidSignature);
    }

    #[test]
    fn test_enforces_verify_strict_instead_of_standard_verify() {
        // 1. A structurally valid Ed25519 public key vector representing a point of order 8.
        // Standard `verify` accepts this as a mathematically decipherable curve point.
        // `verify_strict` hits `self.point.is_small_order()` and returns an Error.
        let weak_pubkey_bytes = [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ];

        let pubk = Ed25519PublicKey::from_slice(&weak_pubkey_bytes)
            .expect("Should pass basic deserialization successfully");

        let msg = b"any message";

        // 2. Pair it with a complementary signature layout where R matches the public key
        // point geometry exactly, and S = 0.
        let mut weak_sig_bytes = [0u8; 64];
        weak_sig_bytes[0..32].copy_from_slice(&weak_pubkey_bytes); // Set R = Public Key Point
                                                                   // Bytes 32 to 64 (S) remain 0x00

        let sig = MessageSignature::from_bytes(&weak_sig_bytes).unwrap();

        // 3. Execution Verification Check
        let result = pubk.verify(msg, &sig);

        // CRITICAL SECURITY ASSERTION:
        // If you are using loose `verify`, the inner loop math resolves: R = [0]B - A -> R = -A.
        // Because this is an order-8 element, the assertion holds, and loose verify returns Ok(()).
        // We expect an error path to prove that `verify_strict` intercepted the execution chain!
        assert!(
            result.is_err(),
            "CRITICAL SECURITY VULNERABILITY: Your wrapper code is calling loose `verify` \
         instead of `verify_strict`. An order-8 malleable public key signature was allowed!"
        );
    }
}
