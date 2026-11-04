// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

//! secp256k1 keys and ECDSA signatures, implemented with the pure-Rust `k256` crate.
//!
//! The behavior of every consensus-relevant function in this module mirrors
//! libsecp256k1 (the C library previously used on native targets): which encodings
//! are accepted, which signatures recover or verify, and where low-S is enforced.

use ecdsa::hazmat::sign_prehashed_rfc6979;
use k256::ecdsa::{RecoveryId as K256RecoveryId, Signature as K256Signature, VerifyingKey};
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::sha2::Sha256;
use k256::{FieldBytes, PublicKey as K256PublicKey, Scalar, Secp256k1, SecretKey as K256SecretKey};
use serde::de::{Deserialize, Error as de_Error};
use serde::Serialize;
use thiserror::Error;

use crate::types::{PrivateKey, PublicKey};
use crate::util::hash::{hex_bytes, to_hex, Sha256Sum};

pub const MESSAGE_SIGNATURE_ENCODED_SIZE: u32 = 65;

/// Size of a SEC1-compressed public key
pub const PUBLIC_KEY_SIZE: usize = 33;

/// Size of a SEC1-uncompressed (or hybrid) public key
const UNCOMPRESSED_PUBLIC_KEY_SIZE: usize = 65;

/// SEC1 public key encoding tags. The hybrid encoding is an uncompressed point whose tag
/// also carries the parity of y.
const TAG_PUBKEY_EVEN: u8 = 0x02;
const TAG_PUBKEY_ODD: u8 = 0x03;
const TAG_PUBKEY_UNCOMPRESSED: u8 = 0x04;
const TAG_PUBKEY_HYBRID_EVEN: u8 = 0x06;
const TAG_PUBKEY_HYBRID_ODD: u8 = 0x07;

/// A recoverable ECDSA signature, stored as VRS: recovery ID, then `r` and `s`.
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

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Invalid recovery ID")]
    InvalidRecoveryId,
    #[error("Invalid input length")]
    InvalidInputLength,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Secp256k1PublicKey {
    // serialized as a compressed hex string
    #[serde(
        serialize_with = "secp256k1_pubkey_serialize",
        deserialize_with = "secp256k1_pubkey_deserialize"
    )]
    key: K256PublicKey,
    compressed: bool,
}

impl std::hash::Hash for Secp256k1PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key.to_compressed_point().hash(state);
        self.compressed.hash(state);
    }
}

/// `k256::SecretKey` zeroizes on drop and redacts itself in `Debug` output, so deriving
/// `Debug` here does not leak key material into logs.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Secp256k1PrivateKey {
    // serialized as a hex string
    #[serde(
        serialize_with = "secp256k1_privkey_serialize",
        deserialize_with = "secp256k1_privkey_deserialize"
    )]
    key: K256SecretKey,
    compress_public: bool,
}

/// Parse a 32-byte big-endian scalar, rejecting values `>= n` but accepting zero, like
/// libsecp256k1's compact signature parser.
fn parse_scalar(bytes: &[u8]) -> Option<Scalar> {
    let repr = FieldBytes::try_from(bytes).ok()?;
    Scalar::from_repr(repr).into_option()
}

/// Parse a 33-byte compressed, 65-byte uncompressed, or 65-byte hybrid SEC1 public key,
/// accepting exactly the encodings libsecp256k1 accepts. `k256` differs in both
/// directions: it rejects hybrid keys (which can appear in Bitcoin scripts), so those are
/// converted to the uncompressed encoding after checking the y-parity tag; and it accepts
/// other SEC1 encodings (e.g. 33-byte "compact" keys tagged `0x05`), which are rejected.
fn parse_pubkey(data: &[u8]) -> Result<K256PublicKey, Error> {
    let Some(&tag) = data.first() else {
        return Err(Error::InvalidPublicKey);
    };
    let hybrid = match (data.len(), tag) {
        (PUBLIC_KEY_SIZE, TAG_PUBKEY_EVEN | TAG_PUBKEY_ODD)
        | (UNCOMPRESSED_PUBLIC_KEY_SIZE, TAG_PUBKEY_UNCOMPRESSED) => false,
        (UNCOMPRESSED_PUBLIC_KEY_SIZE, TAG_PUBKEY_HYBRID_EVEN | TAG_PUBKEY_HYBRID_ODD) => true,
        _ => return Err(Error::InvalidPublicKey),
    };
    if !hybrid {
        return K256PublicKey::from_sec1_bytes(data).map_err(|_| Error::InvalidPublicKey);
    }

    let y_is_odd = data[UNCOMPRESSED_PUBLIC_KEY_SIZE - 1] & 1 == 1;
    if y_is_odd != (data[0] == TAG_PUBKEY_HYBRID_ODD) {
        return Err(Error::InvalidPublicKey);
    }
    let mut uncompressed = [0u8; UNCOMPRESSED_PUBLIC_KEY_SIZE];
    uncompressed.copy_from_slice(data);
    uncompressed[0] = TAG_PUBKEY_UNCOMPRESSED;
    K256PublicKey::from_sec1_bytes(&uncompressed).map_err(|_| Error::InvalidPublicKey)
}

/// Recover the signer's public key. Accepts high-S signatures: low-S is enforced by the
/// callers that need it. Fails if `r` or `s` is zero, or if no point matches `recovery_id`.
fn recover_pubkey(
    message: &[u8],
    r: Scalar,
    s: Scalar,
    recovery_id: K256RecoveryId,
) -> Result<K256PublicKey, Error> {
    if message.len() != 32 {
        return Err(Error::InvalidMessage);
    }
    let signature = K256Signature::from_scalars(r, s).map_err(|_| Error::InvalidSignature)?;
    let verifying_key = VerifyingKey::recover_from_prehash(message, &signature, recovery_id)
        .map_err(|_| Error::InvalidSignature)?;
    Ok(K256PublicKey::from(verifying_key))
}

impl MessageSignature {
    pub fn empty() -> MessageSignature {
        // NOTE: this cannot be a valid signature
        MessageSignature([0u8; 65])
    }

    #[cfg(any(test, feature = "testing"))]
    // test method for generating place-holder data
    pub fn from_raw(sig: &[u8]) -> MessageSignature {
        let mut buf = [0u8; 65];
        if sig.len() < 65 {
            buf[..sig.len()].copy_from_slice(sig);
        } else {
            buf.copy_from_slice(&sig[..65]);
        }
        MessageSignature(buf)
    }

    // Returns the version of this message signature in which s has
    // the opposite sign (mod n). This is only used in tests, to
    // create invalid (or let's call them semi-valid) transaction
    // signatures to test how the code handles them.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_negated_s(&self) -> Self {
        let mut bytes = [0u8; 65];
        bytes.copy_from_slice(self.as_bytes());

        let s = k256::NonZeroScalar::try_from(&bytes[33..]).expect("s must be a nonzero scalar");
        bytes[33..].copy_from_slice(&(-s).to_repr());
        bytes[0] ^= 1; // invert the parity of the recovery id
        Self(bytes)
    }

    /// Convert from VRS to RSV
    pub fn to_rsv(&self) -> Vec<u8> {
        [&self.0[1..], &self.0[0..1]].concat()
    }

    /// Convert from RSV (what Clarity uses) to VRS (what we use here)
    pub fn from_rsv(source: &[u8]) -> Option<Self> {
        if source.len() != 65 {
            return None;
        }
        let swapped: [u8; 65] = *[&source[64..], &source[0..64]]
            .concat()
            .as_array()
            .expect("source has len 65, thus this is guaranteed to work");
        Some(Self(swapped))
    }

    pub fn from_secp256k1_recoverable(
        sig: &K256Signature,
        recid: K256RecoveryId,
    ) -> MessageSignature {
        let mut ret_bytes = [0u8; 65];
        ret_bytes[0] = recid.to_byte();
        ret_bytes[1..].copy_from_slice(&sig.to_bytes());
        MessageSignature(ret_bytes)
    }

    /// Decode into a `k256` signature and recovery ID. Returns `None` if the recovery ID
    /// is not in `0..=3`, or if `r` or `s` is zero or not less than the curve order.
    pub fn to_secp256k1_recoverable(&self) -> Option<(K256Signature, K256RecoveryId)> {
        let recovery_id = K256RecoveryId::from_byte(self.0[0])?;
        let signature = K256Signature::from_slice(&self.0[1..]).ok()?;
        Some((signature, recovery_id))
    }

    /// Whether this signature parses as a recoverable signature: the recovery ID is in
    /// `0..=3` and both `r` and `s` are less than the curve order. Like libsecp256k1's
    /// compact parser, this does *not* reject zero `r` or `s`; such signatures parse but
    /// never recover.
    pub fn is_well_formed(&self) -> bool {
        self.decode_recoverable().is_some()
    }

    /// DER-encode the non-recoverable part of this signature (`r` and `s`).
    /// Returns `None` if the signature cannot be decoded.
    pub fn to_der_signature(&self) -> Option<Vec<u8>> {
        let (signature, _) = self.to_secp256k1_recoverable()?;
        Some(signature.to_der().as_bytes().to_vec())
    }

    /// Decode the recovery ID, `r` and `s` with libsecp256k1's parsing rules (see
    /// [`Self::is_well_formed`]).
    fn decode_recoverable(&self) -> Option<(K256RecoveryId, Scalar, Scalar)> {
        let recovery_id = K256RecoveryId::from_byte(self.0[0])?;
        let r = parse_scalar(&self.0[1..33])?;
        let s = parse_scalar(&self.0[33..65])?;
        Some((recovery_id, r, s))
    }
}

#[cfg(any(test, feature = "testing"))]
impl Default for Secp256k1PublicKey {
    fn default() -> Self {
        Self::new()
    }
}

impl Secp256k1PublicKey {
    #[cfg(any(test, feature = "testing"))]
    pub fn new() -> Secp256k1PublicKey {
        Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::random())
    }

    pub fn from_hex(hex_string: &str) -> Result<Secp256k1PublicKey, &'static str> {
        let data = hex_bytes(hex_string).map_err(|_e| "Failed to decode hex public key")?;
        Secp256k1PublicKey::from_slice(&data[..]).map_err(|_e| "Invalid public key hex string")
    }

    pub fn from_slice(data: &[u8]) -> Result<Secp256k1PublicKey, &'static str> {
        let key = parse_pubkey(data).map_err(|_e| "Invalid public key: failed to load")?;
        Ok(Secp256k1PublicKey {
            key,
            compressed: data.len() == PUBLIC_KEY_SIZE,
        })
    }

    pub fn from_private(privk: &Secp256k1PrivateKey) -> Secp256k1PublicKey {
        Secp256k1PublicKey {
            key: privk.key.public_key(),
            compressed: privk.compress_public,
        }
    }

    pub fn to_hex(&self) -> String {
        to_hex(&self.to_bytes())
    }

    pub fn to_bytes_compressed(&self) -> Vec<u8> {
        self.key.to_compressed_point().to_vec()
    }

    pub fn compressed(&self) -> bool {
        self.compressed
    }

    pub fn set_compressed(&mut self, value: bool) {
        self.compressed = value;
    }

    /// recover message and signature to public key (will be compressed)
    pub fn recover_to_pubkey(
        msg: &[u8],
        sig: &MessageSignature,
    ) -> Result<Secp256k1PublicKey, &'static str> {
        Self::recover_to_pubkey_possibly_with_low_s_verification(msg, sig, true)
    }

    /// Recover message and signature to public key (will be compressed), while
    /// skipping validation that the signature is normalized to low-S. You shouldn't
    /// use this in new code.
    pub fn recover_to_pubkey_without_validating_low_s(
        msg: &[u8],
        sig: &MessageSignature,
    ) -> Result<Secp256k1PublicKey, &'static str> {
        Self::recover_to_pubkey_possibly_with_low_s_verification(msg, sig, false)
    }

    fn recover_to_pubkey_possibly_with_low_s_verification(
        msg: &[u8],
        sig: &MessageSignature,
        verify_low_s: bool,
    ) -> Result<Secp256k1PublicKey, &'static str> {
        if msg.len() != 32 {
            return Err("Invalid message: failed to decode data hash: must be a 32-byte hash");
        }

        let (recovery_id, r, s) = sig
            .decode_recoverable()
            .ok_or("Invalid signature: failed to decode recoverable signature")?;

        if verify_low_s && bool::from(s.is_high()) {
            return Err("Invalid signature: high-S");
        }

        let key = recover_pubkey(msg, r, s, recovery_id)
            .map_err(|_e| "Invalid signature: failed to recover public key")?;

        Ok(Secp256k1PublicKey {
            key,
            compressed: true,
        })
    }
}

impl PublicKey for Secp256k1PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.key.to_sec1_point(self.compressed).as_bytes().to_vec()
    }

    fn verify(&self, data_hash: &[u8], sig: &MessageSignature) -> Result<bool, &'static str> {
        let recovered_pubkey = Self::recover_to_pubkey_without_validating_low_s(data_hash, sig)?;

        if recovered_pubkey.key != self.key {
            test_debug!("{:?} != {:?}", &recovered_pubkey.key, &self.key);
            return Ok(false);
        }

        // recovery accepts high-S signatures, so we have to reject them ourselves
        let (_, _, s) = sig
            .decode_recoverable()
            .ok_or("Invalid signature: failed to decode recoverable signature")?;
        if bool::from(s.is_high()) {
            return Err("Invalid signature: high-S");
        }

        Ok(true)
    }
}

impl Secp256k1PrivateKey {
    #[cfg(feature = "rand")]
    pub fn random() -> Secp256k1PrivateKey {
        use rand::RngCore as _;

        let mut rng = rand::thread_rng();
        loop {
            // keep trying to generate valid bytes
            let mut random_32_bytes = [0u8; 32];
            rng.fill_bytes(&mut random_32_bytes);
            if let Ok(key) = K256SecretKey::from_slice(&random_32_bytes) {
                return Secp256k1PrivateKey {
                    key,
                    compress_public: true,
                };
            }
        }
    }

    /// Create a Secp256k1PrivateKey from seed bytes by repeatedly
    ///  SHA256 hashing the seed bytes until a private key is found.
    ///
    /// If `seed` is a valid private key, it will be returned without hashing.
    /// The returned private key's compress_public flag will be `true`
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

    pub fn from_hex(hex_string: &str) -> Result<Secp256k1PrivateKey, &'static str> {
        let data = hex_bytes(hex_string).map_err(|_e| "Failed to decode hex private key")?;
        Secp256k1PrivateKey::from_slice(&data[..]).map_err(|_e| "Invalid private key hex string")
    }

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
        // rejects zero and values >= n
        match K256SecretKey::from_slice(&data[0..32]) {
            Ok(key) => Ok(Secp256k1PrivateKey {
                key,
                compress_public,
            }),
            Err(_e) => Err("Invalid private key: failed to load"),
        }
    }

    pub fn compress_public(&self) -> bool {
        self.compress_public
    }

    pub fn set_compress_public(&mut self, value: bool) {
        self.compress_public = value;
    }

    pub fn to_hex(&self) -> String {
        to_hex(&self.to_bytes())
    }

    /// Sign with RFC6979 deterministic nonces, mixing in `extra_entropy` as the RFC6979
    /// "additional data" when it is non-empty. This produces the same signatures as
    /// libsecp256k1, except when `data_hash >= n` (probability ~2^-128 for a hash):
    /// libsecp256k1 seeds RFC6979 with the unreduced hash, so the nonce (but not the
    /// validity of the signature) differs.
    fn sign_rfc6979(
        &self,
        data_hash: &[u8],
        extra_entropy: &[u8],
    ) -> Result<MessageSignature, &'static str> {
        if data_hash.len() != 32 {
            return Err("Invalid message: failed to decode data hash: must be a 32-byte hash");
        }
        // The resulting signature is low-S, with the recovery ID adjusted to match.
        let (sig, recid) = sign_prehashed_rfc6979::<Secp256k1, Sha256>(
            &self.key.to_nonzero_scalar(),
            data_hash,
            extra_entropy,
        );
        Ok(MessageSignature::from_secp256k1_recoverable(&sig, recid))
    }
}

impl PrivateKey for Secp256k1PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bits = self.key.to_bytes().to_vec();
        if self.compress_public {
            bits.push(0x01);
        }
        bits
    }

    fn sign(&self, data_hash: &[u8]) -> Result<MessageSignature, &'static str> {
        self.sign_rfc6979(data_hash, &[])
    }

    #[cfg(any(test, feature = "testing"))]
    fn sign_with_noncedata(
        &self,
        data_hash: &[u8],
        noncedata: &[u8; 32],
    ) -> Result<MessageSignature, &'static str> {
        self.sign_rfc6979(data_hash, noncedata)
    }
}

fn secp256k1_pubkey_serialize<S: serde::Serializer>(
    pubk: &K256PublicKey,
    s: S,
) -> Result<S::Ok, S::Error> {
    let key_hex = to_hex(&pubk.to_compressed_point());
    s.serialize_str(key_hex.as_str())
}

fn secp256k1_pubkey_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<K256PublicKey, D::Error> {
    let key_hex = String::deserialize(d)?;
    let key_bytes = hex_bytes(&key_hex).map_err(de_Error::custom)?;

    parse_pubkey(&key_bytes).map_err(de_Error::custom)
}

fn secp256k1_privkey_serialize<S: serde::Serializer>(
    privk: &K256SecretKey,
    s: S,
) -> Result<S::Ok, S::Error> {
    let key_hex = to_hex(&privk.to_bytes());
    s.serialize_str(key_hex.as_str())
}

fn secp256k1_privkey_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<K256SecretKey, D::Error> {
    let key_hex = String::deserialize(d)?;
    let key_bytes = hex_bytes(&key_hex).map_err(de_Error::custom)?;
    if key_bytes.len() != 32 {
        return Err(de_Error::custom(Error::InvalidInputLength));
    }

    K256SecretKey::from_slice(&key_bytes).map_err(de_Error::custom)
}

/// Recover a public key from a 32-byte message hash and a 65-byte RSV signature.
/// High-S signatures are accepted.
pub fn secp256k1_recover(
    message_arr: &[u8],
    serialized_signature_arr: &[u8],
) -> Result<[u8; 33], Error> {
    if message_arr.len() != 32 {
        return Err(Error::InvalidMessage);
    }
    if serialized_signature_arr.len() != 65 {
        return Err(Error::InvalidInputLength);
    }

    let recovery_id =
        K256RecoveryId::from_byte(serialized_signature_arr[64]).ok_or(Error::InvalidRecoveryId)?;
    let r = parse_scalar(&serialized_signature_arr[..32]).ok_or(Error::InvalidSignature)?;
    let s = parse_scalar(&serialized_signature_arr[32..64]).ok_or(Error::InvalidSignature)?;

    let recovered = recover_pubkey(message_arr, r, s, recovery_id)?;
    Ok(recovered.to_compressed_point().into())
}

/// Verify a 64-byte RS signature (a 65th recovery byte is ignored) over a 32-byte message
/// hash. High-S signatures are rejected.
pub fn secp256k1_verify(
    message_arr: &[u8],
    serialized_signature_arr: &[u8],
    pubkey_arr: &[u8],
) -> Result<(), Error> {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    if message_arr.len() != 32 {
        return Err(Error::InvalidMessage);
    }
    if !(64..=65).contains(&serialized_signature_arr.len()) {
        return Err(Error::InvalidInputLength);
    }

    let r = parse_scalar(&serialized_signature_arr[..32]).ok_or(Error::InvalidSignature)?;
    let s = parse_scalar(&serialized_signature_arr[32..64]).ok_or(Error::InvalidSignature)?;
    let pubkey = parse_pubkey(pubkey_arr)?;

    // rejects zero `r` or `s`
    let signature = K256Signature::from_scalars(r, s).map_err(|_| Error::InvalidSignature)?;
    // `verify_prehash()` rejects high-S signatures
    VerifyingKey::from(pubkey)
        .verify_prehash(message_arr, &signature)
        .map_err(|_| Error::InvalidSignature)
}

pub fn secp256k1_decompress(compressed_pubkey_arr: &[u8]) -> Result<[u8; 65], Error> {
    let pubkey = parse_pubkey(compressed_pubkey_arr)?;
    Ok(pubkey.to_uncompressed_point().into())
}

#[cfg(test)]
mod tests {
    use rand::RngCore as _;

    use super::*;
    use crate::util::get_epoch_time_ms;
    use crate::util::hash::hex_bytes;

    struct KeyFixture<I, R> {
        input: I,
        result: R,
    }

    #[derive(Debug)]
    struct VerifyFixture<R> {
        public_key: &'static str,
        data: &'static str,
        signature: &'static str,
        result: R,
    }

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
    /// Test the behavior of from_seed using hard-coded values from previous existing integration tests
    fn sk_from_seed() {
        let sk = Secp256k1PrivateKey::from_seed(&[2; 32]);
        assert_eq!(
            Secp256k1PublicKey::from_private(&sk).to_hex(),
            "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"
        );
        assert_eq!(
            sk.to_hex(),
            "020202020202020202020202020202020202020202020202020202020202020201"
        );

        let sk = Secp256k1PrivateKey::from_seed(&[0]);
        assert_eq!(
            Secp256k1PublicKey::from_private(&sk).to_hex(),
            "0243311589af63c2adda04fcd7792c038a05c12a4fe40351b3eb1612ff6b2e5a0e"
        );
        assert_eq!(
            sk.to_hex(),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d01"
        );
    }

    #[test]
    fn test_parse_serialize() {
        let fixtures = vec![
            KeyFixture {
                input: "0233d78f74de8ef4a1de815b6d5c5c129c073786305c0826c499b1811c9a12cee5",
                result: Some(Secp256k1PublicKey {
                    key: K256PublicKey::from_sec1_bytes(&hex_bytes("0233d78f74de8ef4a1de815b6d5c5c129c073786305c0826c499b1811c9a12cee5").unwrap()[..]).unwrap(),
                    compressed: true
                })
            },
            KeyFixture {
                input: "044a83ad59dbae1e2335f488dbba5f8604d00f612a43ebaae784b5b7124cc38c3aaf509362787e1a8e25131724d57fec81b87889aabb4edf7bd89f5c4daa4f8aa7",
                result: Some(Secp256k1PublicKey {
                    key: K256PublicKey::from_sec1_bytes(&hex_bytes("044a83ad59dbae1e2335f488dbba5f8604d00f612a43ebaae784b5b7124cc38c3aaf509362787e1a8e25131724d57fec81b87889aabb4edf7bd89f5c4daa4f8aa7").unwrap()[..]).unwrap(),
                    compressed: false
                })
            },
            KeyFixture {
                input: "0233d78f74de8ef4a1de815b6d5c5c129c073786305c0826c499b1811c9a12ce",
                result: None,
            },
            KeyFixture {
                input: "044a83ad59dbae1e2335f488dbba5f8604d00f612a43ebaae784b5b7124cc38c3aaf509362787e1a8e25131724d57fec81b87889aabb4edf7bd89f5c4daa4f8a",
                result: None,
            }
        ];

        for fixture in fixtures {
            let key_res = Secp256k1PublicKey::from_hex(fixture.input);
            match (key_res, fixture.result) {
                (Ok(key), Some(key_result)) => {
                    assert_eq!(key, key_result);

                    let key_from_slice =
                        Secp256k1PublicKey::from_slice(&hex_bytes(fixture.input).unwrap()[..])
                            .unwrap();
                    assert_eq!(key_from_slice, key_result);

                    let key_bytes = key.to_bytes();
                    assert_eq!(key_bytes, hex_bytes(fixture.input).unwrap());
                }
                (Err(_e), None) => {}
                (_, _) => {
                    // either got a key when we didn't expect one, or didn't get a key when we did
                    // expect one.
                    panic!("Unexpected result: we either got a key when we didn't expect one, or didn't get a key when we did expect one.");
                }
            }
        }
    }

    #[test]
    fn test_parse_hybrid_pubkey() {
        let uncompressed = hex_bytes("044a83ad59dbae1e2335f488dbba5f8604d00f612a43ebaae784b5b7124cc38c3aaf509362787e1a8e25131724d57fec81b87889aabb4edf7bd89f5c4daa4f8aa7").unwrap();
        let expected = Secp256k1PublicKey::from_slice(&uncompressed).unwrap();
        // y ends in 0xa7, so it is odd
        let mut hybrid = uncompressed.clone();
        hybrid[0] = TAG_PUBKEY_HYBRID_ODD;

        let key = Secp256k1PublicKey::from_slice(&hybrid).unwrap();
        assert_eq!(key, expected);
        assert!(!key.compressed());
        // re-serialized with the uncompressed tag, like libsecp256k1
        assert_eq!(key.to_bytes(), uncompressed);
        assert_eq!(
            secp256k1_decompress(&hybrid).unwrap().to_vec(),
            uncompressed
        );

        // the tag must match the parity of y
        hybrid[0] = TAG_PUBKEY_HYBRID_EVEN;
        assert!(Secp256k1PublicKey::from_slice(&hybrid).is_err());
        // hybrid tags are only valid for 65-byte keys
        let mut compressed = expected.to_bytes_compressed();
        compressed[0] = TAG_PUBKEY_HYBRID_ODD;
        assert!(Secp256k1PublicKey::from_slice(&compressed).is_err());
    }

    #[test]
    fn test_parse_rejects_non_libsecp256k1_encodings() {
        let key = Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::from_seed(b"tags"));
        // SEC1 "compact" (x-only) encoding, which k256 would otherwise accept
        let mut compact = key.to_bytes_compressed();
        compact[0] = 0x05;
        assert!(Secp256k1PublicKey::from_slice(&compact).is_err());
        assert!(secp256k1_decompress(&compact).is_err());
        // SEC1 identity encoding
        assert!(Secp256k1PublicKey::from_slice(&[0x00]).is_err());
        assert!(Secp256k1PublicKey::from_slice(&[]).is_err());
        // compressed tag with an uncompressed length, and vice versa
        let mut uncompressed = key.to_bytes_compressed();
        uncompressed.resize(UNCOMPRESSED_PUBLIC_KEY_SIZE, 0);
        assert!(Secp256k1PublicKey::from_slice(&uncompressed).is_err());
        let mut compressed = key.to_bytes_compressed();
        compressed[0] = TAG_PUBKEY_UNCOMPRESSED;
        assert!(Secp256k1PublicKey::from_slice(&compressed).is_err());
    }

    #[test]
    fn test_verify() {
        let fixtures : Vec<VerifyFixture<Result<bool, &'static str>>> = vec![
            VerifyFixture {
                public_key: "0385f2e2867524289d6047d0d9c5e764c5d413729fc32291ad2c353fbc396a4219",
                signature: "00354445a1dc98a1bd27984dbe69979a5cd77886b4d9134af5c40e634d96e1cb445b97de5b632582d31704f86706a780886e6e381bfed65228267358262d203fe6",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",       // sha256 hash of "hello world"
                result: Ok(true)
            },
            VerifyFixture {
                public_key: "0385f2e2867524289d6047d0d9c5e764c5d413729fc32291ad2c353fbc396a4219",
                signature: "00354445a1dc98a1bd27984dbe69979a5cd77886b4d9134af5c40e634d96e1cb445b97de5b632582d31704f86706a780886e6e381bfed65228267358262d203fe6",
                data: "ca3704aa0b06f5954c79ee837faa152d84d6b2d42838f0637a15eda8337dbdce",       // sha256 hash of "nope"
                result: Ok(false)
            },
            VerifyFixture {
                public_key: "034c35b09b758678165d6ed84a50b329900c99986cf8e9a358ceae0d03af91f5b6",   // wrong key
                signature: "00354445a1dc98a1bd27984dbe69979a5cd77886b4d9134af5c40e634d96e1cb445b97de5b632582d31704f86706a780886e6e381bfed65228267358262d203fe6",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",       // sha256 hash of "hello world"
                result: Ok(false)
            },
            VerifyFixture {
                public_key: "0385f2e2867524289d6047d0d9c5e764c5d413729fc32291ad2c353fbc396a4219",
                signature: "00354445a1dc98a1bd27984dbe69979a5cd77886b4d9134af5c40e634d96e1cb445b97de5b632582d31704f86706a780886e6e381bfed65228267358262d203fe7",  // wrong sig (bad s)
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",       // sha256 hash of "hello world"
                result: Ok(false)
            },
            VerifyFixture {
                public_key: "0385f2e2867524289d6047d0d9c5e764c5d413729fc32291ad2c353fbc396a4219",
                signature: "00454445a1dc98a1bd27984dbe69979a5cd77886b4d9134af5c40e634d96e1cb445b97de5b632582d31704f86706a780886e6e381bfed65228267358262d203fe6",  // wrong sig (bad r)
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",       // sha256 hash of "hello world"
                result: Ok(false)
            },
            VerifyFixture {
                public_key: "0385f2e2867524289d6047d0d9c5e764c5d413729fc32291ad2c353fbc396a4219",
                signature: "01354445a1dc98a1bd27984dbe69979a5cd77886b4d9134af5c40e634d96e1cb445b97de5b632582d31704f86706a780886e6e381bfed65228267358262d203fe6",  // wrong sig (bad recovery)
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",       // sha256 hash of "hello world"
                result: Ok(false)
            },
            VerifyFixture {
                public_key: "0385f2e2867524289d6047d0d9c5e764c5d413729fc32291ad2c353fbc396a4219",
                signature: "02354445a1dc98a1bd27984dbe69979a5cd77886b4d9134af5c40e634d96e1cb445b97de5b632582d31704f86706a780886e6e381bfed65228267358262d203fe6",  // wrong sig (bad recovery)
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",       // sha256 hash of "hello world"
                result: Err("Invalid signature: failed to recover public key"),
            },
            VerifyFixture {
                public_key: "0385f2e2867524289d6047d0d9c5e764c5d413729fc32291ad2c353fbc396a4219",
                signature: "03354445a1dc98a1bd27984dbe69979a5cd77886b4d9134af5c40e634d96e1cb445b97de5b632582d31704f86706a780886e6e381bfed65228267358262d203fe6",  // wrong sig (bad recovery)
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",       // sha256 hash of "hello world"
                result: Err("Invalid signature: failed to recover public key"),
            }
        ];

        for fixture in fixtures {
            let key = Secp256k1PublicKey::from_hex(fixture.public_key).unwrap();
            let signature = MessageSignature::from_raw(&hex_bytes(fixture.signature).unwrap());
            let ver_res = key.verify(&hex_bytes(fixture.data).unwrap(), &signature);
            match (ver_res, fixture.result) {
                (Ok(true), Ok(true)) => {}
                (Ok(false), Ok(false)) => {}
                (Err(e1), Err(e2)) => assert_eq!(e1, e2),
                (Err(e1), _) => {
                    test_debug!("Failed to verify signature: {}", e1);
                    panic!(
                        "failed fixture (verification: {:?}): {:#?}",
                        ver_res, fixture
                    );
                }
                (_, _) => {
                    panic!(
                        "failed fixture (verification: {:?}): {:#?}",
                        ver_res, fixture
                    );
                }
            }
        }
    }

    #[test]
    fn test_verify_rejects_high_s_after_key_match() {
        let privk = Secp256k1PrivateKey::from_seed(b"verify-high-s");
        let pubk = Secp256k1PublicKey::from_private(&privk);
        let msg = [0x5au8; 32];
        let high_s_sig = privk.sign(&msg).unwrap().with_negated_s();

        assert_eq!(
            pubk.verify(&msg, &high_s_sig),
            Err("Invalid signature: high-S")
        );
        // a key mismatch is reported before the high-S check
        let other = Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::from_seed(b"other"));
        assert_eq!(other.verify(&msg, &high_s_sig), Ok(false));
    }

    #[test]
    fn test_recover_to_pubkey_low_s_enforcement() {
        let privk = Secp256k1PrivateKey::from_seed(b"recover-low-s");
        let pubk = Secp256k1PublicKey::from_private(&privk);
        let msg = [0x33u8; 32];
        let sig = privk.sign(&msg).unwrap();
        let high_s_sig = sig.with_negated_s();

        let recovered = Secp256k1PublicKey::recover_to_pubkey(&msg, &sig).unwrap();
        assert_eq!(recovered.to_bytes_compressed(), pubk.to_bytes_compressed());

        assert_eq!(
            Secp256k1PublicKey::recover_to_pubkey(&msg, &high_s_sig),
            Err("Invalid signature: high-S")
        );
        let recovered =
            Secp256k1PublicKey::recover_to_pubkey_without_validating_low_s(&msg, &high_s_sig)
                .unwrap();
        assert_eq!(recovered.to_bytes_compressed(), pubk.to_bytes_compressed());
    }

    #[test]
    fn test_recover_to_pubkey_errors() {
        let privk = Secp256k1PrivateKey::from_seed(b"recover-errors");
        let msg = [0x44u8; 32];
        let sig = privk.sign(&msg).unwrap();

        assert_eq!(
            Secp256k1PublicKey::recover_to_pubkey(&msg[..31], &sig),
            Err("Invalid message: failed to decode data hash: must be a 32-byte hash")
        );

        let mut bad_recid = sig.clone();
        bad_recid.0[0] = 4;
        assert_eq!(
            Secp256k1PublicKey::recover_to_pubkey(&msg, &bad_recid),
            Err("Invalid signature: failed to decode recoverable signature")
        );

        // s >= n does not decode
        let mut overflow_s = sig.clone();
        overflow_s.0[33..].copy_from_slice(&[0xff; 32]);
        assert_eq!(
            Secp256k1PublicKey::recover_to_pubkey(&msg, &overflow_s),
            Err("Invalid signature: failed to decode recoverable signature")
        );

        // zero r or s decodes, but cannot recover
        assert_eq!(
            Secp256k1PublicKey::recover_to_pubkey(&msg, &MessageSignature::empty()),
            Err("Invalid signature: failed to recover public key")
        );
    }

    #[test]
    fn test_is_well_formed() {
        let privk = Secp256k1PrivateKey::from_seed(b"well-formed");
        let sig = privk.sign(&[0x11u8; 32]).unwrap();
        assert!(sig.is_well_formed());
        assert!(sig.to_secp256k1_recoverable().is_some());

        // zero r and s parse, but are not usable k256 signatures
        assert!(MessageSignature::empty().is_well_formed());
        assert!(MessageSignature::empty()
            .to_secp256k1_recoverable()
            .is_none());

        let mut bad_recid = sig.clone();
        bad_recid.0[0] = 4;
        assert!(!bad_recid.is_well_formed());

        let mut overflow_r = sig.clone();
        overflow_r.0[1..33].copy_from_slice(&[0xff; 32]);
        assert!(!overflow_r.is_well_formed());

        let mut overflow_s = sig;
        overflow_s.0[33..].copy_from_slice(&[0xff; 32]);
        assert!(!overflow_s.is_well_formed());
    }

    #[test]
    fn test_sign_matches_libsecp256k1() {
        // Signatures generated with the `secp256k1` crate (libsecp256k1 bindings) via
        // `sign_ecdsa_recoverable` and `sign_ecdsa_recoverable_with_noncedata`.
        let privk = Secp256k1PrivateKey::from_hex(
            "7b48329a5126dad83fc583c309c2698ae2843acfb9a7023fb081d850386c6950",
        )
        .unwrap();
        let msg =
            hex_bytes("77949dd27dabb40847564f40afcde8b91e0f7baf2cc710415a4ac8b777104866").unwrap();

        assert_eq!(
            privk.sign(&msg).unwrap().to_hex(),
            "0183cf28dd6aeba05f6b673e24a2561e78906493abd92d549896af6ae43f043239454b02877c1a9525451256f920bed1dced534c406addd0369471fbf6e57c4b62"
        );
        assert_eq!(
            privk.sign_with_noncedata(&msg, &[0xaa; 32]).unwrap().to_hex(),
            "00e710f950d452810697436b78284acb5e8bd49d5a633ff6439ea32d9c031709d54f574fe4912934dd5e9b1aaaacf4b208e104cf7bb07ae1519ed4ebb688871c63"
        );
    }

    #[test]
    #[ignore]
    fn test_verify_benchmark_roundtrip() {
        let mut runtime_sign = 0;
        let mut runtime_verify = 0;
        let mut runtime_recover = 0;
        let mut rng = rand::thread_rng();

        for _i in 0..100 {
            let privk = Secp256k1PrivateKey::random();
            let pubk = Secp256k1PublicKey::from_private(&privk);

            let mut msg = [0u8; 32];
            rng.fill_bytes(&mut msg);

            let sign_start = get_epoch_time_ms();
            for _j in 0..1000 {
                let _sig = privk.sign(&msg).unwrap();
            }
            let sign_end = get_epoch_time_ms();

            let sig = privk.sign(&msg).unwrap();

            let recovered_pubk = Secp256k1PublicKey::recover_to_pubkey(&msg, &sig).unwrap();
            assert_eq!(recovered_pubk.key, pubk.key);

            let recover_start = get_epoch_time_ms();
            for _j in 0..1000 {
                let _recovered_pubk = Secp256k1PublicKey::recover_to_pubkey(&msg, &sig).unwrap();
            }
            let recover_end = get_epoch_time_ms();

            let verify_start = get_epoch_time_ms();
            for _j in 0..1000 {
                let _valid = pubk.verify(&msg, &sig).unwrap();
            }
            let verify_end = get_epoch_time_ms();

            let valid = pubk.verify(&msg, &sig).unwrap();
            assert!(valid);

            test_debug!(
                "Runtime: {:?} sign, {:?} recover, {:?} verify",
                ((sign_end - sign_start) as f64) / 1000.0,
                ((recover_end - recover_start) as f64) / 1000.0,
                ((verify_end - verify_start) as f64) / 1000.0
            );

            runtime_sign += sign_end - sign_start;
            runtime_verify += verify_end - verify_start;
            runtime_recover += recover_end - recover_start;
        }

        test_debug!(
            "Total Runtime: {:?} sign, {:?} verify, {:?} recover, {:?} verify - recover",
            runtime_sign,
            runtime_verify,
            runtime_recover,
            runtime_verify - runtime_recover
        );
    }

    #[test]
    fn test_decompress() {
        let mut sk = Secp256k1PrivateKey::random();
        sk.set_compress_public(true);
        let pk = Secp256k1PublicKey::from_private(&sk);

        assert_eq!(pk.to_bytes().len(), 33);

        let decompressed_pk = secp256k1_decompress(pk.to_bytes().as_slice()).unwrap();
        assert_eq!(decompressed_pk.len(), 65);

        sk.set_compress_public(false);
        let pk_uncompressed = Secp256k1PublicKey::from_private(&sk);

        assert_eq!(pk_uncompressed.to_bytes(), decompressed_pk);
    }

    #[test]
    fn test_with_negated_s() {
        let priv_key = Secp256k1PrivateKey::from_hex(
            "7b48329a5126dad83fc583c309c2698ae2843acfb9a7023fb081d850386c6950",
        )
        .unwrap();
        let pub_key = Secp256k1PublicKey::from_private(&priv_key);
        let message =
            &hex_bytes("77949dd27dabb40847564f40afcde8b91e0f7baf2cc710415a4ac8b777104866").unwrap()
                [..];
        let original_sig = priv_key.sign(message).unwrap();
        let high_s_sig = original_sig.with_negated_s();

        assert_ne!(
            original_sig, high_s_sig,
            "low-S and high-S signatures should not be the same"
        );

        assert_eq!(
            original_sig,
            high_s_sig.with_negated_s(),
            "negating twice should bring back the original"
        );

        let recovered_from_orig =
            Secp256k1PublicKey::recover_to_pubkey_without_validating_low_s(message, &original_sig)
                .unwrap();
        let recovered_from_high_s =
            Secp256k1PublicKey::recover_to_pubkey_without_validating_low_s(message, &high_s_sig)
                .unwrap();

        assert_eq!(
            recovered_from_orig, recovered_from_high_s,
            "both signatures should recover to the same public key"
        );

        assert_eq!(
            recovered_from_high_s.key, pub_key.key,
            "the recovered key should be identical to the original key"
        );
    }

    #[test]
    fn test_secp256k1_recover_high_s() {
        let privk = Secp256k1PrivateKey::from_seed(b"test-recover-high-s");
        let pubk = Secp256k1PublicKey::from_private(&privk);
        let msg = Sha256Sum::from_data(b"hello world");
        let high_s_sig = privk.sign(msg.as_bytes()).unwrap().with_negated_s();

        let recovered = secp256k1_recover(msg.as_bytes(), &high_s_sig.to_rsv())
            .expect("secp256k1_recover must accept high-S signatures");
        assert_eq!(recovered.to_vec(), pubk.to_bytes_compressed());
    }

    #[test]
    fn test_secp256k1_recover_errors() {
        let privk = Secp256k1PrivateKey::from_seed(b"recover-fn-errors");
        let msg = [0x66u8; 32];
        let rsv = privk.sign(&msg).unwrap().to_rsv();

        assert!(secp256k1_recover(&msg, &rsv).is_ok());
        assert_eq!(
            secp256k1_recover(&msg[..31], &rsv),
            Err(Error::InvalidMessage)
        );
        assert_eq!(
            secp256k1_recover(&msg, &rsv[..64]),
            Err(Error::InvalidInputLength)
        );
        let mut bad_recid = rsv.clone();
        bad_recid[64] = 4;
        assert_eq!(
            secp256k1_recover(&msg, &bad_recid),
            Err(Error::InvalidRecoveryId)
        );
        assert!(secp256k1_recover(&msg, &[0u8; 65]).is_err());
    }

    #[test]
    fn test_secp256k1_verify_function() {
        let pubkey =
            hex_bytes("0385f2e2867524289d6047d0d9c5e764c5d413729fc32291ad2c353fbc396a4219")
                .unwrap();
        let message =
            hex_bytes("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9").unwrap();
        let sig_rs = hex_bytes(
            "354445a1dc98a1bd27984dbe69979a5cd77886b4d9134af5c40e634d96e1cb44\
             5b97de5b632582d31704f86706a780886e6e381bfed65228267358262d203fe6",
        )
        .unwrap();

        assert_eq!(secp256k1_verify(&message, &sig_rs, &pubkey), Ok(()));
        // a 65th (recovery) byte is ignored
        let mut sig_rsv = sig_rs.clone();
        sig_rsv.push(3);
        assert_eq!(secp256k1_verify(&message, &sig_rsv, &pubkey), Ok(()));

        let mut bad_msg = message.clone();
        bad_msg[0] ^= 0xff;
        assert!(secp256k1_verify(&bad_msg, &sig_rs, &pubkey).is_err());

        let other_pubk = Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::random());
        assert!(secp256k1_verify(&message, &sig_rs, &other_pubk.to_bytes_compressed()).is_err());

        // malformed inputs are errors, not panics
        assert_eq!(
            secp256k1_verify(&message, &sig_rs[..63], &pubkey),
            Err(Error::InvalidInputLength)
        );
        assert_eq!(
            secp256k1_verify(&message[..31], &sig_rs, &pubkey),
            Err(Error::InvalidMessage)
        );
        assert_eq!(
            secp256k1_verify(&message, &sig_rs, &pubkey[..32]),
            Err(Error::InvalidPublicKey)
        );

        // high-S signatures are rejected
        let high_s_sig = hex_bytes(
            "54cd3f378a424a3e50ff1c911b7d80cf424e1b86dddecadbcf39077e62fa1e54\
             ee6514347c1608df2c3995e7356f2d60a1fab60878214642134d78cd923ce27a",
        )
        .unwrap();
        let high_s_msg =
            hex_bytes("89171d7815da4bc1f644665a3234bc99d1680afa0b3285eff4878f4275fbfa89").unwrap();
        let high_s_pubkey =
            hex_bytes("0256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967")
                .unwrap();
        assert!(secp256k1_verify(&high_s_msg, &high_s_sig, &high_s_pubkey).is_err());
    }

    #[test]
    fn test_to_der_signature() {
        // r and s both have their high bit clear: no padding
        let sig = MessageSignature::from_raw(&hex_bytes("00354445a1dc98a1bd27984dbe69979a5cd77886b4d9134af5c40e634d96e1cb445b97de5b632582d31704f86706a780886e6e381bfed65228267358262d203fe6").unwrap());
        assert_eq!(
            to_hex(&sig.to_der_signature().unwrap()),
            "30440220354445a1dc98a1bd27984dbe69979a5cd77886b4d9134af5c40e634d96e1cb4402205b97de5b632582d31704f86706a780886e6e381bfed65228267358262d203fe6"
        );

        // r has its high bit set (padded with 0x00), s = 1 (leading zeros stripped)
        let mut bytes = [0u8; 65];
        bytes[1] = 0x80;
        bytes[32] = 0x01;
        bytes[64] = 0x01;
        let der = MessageSignature(bytes).to_der_signature().unwrap();
        assert_eq!(&der[..5], &[0x30, 0x26, 0x02, 0x21, 0x00]);
        assert_eq!(&der[der.len() - 3..], &[0x02, 0x01, 0x01]);

        // zero r or s cannot be DER-encoded
        assert!(MessageSignature::empty().to_der_signature().is_none());
    }

    #[test]
    fn test_privkey_debug_redacts_key() {
        let privk = Secp256k1PrivateKey::from_seed(b"debug-redaction");
        let key_hex = to_hex(&privk.to_bytes()[..32]);
        let debug = format!("{privk:?}");
        assert!(!debug.contains(&key_hex));
        assert!(!debug.to_lowercase().contains(&key_hex[..16]));
    }

    #[test]
    fn test_privkey_from_slice() {
        let raw = [0x12u8; 32];
        let sk = Secp256k1PrivateKey::from_slice(&raw).unwrap();
        assert!(!sk.compress_public());
        assert_eq!(sk.to_bytes(), raw);

        let mut raw_comp = [0x01u8; 33];
        raw_comp[..32].copy_from_slice(&raw);
        let sk_comp = Secp256k1PrivateKey::from_slice(&raw_comp).unwrap();
        assert!(sk_comp.compress_public());
        assert_eq!(sk_comp.to_bytes(), raw_comp);

        raw_comp[32] = 0x02;
        assert!(Secp256k1PrivateKey::from_slice(&raw_comp).is_err());
        assert!(Secp256k1PrivateKey::from_slice(&raw[..31]).is_err());
        assert!(Secp256k1PrivateKey::from_slice(&[0x12u8; 34]).is_err());
        assert!(Secp256k1PrivateKey::from_slice(&[0u8; 32]).is_err());
        assert!(Secp256k1PrivateKey::from_slice(&[0xffu8; 32]).is_err());
    }

    #[test]
    fn test_serde_roundtrip() {
        let privk = Secp256k1PrivateKey::from_seed(b"serde");
        let pubk = Secp256k1PublicKey::from_private(&privk);

        let privk_json = serde_json::to_string(&privk).unwrap();
        assert_eq!(
            serde_json::from_str::<Secp256k1PrivateKey>(&privk_json).unwrap(),
            privk
        );
        let pubk_json = serde_json::to_string(&pubk).unwrap();
        assert_eq!(
            serde_json::from_str::<Secp256k1PublicKey>(&pubk_json).unwrap(),
            pubk
        );
    }

    #[test]
    fn test_pubkey_hash_usable_as_map_key() {
        use std::collections::HashMap;

        let pubk1 = Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::from_seed(b"key-one"));
        let pubk2 = Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::from_seed(b"key-two"));

        let mut map: HashMap<Secp256k1PublicKey, u32> = HashMap::new();
        map.insert(pubk1.clone(), 1);
        map.insert(pubk2.clone(), 2);

        assert_eq!(map[&pubk1], 1);
        assert_eq!(map[&pubk2], 2);

        let mut pubk1_uncomp = pubk1;
        pubk1_uncomp.set_compressed(false);
        assert_eq!(map.get(&pubk1_uncomp), None);
    }
}
