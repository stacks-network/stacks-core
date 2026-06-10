// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

#[cfg(all(any(test, feature = "testing"), not(feature = "wasm-deterministic")))]
use ::libsecp256k1::curve::Scalar;
pub use ::libsecp256k1::Error;
use ::libsecp256k1::{
    self, PublicKey as LibSecp256k1PublicKey, RecoveryId as LibSecp256k1RecoveryId,
    SecretKey as LibSecp256k1PrivateKey, Signature as LibSecp256k1Signature, ECMULT_GEN_CONTEXT,
};
#[cfg(not(feature = "wasm-deterministic"))]
use ::libsecp256k1::{Error as LibSecp256k1Error, Message as LibSecp256k1Message};
use serde::de::{Deserialize, Error as de_Error};
use serde::Serialize;

use super::MessageSignature;
use crate::types::{PrivateKey, PublicKey};
use crate::util::hash::{hex_bytes, to_hex, Sha256Sum};

pub const PUBLIC_KEY_SIZE: usize = 33;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Secp256k1PublicKey {
    // serde is broken for secp256k1, so do it ourselves
    #[serde(
        serialize_with = "secp256k1_pubkey_serialize",
        deserialize_with = "secp256k1_pubkey_deserialize"
    )]
    key: LibSecp256k1PublicKey,
    compressed: bool,
}

impl std::hash::Hash for Secp256k1PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key.serialize_compressed().hash(state);
        self.compressed.hash(state);
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct Secp256k1PrivateKey {
    // serde is broken for secp256k1, so do it ourselves
    #[serde(
        serialize_with = "secp256k1_privkey_serialize",
        deserialize_with = "secp256k1_privkey_deserialize"
    )]
    key: LibSecp256k1PrivateKey,
    compress_public: bool,
}

impl MessageSignature {
    pub fn empty() -> MessageSignature {
        // NOTE: this cannot be a valid signature
        MessageSignature([0u8; 65])
    }

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

    pub fn from_secp256k1_recoverable(
        sig: &LibSecp256k1Signature,
        recid: LibSecp256k1RecoveryId,
    ) -> MessageSignature {
        let bytes = sig.serialize();
        let mut ret_bytes = [0u8; 65];
        ret_bytes[0] = recid.serialize();
        ret_bytes[1..=64].copy_from_slice(&bytes[..64]);
        MessageSignature(ret_bytes)
    }

    pub fn to_secp256k1_recoverable(
        &self,
    ) -> Option<(LibSecp256k1Signature, LibSecp256k1RecoveryId)> {
        let recovery_id = LibSecp256k1RecoveryId::parse(self.0[0]).ok()?;
        let signature = LibSecp256k1Signature::parse_standard_slice(&self.0[1..65]).ok()?;
        Some((signature, recovery_id))
    }

    /// Convert from VRS to RSV
    pub fn to_rsv(&self) -> Vec<u8> {
        [&self.0[1..], &self.0[0..1]].concat()
    }

    /// DER-encode the non-recoverable portion of this signature.
    /// Returns None if the signature bytes are malformed.
    pub fn to_der_signature(&self) -> Option<Vec<u8>> {
        let (sig, _) = self.to_secp256k1_recoverable()?;
        Some(secp256k1_der_encode(&sig.serialize()))
    }
}

/// Encode a 64-byte compact ECDSA signature (r||s, big-endian) in DER format.
pub fn secp256k1_der_encode(compact: &[u8; 64]) -> Vec<u8> {
    fn encode_int(n: &[u8]) -> Vec<u8> {
        let start = n.iter().position(|&b| b != 0).unwrap_or(n.len());
        let n = &n[start..];
        let needs_pad = !n.is_empty() && (n[0] & 0x80 != 0);
        let int_len = n.len() + usize::from(needs_pad);
        let mut v = Vec::with_capacity(int_len + 2);
        v.push(0x02);
        v.push(int_len as u8);
        if needs_pad {
            v.push(0x00);
        }
        v.extend_from_slice(n);
        v
    }

    let r = encode_int(&compact[..32]);
    let s = encode_int(&compact[32..]);
    let mut out = Vec::with_capacity(r.len() + s.len() + 2);
    out.push(0x30);
    out.push((r.len() + s.len()) as u8);
    out.extend(r);
    out.extend(s);
    out
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
        let (format, compressed) = if data.len() == PUBLIC_KEY_SIZE {
            (libsecp256k1::PublicKeyFormat::Compressed, true)
        } else {
            (libsecp256k1::PublicKeyFormat::Full, false)
        };
        LibSecp256k1PublicKey::parse_slice(data, Some(format))
            .map(|key| Secp256k1PublicKey { key, compressed })
            .map_err(|_e| "Invalid public key: failed to load")
    }

    #[cfg(not(feature = "wasm-deterministic"))]
    pub fn from_private(privk: &Secp256k1PrivateKey) -> Secp256k1PublicKey {
        let key =
            LibSecp256k1PublicKey::from_secret_key_with_context(&privk.key, &ECMULT_GEN_CONTEXT);
        Secp256k1PublicKey {
            key,
            compressed: privk.compress_public,
        }
    }

    pub fn to_hex(&self) -> String {
        to_hex(&self.to_bytes())
    }

    pub fn to_bytes_compressed(&self) -> Vec<u8> {
        self.key.serialize_compressed().to_vec()
    }

    pub fn compressed(&self) -> bool {
        self.compressed
    }

    pub fn set_compressed(&mut self, value: bool) {
        self.compressed = value;
    }

    #[cfg(not(feature = "wasm-deterministic"))]
    /// recover message and signature to public key (will be compressed)
    pub fn recover_to_pubkey(
        msg: &[u8],
        sig: &MessageSignature,
    ) -> Result<Secp256k1PublicKey, &'static str> {
        // secp256k1_recover expects RSV order; MessageSignature is stored as VRS
        let secp256k1_sig = secp256k1_recover(msg, &sig.to_rsv())
            .map_err(|_e| "Invalid signature: failed to recover public key")?;
        Secp256k1PublicKey::from_slice(&secp256k1_sig)
    }
}

impl PublicKey for Secp256k1PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        if self.compressed {
            self.key.serialize_compressed().to_vec()
        } else {
            self.key.serialize().to_vec()
        }
    }

    #[cfg(feature = "wasm-deterministic")]
    fn verify(&self, _data_hash: &[u8], _sig: &MessageSignature) -> Result<bool, &'static str> {
        Err("Not implemented for wasm-deterministic")
    }

    #[cfg(not(feature = "wasm-deterministic"))]
    fn verify(&self, data_hash: &[u8], sig: &MessageSignature) -> Result<bool, &'static str> {
        let recovered = Secp256k1PublicKey::recover_to_pubkey(data_hash, sig)?;
        if recovered.key != self.key {
            test_debug!("{:?} != {:?}", &recovered.key, &self.key);
            return Ok(false);
        }

        // NOTE: libsecp256k1 _should_ ensure that the S is low,
        // but add this check just to be safe.
        let (standard_sig, _) = sig
            .to_secp256k1_recoverable()
            .ok_or("Invalid signature: failed to decode recoverable signature")?;
        if !is_low_s(&standard_sig) {
            return Err("Invalid signature: high-S");
        }

        Ok(true)
    }
}

/// Returns true if the signature's S value is in the lower half of the secp256k1 group order.
#[cfg(not(feature = "wasm-deterministic"))]
fn is_low_s(sig: &LibSecp256k1Signature) -> bool {
    // secp256k1 group order n divided by 2 (big-endian)
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68,
        0x1b, 0x20, 0xa0,
    ];
    let bytes = sig.serialize();
    bytes[32..] <= HALF_ORDER[..]
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
            if let Ok(pk) = LibSecp256k1PrivateKey::parse_slice(&random_32_bytes) {
                return Secp256k1PrivateKey {
                    key: pk,
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
        LibSecp256k1PrivateKey::parse_slice(&data[0..32])
            .map(|key| Secp256k1PrivateKey {
                key,
                compress_public,
            })
            .map_err(|_e| "Invalid private key: failed to load")
    }

    pub fn compress_public(&self) -> bool {
        self.compress_public
    }

    pub fn set_compress_public(&mut self, value: bool) {
        self.compress_public = value;
    }

    pub fn to_hex(&self) -> String {
        let mut bytes = self.key.serialize().to_vec();
        if self.compress_public {
            bytes.push(1);
        }
        to_hex(&bytes)
    }
}

impl PrivateKey for Secp256k1PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bits = self.key.serialize().to_vec();
        if self.compress_public {
            bits.push(0x01);
        }
        bits
    }

    #[cfg(feature = "wasm-deterministic")]
    fn sign(&self, _data_hash: &[u8]) -> Result<MessageSignature, &'static str> {
        Err("Not implemented for wasm-deterministic")
    }

    #[cfg(not(feature = "wasm-deterministic"))]
    fn sign(&self, data_hash: &[u8]) -> Result<MessageSignature, &'static str> {
        let message = LibSecp256k1Message::parse_slice(data_hash).map_err(|_e| {
            "Invalid message: failed to decode data hash: must be a 32-byte hash"
        })?;
        let (sig, recid) = libsecp256k1::sign(&message, &self.key);
        Ok(MessageSignature::from_secp256k1_recoverable(&sig, recid))
    }

    #[cfg(all(feature = "wasm-deterministic", any(test, feature = "testing")))]
    fn sign_with_noncedata(
        &self,
        _data_hash: &[u8],
        _noncedata: &[u8; 32],
    ) -> Result<MessageSignature, &'static str> {
        Err("Not implemented for wasm-deterministic")
    }

    #[cfg(all(any(test, feature = "testing"), not(feature = "wasm-deterministic")))]
    fn sign_with_noncedata(
        &self,
        data_hash: &[u8],
        noncedata: &[u8; 32],
    ) -> Result<MessageSignature, &'static str> {
        let message = LibSecp256k1Message::parse_slice(data_hash).map_err(|_e| {
            "Invalid message: failed to decode data hash: must be a 32-byte hash"
        })?;
        let mut nonce = Scalar::default();
        let _ = nonce.set_b32(noncedata);

        // we need this as the key raw data are private
        let mut key = Scalar::default();
        let _ = key.set_b32(&self.key.serialize());

        let (sigr, sigs, recid) = match ECMULT_GEN_CONTEXT.sign_raw(&key, &message.0, &nonce) {
            Ok(result) => result,
            Err(_) => return Err("unable to sign message"),
        };

        let recid = match LibSecp256k1RecoveryId::parse(recid) {
            Ok(recid) => recid,
            Err(_) => return Err("invalid recovery id"),
        };

        let sig = LibSecp256k1Signature { r: sigr, s: sigs };
        Ok(MessageSignature::from_secp256k1_recoverable(&sig, recid))
    }
}

fn secp256k1_pubkey_serialize<S: serde::Serializer>(
    pubk: &LibSecp256k1PublicKey,
    s: S,
) -> Result<S::Ok, S::Error> {
    let key_hex = to_hex(&pubk.serialize_compressed());
    s.serialize_str(key_hex.as_str())
}

fn secp256k1_pubkey_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<LibSecp256k1PublicKey, D::Error> {
    let key_hex = String::deserialize(d)?;
    let key_bytes = hex_bytes(&key_hex).map_err(de_Error::custom)?;

    LibSecp256k1PublicKey::parse_slice(&key_bytes[..], None).map_err(de_Error::custom)
}

fn secp256k1_privkey_serialize<S: serde::Serializer>(
    privk: &LibSecp256k1PrivateKey,
    s: S,
) -> Result<S::Ok, S::Error> {
    let key_hex = to_hex(&privk.serialize());
    s.serialize_str(key_hex.as_str())
}

fn secp256k1_privkey_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<LibSecp256k1PrivateKey, D::Error> {
    let key_hex = String::deserialize(d)?;
    let key_bytes = hex_bytes(&key_hex).map_err(de_Error::custom)?;

    LibSecp256k1PrivateKey::parse_slice(&key_bytes[..]).map_err(de_Error::custom)
}

#[cfg(not(feature = "wasm-deterministic"))]
pub fn secp256k1_recover(
    message_arr: &[u8],
    serialized_signature_arr: &[u8],
) -> Result<[u8; 33], LibSecp256k1Error> {
    let recovery_id = libsecp256k1::RecoveryId::parse(serialized_signature_arr[64] as u8)?;
    let message = LibSecp256k1Message::parse_slice(message_arr)?;
    let signature =
        LibSecp256k1Signature::parse_standard_slice(&serialized_signature_arr[..64])?;
    let recovered_pub = libsecp256k1::recover(&message, &signature, &recovery_id)?;
    Ok(recovered_pub.serialize_compressed())
}

#[cfg(not(feature = "wasm-deterministic"))]
pub fn secp256k1_verify(
    message_arr: &[u8],
    serialized_signature_arr: &[u8],
    pubkey_arr: &[u8],
) -> Result<(), LibSecp256k1Error> {
    let message = LibSecp256k1Message::parse_slice(message_arr)?;
    let signature =
        LibSecp256k1Signature::parse_standard_slice(&serialized_signature_arr[..64])?; // ignore 65th byte if present
    let pubkey = LibSecp256k1PublicKey::parse_slice(
        pubkey_arr,
        Some(libsecp256k1::PublicKeyFormat::Compressed),
    )?;
    // Reject high-S signatures to prevent malleability (consistent with Bitcoin secp256k1)
    if !is_low_s(&signature) {
        return Err(LibSecp256k1Error::InvalidSignature);
    }
    if libsecp256k1::verify(&message, &signature, &pubkey) {
        Ok(())
    } else {
        Err(LibSecp256k1Error::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore as _;

    /// Negate a secp256k1 scalar: returns `n - s` (mod n), giving the complementary S value.
    /// Negating S and flipping the recovery-id bit produces a valid signature for the same
    /// (message, key) pair that has the opposite S parity.
    fn negate_secp256k1_scalar(s: &[u8; 32]) -> [u8; 32] {
        // secp256k1 group order n
        const N: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];
        let mut result = [0u8; 32];
        let mut borrow: i32 = 0;
        for i in (0..32).rev() {
            let diff = N[i] as i32 - s[i] as i32 - borrow;
            result[i] = diff.rem_euclid(256) as u8;
            borrow = if diff < 0 { 1 } else { 0 };
        }
        result
    }

    #[test]
    fn test_recover_high_s() {
        // Sign a message, convert the signature to its high-S equivalent, and verify that
        // secp256k1_recover returns the original public key.  This is the invariant that
        // allows secp256k1-recover? to work with high-S signatures.
        use crate::util::hash::Sha256Sum;

        let privk = Secp256k1PrivateKey::from_seed(b"test-recover-high-s");
        let pubk = Secp256k1PublicKey::from_private(&privk);
        let msg = Sha256Sum::from_data(b"hello world");

        let sig = privk.sign(msg.as_bytes()).expect("sign should succeed");
        let (low_sig, recid) = sig
            .to_secp256k1_recoverable()
            .expect("signature must be parseable");
        let compact = low_sig.serialize(); // [r (32) || s (32)]

        // Build the complementary high-S RSV form:
        //   s_complement = n - s   (always has the opposite S-parity)
        //   recovery_id  = old_id XOR 1  (flips the y-parity bit of R)
        let s_comp = negate_secp256k1_scalar(compact[32..].try_into().unwrap());

        // Confirm the complement is actually high-S (sanity: exactly one of s / s_comp is high)
        const HALF_ORDER: [u8; 32] = [
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46,
            0x68, 0x1b, 0x20, 0xa0,
        ];
        let orig_is_low = compact[32..] <= HALF_ORDER[..];
        let comp_is_high = s_comp > HALF_ORDER;
        assert_eq!(
            orig_is_low, comp_is_high,
            "exactly one of (s, n-s) must be high-S"
        );

        // Use whichever form is high-S
        let (high_s, high_v) = if comp_is_high {
            (s_comp, recid.serialize() ^ 1)
        } else {
            // original s is already high-S
            let mut orig = [0u8; 32];
            orig.copy_from_slice(&compact[32..]);
            (orig, recid.serialize())
        };

        let mut sig_rsv = [0u8; 65];
        sig_rsv[..32].copy_from_slice(&compact[..32]); // R
        sig_rsv[32..64].copy_from_slice(&high_s); // high-S
        sig_rsv[64] = high_v; // recovery id

        let recovered = super::secp256k1_recover(msg.as_bytes(), &sig_rsv)
            .expect("secp256k1_recover must succeed for high-S");

        assert_eq!(
            recovered.to_vec(),
            pubk.to_bytes_compressed(),
            "high-S recovery must return the original signer's public key"
        );
    }

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
                    key: LibSecp256k1PublicKey::parse_slice(
                        &hex_bytes(
                            "0233d78f74de8ef4a1de815b6d5c5c129c073786305c0826c499b1811c9a12cee5",
                        )
                        .unwrap()[..],
                        Some(libsecp256k1::PublicKeyFormat::Compressed),
                    )
                    .unwrap(),
                    compressed: true,
                }),
            },
            KeyFixture {
                input: "044a83ad59dbae1e2335f488dbba5f8604d00f612a43ebaae784b5b7124cc38c3aaf509362787e1a8e25131724d57fec81b87889aabb4edf7bd89f5c4daa4f8aa7",
                result: Some(Secp256k1PublicKey {
                    key: LibSecp256k1PublicKey::parse_slice(
                        &hex_bytes("044a83ad59dbae1e2335f488dbba5f8604d00f612a43ebaae784b5b7124cc38c3aaf509362787e1a8e25131724d57fec81b87889aabb4edf7bd89f5c4daa4f8aa7")
                            .unwrap()[..],
                        Some(libsecp256k1::PublicKeyFormat::Full),
                    )
                    .unwrap(),
                    compressed: false,
                }),
            },
            KeyFixture {
                input: "0233d78f74de8ef4a1de815b6d5c5c129c073786305c0826c499b1811c9a12ce",
                result: None,
            },
            KeyFixture {
                input: "044a83ad59dbae1e2335f488dbba5f8604d00f612a43ebaae784b5b7124cc38c3aaf509362787e1a8e25131724d57fec81b87889aabb4edf7bd89f5c4daa4f8a",
                result: None,
            },
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
                    panic!("Unexpected result: we either got a key when we didn't expect one, or didn't get a key when we did expect one.");
                }
            }
        }
    }

    #[test]
    fn test_verify() {
        let fixtures: Vec<VerifyFixture<Result<bool, &'static str>>> = vec![
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
                        &ver_res, &fixture
                    );
                }
                (_, _) => {
                    panic!(
                        "failed fixture (verification: {:?}): {:#?}",
                        &ver_res, &fixture
                    );
                }
            }
        }
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

    // -----------------------------------------------------------------------
    // MessageSignature::empty
    // -----------------------------------------------------------------------

    #[test]
    fn test_message_signature_empty() {
        let sig = MessageSignature::empty();
        // empty() is the all-zeros sentinel; recovery must fail because (r=0, s=0)
        // is not a valid ECDSA signature for any message.
        assert_eq!(sig.0, [0u8; 65]);
        let rsv = sig.to_rsv();
        assert_eq!(rsv[64], 0, "recovery ID of empty() must be 0");
        assert!(
            rsv[..64].iter().all(|&b| b == 0),
            "RS of empty() must be all zeros"
        );
        // secp256k1_recover must fail for the zero (r, s) pair
        assert!(
            super::secp256k1_recover(&[0x11u8; 32], &rsv).is_err(),
            "recovery on empty() must fail"
        );
    }

    // -----------------------------------------------------------------------
    // MessageSignature: from_secp256k1_recoverable / to_secp256k1_recoverable
    // -----------------------------------------------------------------------

    #[test]
    fn test_message_signature_recoverable_roundtrip() {
        let privk = Secp256k1PrivateKey::random();
        let msg = [0x11u8; 32];
        let sig = privk.sign(&msg).expect("sign should succeed");

        // to_secp256k1_recoverable must parse the VRS bytes correctly
        let (recovered_sig, recovered_recid) = sig
            .to_secp256k1_recoverable()
            .expect("to_secp256k1_recoverable must succeed for a freshly signed message");

        // round-trip: re-build MessageSignature and compare bytes
        let rebuilt = MessageSignature::from_secp256k1_recoverable(&recovered_sig, recovered_recid);
        assert_eq!(
            sig.as_bytes(),
            rebuilt.as_bytes(),
            "from_secp256k1_recoverable/to_secp256k1_recoverable round-trip must be identity"
        );
    }

    // -----------------------------------------------------------------------
    // MessageSignature::to_rsv
    // -----------------------------------------------------------------------

    #[test]
    fn test_message_signature_to_rsv() {
        // Known VRS vector: V=00, R=354445...cb44, S=5b97...3fe6
        let vrs = hex_bytes(
            "00354445a1dc98a1bd27984dbe69979a5cd77886b4d9134af5c40e634d96e1cb44\
             5b97de5b632582d31704f86706a780886e6e381bfed65228267358262d203fe6",
        )
        .unwrap();
        let sig = MessageSignature::from_raw(&vrs);
        let rsv = sig.to_rsv();

        assert_eq!(rsv.len(), 65);
        // First 64 bytes of RSV == bytes 1..65 of VRS (the RS part)
        assert_eq!(&rsv[..64], &vrs[1..65]);
        // Last byte of RSV == byte 0 of VRS (the recovery ID)
        assert_eq!(rsv[64], vrs[0]);
    }

    // -----------------------------------------------------------------------
    // secp256k1_der_encode / MessageSignature::to_der_signature
    // -----------------------------------------------------------------------

    #[test]
    fn test_secp256k1_der_encode_no_padding() {
        // R and S both start with a byte < 0x80 — no zero-padding needed.
        // R: 354445...cb44  (first byte 0x35)
        // S: 5b97...3fe6    (first byte 0x5b)
        let rs = hex_bytes(
            "354445a1dc98a1bd27984dbe69979a5cd77886b4d9134af5c40e634d96e1cb44\
             5b97de5b632582d31704f86706a780886e6e381bfed65228267358262d203fe6",
        )
        .unwrap();
        let compact: &[u8; 64] = rs.as_slice().try_into().unwrap();
        let der = super::secp256k1_der_encode(compact);

        // Structure: 30 <total_len> 02 <r_len> <r_bytes> 02 <s_len> <s_bytes>
        assert_eq!(der[0], 0x30, "SEQUENCE tag");
        let total_inner = der[1] as usize;
        assert_eq!(total_inner + 2, der.len(), "outer length consistent");

        assert_eq!(der[2], 0x02, "R INTEGER tag");
        let r_len = der[3] as usize;
        assert_eq!(&der[4..4 + r_len], &rs[..32], "R value");

        let s_offset = 4 + r_len;
        assert_eq!(der[s_offset], 0x02, "S INTEGER tag");
        let s_len = der[s_offset + 1] as usize;
        assert_eq!(&der[s_offset + 2..], &rs[32..], "S value");

        // Both are 32 bytes with no leading-zero padding
        assert_eq!(r_len, 32);
        assert_eq!(s_len, 32);
        assert_eq!(der.len(), 70); // 2 + 2 + 32 + 2 + 32
    }

    #[test]
    fn test_secp256k1_der_encode_with_padding() {
        // R starts with 0xff (>= 0x80) → needs a 0x00 prefix in DER.
        // S is the integer 1: stored as [0x00, 0x00, …, 0x00, 0x01] (leading zeros
        // are stripped to produce a single-byte DER INTEGER 0x01).
        let mut compact = [0u8; 64];
        compact[0] = 0xff; // R high-bit set
        compact[63] = 0x01; // S = 1 (only the last byte is non-zero)

        let der = super::secp256k1_der_encode(&compact);

        assert_eq!(der[0], 0x30);
        assert_eq!(der[2], 0x02); // R tag
        let r_len = der[3] as usize;
        assert_eq!(r_len, 33, "R must be padded to 33 bytes");
        assert_eq!(der[4], 0x00, "leading zero pad for R");
        assert_eq!(der[5], 0xff, "first real R byte");

        let s_offset = 4 + r_len;
        assert_eq!(der[s_offset], 0x02); // S tag
        let s_len = der[s_offset + 1] as usize;
        assert_eq!(s_len, 1, "leading zeros stripped: S=1 encodes as 1 byte");
        assert_eq!(der[s_offset + 2], 0x01, "S value");
    }

    #[test]
    fn test_to_der_signature_matches_der_encode() {
        let privk = Secp256k1PrivateKey::random();
        let msg = [0x22u8; 32];
        let sig = privk.sign(&msg).expect("sign should succeed");

        // to_der_signature must produce the same bytes as manually calling secp256k1_der_encode
        let der_via_method = sig
            .to_der_signature()
            .expect("to_der_signature must succeed for a valid signature");

        let (raw_sig, _recid) = sig.to_secp256k1_recoverable().unwrap();
        let der_via_fn = super::secp256k1_der_encode(&raw_sig.serialize());

        assert_eq!(der_via_method, der_via_fn);

        // Structural sanity: starts with 0x30 SEQUENCE tag
        assert_eq!(der_via_method[0], 0x30);
        assert!(
            der_via_method.len() >= 70 && der_via_method.len() <= 72,
            "DER-encoded secp256k1 sig is 70-72 bytes"
        );
    }

    #[test]
    fn test_to_der_signature_structure() {
        // to_der_signature must produce a valid SEQUENCE header for any parsed signature.
        let privk = Secp256k1PrivateKey::random();
        let sig = privk.sign(&[0x44u8; 32]).expect("sign must succeed");
        let der = sig.to_der_signature().expect("must return Some for valid sig");
        assert_eq!(der[0], 0x30, "DER SEQUENCE tag");
        assert_eq!(der.len(), der[1] as usize + 2, "DER length field consistent");
    }

    // -----------------------------------------------------------------------
    // Secp256k1PublicKey: to_bytes_compressed / compressed / set_compressed
    // -----------------------------------------------------------------------

    #[test]
    fn test_pubkey_compression_flags() {
        let privk = Secp256k1PrivateKey::random();
        let mut pubk = Secp256k1PublicKey::from_private(&privk);

        // from_private inherits the compress_public flag (default: true)
        assert!(pubk.compressed());
        assert_eq!(pubk.to_bytes().len(), 33);
        assert_eq!(pubk.to_bytes_compressed().len(), 33);
        assert_eq!(pubk.to_bytes(), pubk.to_bytes_compressed());

        pubk.set_compressed(false);
        assert!(!pubk.compressed());
        assert_eq!(pubk.to_bytes().len(), 65);
        // to_bytes_compressed must always return 33 bytes regardless of the flag
        assert_eq!(pubk.to_bytes_compressed().len(), 33);

        // Re-enabling compression must restore the 33-byte output
        pubk.set_compressed(true);
        assert_eq!(pubk.to_bytes().len(), 33);
    }

    // -----------------------------------------------------------------------
    // Secp256k1PublicKey::recover_to_pubkey
    // -----------------------------------------------------------------------

    #[test]
    fn test_recover_to_pubkey() {
        let privk = Secp256k1PrivateKey::random();
        let pubk = Secp256k1PublicKey::from_private(&privk);
        let msg = [0x33u8; 32];

        let sig = privk.sign(&msg).expect("sign should succeed");
        let recovered = Secp256k1PublicKey::recover_to_pubkey(&msg, &sig)
            .expect("recover_to_pubkey must succeed");

        assert_eq!(
            recovered.to_bytes_compressed(),
            pubk.to_bytes_compressed(),
            "recovered key must equal the signer's public key"
        );

        // recovery with wrong message must give a different key (or fail)
        let wrong_msg = [0x34u8; 32];
        let recovered_wrong = Secp256k1PublicKey::recover_to_pubkey(&wrong_msg, &sig)
            .expect("recovery on a different message still succeeds (different key)");
        assert_ne!(
            recovered_wrong.to_bytes_compressed(),
            pubk.to_bytes_compressed(),
            "recovery with wrong message must not return the original key"
        );
    }

    // -----------------------------------------------------------------------
    // Secp256k1PrivateKey::from_slice / PrivateKey::to_bytes
    // -----------------------------------------------------------------------

    #[test]
    fn test_private_key_from_slice_and_to_bytes() {
        // 32-byte slice → uncompressed key
        let raw = [0x12u8; 32];
        let sk = Secp256k1PrivateKey::from_slice(&raw).expect("32-byte slice must parse");
        assert!(!sk.compress_public());
        let bytes = sk.to_bytes();
        assert_eq!(bytes, raw, "to_bytes on uncompressed key must return the 32 raw bytes");

        // 33-byte slice with 0x01 suffix → compressed key
        let mut raw_comp = [0u8; 33];
        raw_comp[..32].copy_from_slice(&raw);
        raw_comp[32] = 0x01;
        let sk_comp =
            Secp256k1PrivateKey::from_slice(&raw_comp).expect("33-byte slice with 0x01 must parse");
        assert!(sk_comp.compress_public());
        let bytes_comp = sk_comp.to_bytes();
        assert_eq!(bytes_comp.len(), 33);
        assert_eq!(bytes_comp[32], 0x01);

        // 33-byte slice with non-0x01 suffix → error
        let mut bad_suffix = raw_comp;
        bad_suffix[32] = 0x02;
        assert!(
            Secp256k1PrivateKey::from_slice(&bad_suffix).is_err(),
            "33-byte slice with non-0x01 suffix must fail"
        );

        // Too short → error
        assert!(
            Secp256k1PrivateKey::from_slice(&raw[..31]).is_err(),
            "31-byte slice must fail"
        );

        // Too long → error
        let too_long = [0x12u8; 34];
        assert!(
            Secp256k1PrivateKey::from_slice(&too_long).is_err(),
            "34-byte slice must fail"
        );

        // All-zero bytes are not a valid secret key
        assert!(
            Secp256k1PrivateKey::from_slice(&[0u8; 32]).is_err(),
            "zero scalar must not be a valid private key"
        );
    }

    // -----------------------------------------------------------------------
    // PrivateKey::sign (non-ignored, end-to-end)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let privk = Secp256k1PrivateKey::random();
        let pubk = Secp256k1PublicKey::from_private(&privk);
        let msg = [0x55u8; 32];

        let sig = privk.sign(&msg).expect("sign must succeed");

        // Correct message → true
        assert_eq!(pubk.verify(&msg, &sig), Ok(true));

        // Tampered message → false
        let mut bad_msg = msg;
        bad_msg[0] ^= 0xff;
        assert_eq!(pubk.verify(&bad_msg, &sig), Ok(false));

        // Wrong key → false
        let other_privk = Secp256k1PrivateKey::random();
        let other_pubk = Secp256k1PublicKey::from_private(&other_privk);
        assert_eq!(other_pubk.verify(&msg, &sig), Ok(false));
    }

    // -----------------------------------------------------------------------
    // PrivateKey::sign_with_noncedata
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_with_noncedata_deterministic() {
        let privk = Secp256k1PrivateKey::random();
        let pubk = Secp256k1PublicKey::from_private(&privk);
        let msg = [0x77u8; 32];
        let nonce = [0xaau8; 32];

        let sig1 = privk
            .sign_with_noncedata(&msg, &nonce)
            .expect("sign_with_noncedata must succeed");
        let sig2 = privk
            .sign_with_noncedata(&msg, &nonce)
            .expect("second call must succeed");

        // Same inputs → identical signatures
        assert_eq!(
            sig1.as_bytes(),
            sig2.as_bytes(),
            "sign_with_noncedata must be deterministic"
        );

        // The signature must verify correctly
        assert_eq!(
            pubk.verify(&msg, &sig1),
            Ok(true),
            "signature produced by sign_with_noncedata must verify"
        );

        // Different nonce → different signature
        let other_nonce = [0xbbu8; 32];
        let sig3 = privk
            .sign_with_noncedata(&msg, &other_nonce)
            .expect("sign with different nonce must succeed");
        assert_ne!(
            sig1.as_bytes(),
            sig3.as_bytes(),
            "different nonce must produce a different signature"
        );
    }

    // -----------------------------------------------------------------------
    // secp256k1_verify
    // -----------------------------------------------------------------------

    #[test]
    fn test_secp256k1_verify_function() {
        // Use the same test vector as test_verify:
        //   pubkey  = 0385f2e2...
        //   message = sha256("hello world")
        //   VRS sig = 00354445...3fe6
        let pubkey =
            hex_bytes("0385f2e2867524289d6047d0d9c5e764c5d413729fc32291ad2c353fbc396a4219")
                .unwrap();
        let message =
            hex_bytes("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
                .unwrap();
        // secp256k1_verify takes RS (first 64 bytes); recovery ID at byte 64 is ignored
        let sig_rs = hex_bytes(
            "354445a1dc98a1bd27984dbe69979a5cd77886b4d9134af5c40e634d96e1cb44\
             5b97de5b632582d31704f86706a780886e6e381bfed65228267358262d203fe6",
        )
        .unwrap();

        // Valid signature → Ok
        assert!(
            super::secp256k1_verify(&message, &sig_rs, &pubkey).is_ok(),
            "valid sig must verify"
        );

        // Wrong message → Err
        let mut bad_msg = message.clone();
        bad_msg[0] ^= 0xff;
        assert!(
            super::secp256k1_verify(&bad_msg, &sig_rs, &pubkey).is_err(),
            "wrong message must fail"
        );

        // Wrong pubkey → Err
        let other_privk = Secp256k1PrivateKey::random();
        let other_pubk = Secp256k1PublicKey::from_private(&other_privk);
        assert!(
            super::secp256k1_verify(&message, &sig_rs, &other_pubk.to_bytes_compressed()).is_err(),
            "wrong pubkey must fail"
        );

        // High-S signature → Err (low-S is enforced)
        let high_s_sig = hex_bytes(
            "54cd3f378a424a3e50ff1c911b7d80cf424e1b86dddecadbcf39077e62fa1e54\
             ee6514347c1608df2c3995e7356f2d60a1fab60878214642134d78cd923ce27a",
        )
        .unwrap();
        let high_s_msg =
            hex_bytes("89171d7815da4bc1f644665a3234bc99d1680afa0b3285eff4878f4275fbfa89")
                .unwrap();
        let high_s_pubkey =
            hex_bytes("0256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967")
                .unwrap();
        assert!(
            super::secp256k1_verify(&high_s_msg, &high_s_sig, &high_s_pubkey).is_err(),
            "high-S signature must be rejected by secp256k1_verify"
        );
    }

    // -----------------------------------------------------------------------
    // Hash impl for Secp256k1PublicKey
    // -----------------------------------------------------------------------

    #[test]
    fn test_pubkey_hash_usable_as_map_key() {
        use std::collections::HashMap;

        let privk1 = Secp256k1PrivateKey::from_seed(b"key-one");
        let privk2 = Secp256k1PrivateKey::from_seed(b"key-two");
        let pubk1 = Secp256k1PublicKey::from_private(&privk1);
        let pubk2 = Secp256k1PublicKey::from_private(&privk2);

        let mut map: HashMap<Secp256k1PublicKey, u32> = HashMap::new();
        map.insert(pubk1.clone(), 1);
        map.insert(pubk2.clone(), 2);

        assert_eq!(map[&pubk1], 1);
        assert_eq!(map[&pubk2], 2);

        // A key with a different compressed flag but same underlying point hashes differently
        let mut pubk1_uncomp = pubk1.clone();
        pubk1_uncomp.set_compressed(false);
        assert_ne!(
            map.get(&pubk1_uncomp),
            Some(&1),
            "different compressed flag changes the hash"
        );
    }
}
