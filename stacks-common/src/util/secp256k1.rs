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

use secp256k1;
use secp256k1::constants as LibSecp256k1Constants;
use secp256k1::ecdsa::RecoverableSignature as LibSecp256k1RecoverableSignature;
use secp256k1::ecdsa::RecoveryId as LibSecp256k1RecoveryID;
use secp256k1::ecdsa::Signature as LibSecp256k1Signature;
use secp256k1::schnorr::Signature as LibSecp256k1SchnorrSignature;
use secp256k1::Error as LibSecp256k1Error;
use secp256k1::Message as LibSecp256k1Message;
use secp256k1::PublicKey as LibSecp256k1PublicKey;
use secp256k1::XOnlyPublicKey as LibSecp256k1XOnlyPublicKey;
use secp256k1::Secp256k1;
use secp256k1::SecretKey as LibSecp256k1PrivateKey;

use crate::types::PrivateKey;
use crate::types::PublicKey;
use crate::types::XOnlyPublicKey;
use crate::util::hash::{hex_bytes, to_hex};

use serde::de::Deserialize;
use serde::de::Error as de_Error;
use serde::ser::Error as ser_Error;
use serde::Serialize;

use rand::thread_rng;
use rand::RngCore;

// per-thread Secp256k1 context
thread_local!(static _secp256k1: Secp256k1<secp256k1::All> = Secp256k1::new());

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct Secp256k1PublicKey {
    // serde is broken for secp256k1, so do it ourselves
    #[serde(
        serialize_with = "secp256k1_pubkey_serialize",
        deserialize_with = "secp256k1_pubkey_deserialize"
    )]
    key: LibSecp256k1PublicKey,
    compressed: bool,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct Secp256k1XOnlyPublicKey {
    // serde is broken for secp256k1, so do it ourselves
    #[serde(
    serialize_with = "secp256k1_xonly_pubkey_serialize",
    deserialize_with = "secp256k1_xonly_pubkey_deserialize"
    )]
    key: LibSecp256k1XOnlyPublicKey
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

pub struct MessageSignature(pub [u8; 65]);
impl_array_newtype!(MessageSignature, u8, 65);
impl_array_hexstring_fmt!(MessageSignature);
impl_byte_array_newtype!(MessageSignature, u8, 65);
impl_byte_array_serde!(MessageSignature);
pub const MESSAGE_SIGNATURE_ENCODED_SIZE: u32 = 65;

impl MessageSignature {
    pub fn empty() -> MessageSignature {
        // NOTE: this cannot be a valid signature
        MessageSignature([0u8; 65])
    }

    #[cfg(any(test, feature = "testing"))]
    // test method for generating place-holder data
    pub fn from_raw(sig: &Vec<u8>) -> MessageSignature {
        let mut buf = [0u8; 65];
        if sig.len() < 65 {
            buf[..sig.len()].copy_from_slice(&sig[..]);
        } else {
            buf.copy_from_slice(&sig[..65]);
        }

        MessageSignature(buf)
    }

    pub fn from_secp256k1_recoverable(sig: &LibSecp256k1RecoverableSignature) -> MessageSignature {
        let (recid, bytes) = sig.serialize_compact();
        let mut ret_bytes = [0u8; 65];
        let recovery_id_byte = recid.to_i32() as u8; // recovery ID will be 0, 1, 2, or 3
        ret_bytes[0] = recovery_id_byte;
        for i in 0..64 {
            ret_bytes[i + 1] = bytes[i];
        }
        MessageSignature(ret_bytes)
    }

    pub fn to_secp256k1_recoverable(&self) -> Option<LibSecp256k1RecoverableSignature> {
        let recid = match LibSecp256k1RecoveryID::from_i32(self.0[0] as i32) {
            Ok(rid) => rid,
            Err(_) => {
                return None;
            }
        };
        let mut sig_bytes = [0u8; 64];
        for i in 0..64 {
            sig_bytes[i] = self.0[i + 1];
        }

        match LibSecp256k1RecoverableSignature::from_compact(&sig_bytes, recid) {
            Ok(sig) => Some(sig),
            Err(_) => None,
        }
    }

    pub fn to_secp256k1_schnorr(&self) -> Option<LibSecp256k1SchnorrSignature> {
        match LibSecp256k1SchnorrSignature::from_slice(&self.0[..64]) {
            Ok(sig) => Some(sig),
            Err(_) => None
        }
    }
}

impl Secp256k1PublicKey {
    #[cfg(any(test, feature = "testing"))]
    pub fn new() -> Secp256k1PublicKey {
        Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::new())
    }

    pub fn from_hex(hex_string: &str) -> Result<Secp256k1PublicKey, &'static str> {
        let data = hex_bytes(hex_string).map_err(|_e| "Failed to decode hex public key")?;
        Secp256k1PublicKey::from_slice(&data[..]).map_err(|_e| "Invalid public key hex string")
    }

    pub fn from_slice(data: &[u8]) -> Result<Secp256k1PublicKey, &'static str> {
        match LibSecp256k1PublicKey::from_slice(data) {
            Ok(pubkey_res) => Ok(Secp256k1PublicKey {
                key: pubkey_res,
                compressed: data.len() == LibSecp256k1Constants::PUBLIC_KEY_SIZE,
            }),
            Err(_e) => Err("Invalid public key: failed to load"),
        }
    }

    pub fn from_private(privk: &Secp256k1PrivateKey) -> Secp256k1PublicKey {
        _secp256k1.with(|ctx| {
            let pubk = LibSecp256k1PublicKey::from_secret_key(&ctx, &privk.key);
            Secp256k1PublicKey {
                key: pubk,
                compressed: privk.compress_public,
            }
        })
    }

    pub fn to_hex(&self) -> String {
        to_hex(&self.to_bytes())
    }

    pub fn to_bytes_compressed(&self) -> Vec<u8> {
        self.key.serialize().to_vec()
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
        _secp256k1.with(|ctx| {
            let msg = LibSecp256k1Message::from_slice(msg).map_err(|_e| {
                "Invalid message: failed to decode data hash: must be a 32-byte hash"
            })?;

            let secp256k1_sig = sig
                .to_secp256k1_recoverable()
                .ok_or("Invalid signature: failed to decode recoverable signature")?;

            let recovered_pubkey = ctx
                .recover_ecdsa(&msg, &secp256k1_sig)
                .map_err(|_e| "Invalid signature: failed to recover public key")?;

            Ok(Secp256k1PublicKey {
                key: recovered_pubkey,
                compressed: true,
            })
        })
    }

    // for benchmarking
    #[cfg(test)]
    pub fn recover_benchmark(
        msg: &LibSecp256k1Message,
        sig: &LibSecp256k1RecoverableSignature,
    ) -> Result<LibSecp256k1PublicKey, &'static str> {
        _secp256k1.with(|ctx| {
            ctx.recover_ecdsa(msg, sig)
                .map_err(|_e| "Invalid signature: failed to recover public key")
        })
    }
}

impl Secp256k1XOnlyPublicKey {
    pub fn new() -> Secp256k1XOnlyPublicKey {
        Secp256k1XOnlyPublicKey::from_private(&Secp256k1PrivateKey::new())
    }

    pub fn from_hex(hex_string: &str) -> Result<Secp256k1XOnlyPublicKey, &'static str> {
        let data = hex_bytes(hex_string).map_err(|_e| "Failed to decode hex public key")?;
        Secp256k1XOnlyPublicKey::from_slice(&data[..]).map_err(|_e| "Invalid xonly public key hex string")
    }

    pub fn from_slice(data: &[u8]) -> Result<Secp256k1XOnlyPublicKey, &'static str> {
        match LibSecp256k1XOnlyPublicKey::from_slice(data) {
            Ok(pubkey_res) => Ok(Secp256k1XOnlyPublicKey {
                key: pubkey_res
            }),
            Err(_e) => Err("Invalid public key: failed to load"),
        }
    }

    pub fn from_private(privk: &Secp256k1PrivateKey) -> Secp256k1XOnlyPublicKey {
        _secp256k1.with(|ctx| {
            let pubk = LibSecp256k1PublicKey::from_secret_key(&ctx, &privk.key);

            Secp256k1XOnlyPublicKey {
                key: pubk.x_only_public_key().0
            }
        })
    }

    pub fn to_hex(&self) -> String {
        to_hex(&self.to_bytes())
    }
}

impl PublicKey for Secp256k1PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        if self.compressed {
            self.key.serialize().to_vec()
        } else {
            self.key.serialize_uncompressed().to_vec()
        }
    }

    fn verify(&self, data_hash: &[u8], sig: &MessageSignature) -> Result<bool, &'static str> {
        _secp256k1.with(|ctx| {
            let msg = LibSecp256k1Message::from_slice(data_hash).map_err(|_e| {
                "Invalid message: failed to decode data hash: must be a 32-byte hash"
            })?;

            let secp256k1_sig = sig
                .to_secp256k1_recoverable()
                .ok_or("Invalid signature: failed to decode recoverable signature")?;

            let recovered_pubkey = ctx
                .recover_ecdsa(&msg, &secp256k1_sig)
                .map_err(|_e| "Invalid signature: failed to recover public key")?;

            if recovered_pubkey != self.key {
                test_debug!("{:?} != {:?}", &recovered_pubkey, &self.key);
                return Ok(false);
            }

            // NOTE: libsecp256k1 _should_ ensure that the S is low,
            // but add this check just to be safe.
            let secp256k1_sig_standard = secp256k1_sig.to_standard();

            // must be low-S
            let mut secp256k1_sig_low_s = secp256k1_sig_standard.clone();
            secp256k1_sig_low_s.normalize_s();
            if secp256k1_sig_low_s != secp256k1_sig_standard {
                return Err("Invalid signature: high-S");
            }

            Ok(true)
        })
    }
}

impl XOnlyPublicKey for Secp256k1XOnlyPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.key.serialize().to_vec()
    }

    fn verify(&self, data_hash: &[u8], sig: &MessageSignature) -> Result<bool, &'static str> {
        _secp256k1.with(|ctx| {
            let msg = LibSecp256k1Message::from_slice(data_hash).map_err(|_e| {
                "Invalid message: failed to decode data hash: must be a 32-byte hash"
            })?;

            let secp256k1_sig = sig
                .to_secp256k1_schnorr()
                .ok_or("Invalid signature: failed to decode signature")?;

            match ctx.verify_schnorr(&secp256k1_sig, &msg, &self.key) {
                Ok(_) => Ok(true),
                Err(E) => Ok(false)
            }
        })
    }
}

impl Secp256k1PrivateKey {
    pub fn new() -> Secp256k1PrivateKey {
        let mut rng = rand::thread_rng();
        loop {
            // keep trying to generate valid bytes
            let mut random_32_bytes = [0u8; 32];
            rng.fill_bytes(&mut random_32_bytes);
            let pk_res = LibSecp256k1PrivateKey::from_slice(&random_32_bytes);
            match pk_res {
                Ok(pk) => {
                    return Secp256k1PrivateKey {
                        key: pk,
                        compress_public: true,
                    };
                }
                Err(_) => {
                    continue;
                }
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
        match LibSecp256k1PrivateKey::from_slice(&data[0..32]) {
            Ok(privkey_res) => Ok(Secp256k1PrivateKey {
                key: privkey_res,
                compress_public: compress_public,
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
        let mut bytes = self.key[..].to_vec();
        if self.compress_public {
            bytes.push(1);
        }
        to_hex(&bytes)
    }
}

impl PrivateKey for Secp256k1PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bits = self.key[..].to_vec();
        if self.compress_public {
            bits.push(0x01);
        }
        bits
    }

    fn sign(&self, data_hash: &[u8]) -> Result<MessageSignature, &'static str> {
        _secp256k1.with(|ctx| {
            let msg = LibSecp256k1Message::from_slice(data_hash).map_err(|_e| {
                "Invalid message: failed to decode data hash: must be a 32-byte hash"
            })?;

            let sig = ctx.sign_ecdsa_recoverable(&msg, &self.key);
            Ok(MessageSignature::from_secp256k1_recoverable(&sig))
        })
    }
}

fn secp256k1_pubkey_serialize<S: serde::Serializer>(
    pubk: &LibSecp256k1PublicKey,
    s: S,
) -> Result<S::Ok, S::Error> {
    let key_hex = to_hex(&pubk.serialize().to_vec());
    s.serialize_str(&key_hex.as_str())
}

fn secp256k1_pubkey_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<LibSecp256k1PublicKey, D::Error> {
    let key_hex = String::deserialize(d)?;
    let key_bytes = hex_bytes(&key_hex).map_err(de_Error::custom)?;

    LibSecp256k1PublicKey::from_slice(&key_bytes[..]).map_err(de_Error::custom)
}

fn secp256k1_privkey_serialize<S: serde::Serializer>(
    privk: &LibSecp256k1PrivateKey,
    s: S,
) -> Result<S::Ok, S::Error> {
    let key_hex = to_hex(&privk[..].to_vec());
    s.serialize_str(&key_hex.as_str())
}

fn secp256k1_privkey_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<LibSecp256k1PrivateKey, D::Error> {
    let key_hex = String::deserialize(d)?;
    let key_bytes = hex_bytes(&key_hex).map_err(de_Error::custom)?;

    LibSecp256k1PrivateKey::from_slice(&key_bytes[..]).map_err(de_Error::custom)
}

pub fn secp256k1_recover(
    message_arr: &[u8],
    serialized_signature_arr: &[u8],
) -> Result<[u8; 33], LibSecp256k1Error> {
    _secp256k1.with(|ctx| {
        let message = LibSecp256k1Message::from_slice(message_arr)?;

        let rec_id = LibSecp256k1RecoveryID::from_i32(serialized_signature_arr[64] as i32)?;
        let recovered_sig = LibSecp256k1RecoverableSignature::from_compact(
            &serialized_signature_arr[..64],
            rec_id,
        )?;
        let recovered_pub = ctx.recover_ecdsa(&message, &recovered_sig)?;
        let recovered_serialized = recovered_pub.serialize(); // 33 bytes version

        Ok(recovered_serialized)
    })
}

pub fn secp256k1_verify(
    message_arr: &[u8],
    serialized_signature_arr: &[u8],
    pubkey_arr: &[u8],
) -> Result<(), LibSecp256k1Error> {
    _secp256k1.with(|ctx| {
        let message = LibSecp256k1Message::from_slice(message_arr)?;
        let expanded_sig = LibSecp256k1Signature::from_compact(&serialized_signature_arr[..64])?; // ignore 65th byte if present
        let pubkey = LibSecp256k1PublicKey::from_slice(pubkey_arr)?;
        ctx.verify_ecdsa(&message, &expanded_sig, &pubkey)
    })
}

fn secp256k1_xonly_pubkey_serialize<S: serde::Serializer>(
    pubk: &LibSecp256k1XOnlyPublicKey,
    s: S,
) -> Result<S::Ok, S::Error> {
    let key_hex = to_hex(&pubk.serialize().to_vec());
    s.serialize_str(&key_hex.as_str())
}

fn secp256k1_xonly_pubkey_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<LibSecp256k1XOnlyPublicKey, D::Error> {
    let key_hex = String::deserialize(d)?;
    let key_bytes = hex_bytes(&key_hex).map_err(de_Error::custom)?;

    LibSecp256k1XOnlyPublicKey::from_slice(&key_bytes[..]).map_err(de_Error::custom)
}

pub fn schnorr_verify(
    message_arr: &[u8],
    serialized_signature_arr: &[u8],
    pubkey_arr: &[u8],
) -> Result<(), LibSecp256k1Error> {

    _secp256k1.with(|ctx| {
        let message = LibSecp256k1Message::from_slice(message_arr)?;
        let expanded_sig = LibSecp256k1SchnorrSignature::from_slice(&serialized_signature_arr[..64])?; // ignore 65th byte if present
        let pubkey = LibSecp256k1XOnlyPublicKey::from_slice(pubkey_arr)?;

        ctx.verify_schnorr(&expanded_sig, &message, &pubkey)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::util::hash::hex_bytes;

    use secp256k1;
    use secp256k1::PublicKey as LibSecp256k1PublicKey;
    use secp256k1::Secp256k1;

    use crate::util::get_epoch_time_ms;
    use crate::util::log;

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
        let mut t1 = Secp256k1PrivateKey::new();
        t1.set_compress_public(true);
        let h_comp = t1.to_hex();
        t1.set_compress_public(false);
        let h_uncomp = t1.to_hex();

        assert!(&h_comp != &h_uncomp);
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

        assert_eq!(Secp256k1PrivateKey::from_hex(&h_uncomp), Ok(t1));

        t1.set_compress_public(true);

        assert_eq!(Secp256k1PrivateKey::from_hex(&h_comp), Ok(t1));
    }

    #[test]
    fn test_parse_serialize() {
        let ctx: Secp256k1<secp256k1::All> = Secp256k1::new();
        let fixtures = vec![
            KeyFixture {
                input: "0233d78f74de8ef4a1de815b6d5c5c129c073786305c0826c499b1811c9a12cee5",
                result: Some(Secp256k1PublicKey {
                    key: LibSecp256k1PublicKey::from_slice(&hex_bytes("0233d78f74de8ef4a1de815b6d5c5c129c073786305c0826c499b1811c9a12cee5").unwrap()[..]).unwrap(),
                    compressed: true
                })
            },
            KeyFixture {
                input: "044a83ad59dbae1e2335f488dbba5f8604d00f612a43ebaae784b5b7124cc38c3aaf509362787e1a8e25131724d57fec81b87889aabb4edf7bd89f5c4daa4f8aa7",
                result: Some(Secp256k1PublicKey {
                    key: LibSecp256k1PublicKey::from_slice(&hex_bytes("044a83ad59dbae1e2335f488dbba5f8604d00f612a43ebaae784b5b7124cc38c3aaf509362787e1a8e25131724d57fec81b87889aabb4edf7bd89f5c4daa4f8aa7").unwrap()[..]).unwrap(),
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
                    assert!(false);
                }
            }
        }
    }

    #[test]
    fn test_secp256k1_verify() {
        let _ctx: Secp256k1<secp256k1::All> = Secp256k1::new();
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
                    eprintln!(
                        "failed fixture (verification: {:?}): {:#?}",
                        &ver_res, &fixture
                    );
                    assert!(false);
                }
                (_, _) => {
                    eprintln!(
                        "failed fixture (verification: {:?}): {:#?}",
                        &ver_res, &fixture
                    );
                    assert!(false);
                }
            }
        }
    }

    #[test]
    fn test_schnorr_verify() {
        let _ctx: Secp256k1<secp256k1::All> = Secp256k1::new();
        let fixtures : Vec<VerifyFixture<Result<bool, &'static str>>> = vec![
            VerifyFixture {
                public_key: "903336626d211c6a88ae35d210a3958cc99f306ba4646685ca97e22abad8591a",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "c46e79d770b9f5aea40451ac0da0d524ec81500a4b4ea38454f3a429003be9b52ee2de0a52a64b2b1d6fa443a7c87181605f9bba0ab674b4bd12b89621bc4ecc",
                result: Ok(true),
            },
            VerifyFixture {
                public_key: "6344ba6755d0dbdc63c5aa1fb511724ddcaa6e85ccdbc986e84586490dbf5c24",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "308755447c5e4b28147031b57c66ad1296032c0ef6aab8a07265f707c86f4597fdf009814470017f0ddc336330cb96720a237c80fa56c3dc0e37f74da3af6c47",
                result: Ok(true),
            },
            VerifyFixture {
                public_key: "8b90e9f86cf49331f59f249375367dc0d22cc4a21006be7dfee32b16154ffcd1",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "957dce5ed362b138810182b36888486a3e6639034e3213b673eaab6c3322d3a3793a20557d90fb4c6075d8e782075acb436f83b497cd5b6fbed9f610c6bf4400",
                result: Ok(true),
            },
            VerifyFixture {
                public_key: "f2d5c59bf48111223215ab605e96a2c0f35705fa6bf8f1dbbc3c2cb3300b48dc",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "d02a79a3387e25892b3e4961046942c150ffd6999b4bb858677ebd7ff06221c53dc3e843030bba0fa93d147a4d76780d4924c8fbbb5ef02993cbe3871ed8bdc1",
                result: Ok(true),
            },
            VerifyFixture {
                public_key: "593bb41d1dc7c4bce98f262c89c9f5851175013ae7dfba2ea0b5e872b8172a3c",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "75ae55876029d7277cf32adb0f0b0476d1f59e0b3de0b6688cb044470d18bd386037f8e8d8a1ef090362d7915990f7f7329efe56b8e34ebc3bfdc5225e2bf3d1",
                result: Ok(true),
            },
            VerifyFixture {
                public_key: "30760f874055b09a765952dc8d96120e16402cdbd34ef2617fe9728b08080db6",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "92a381fddc7f23eb3bf7f6a145094aea029b1b097fde26f945e5ed4ea32df49631f4d8295d4df84b170e3250b5779cf395ab21fe16e238f43a78b498f9e91c8d",
                result: Ok(true),
            },
            VerifyFixture {
                public_key: "c709c155e6de596059c510986ab303ad46c9f8501101a5380856bf12fea81e1c",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "a287c952e54f352aecb36be890716392c36a69e886cb1e96dd6152fe854ae0672e1c5a0f64867e18317b5828dbc13c9ee6bd614767624a56e607c0b7981b2cad", // wrong sig (bad recovery)
                result: Ok(false),
            },
            VerifyFixture {
                public_key: "053c621fb6df223777f912f4bb4493f95edef6e7bfacb0e237a882430c2867fa",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "cf6151aeb7a8a3771468eae5f08c1ce10fe0c3f041b1496a5928361bec83daf7b719c867258b5b14a7b4c2792912e15a7dbf2c506fd9a44e04f1bf35f3720840", // wrong sig (bad recovery)
                result: Ok(false),
            },
            VerifyFixture {
                public_key: "a88e4836571d7f6b680f3d6bf5d6ae35584f8441d2529231605731b54c6cf15c",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "5013e42dd549b25777291bea14fda973e646fbe22915040853db5192fb9d5e31d496d5499ba0f484f9305ae623c1eb1a4453621229fff68f8ea317d586edafbc", // wrong sig (bad recovery)
                result: Ok(false),
            },
            VerifyFixture {
                public_key: "9827c0ae8d0eb4829e8d7e867e64e0b5362e6e8c89248118068b92ccc9c81780",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "b3dbe30c1cad8a533e8f8f5dbe8509be01be7a69475c92a3fe91f6d779c267f198644479b53fad93c660fc628b0cc4dcba10593b094b6c19b9e9f0c034bcec9d", // wrong sig (bad recovery)
                result: Ok(false),
            },
            VerifyFixture {
                public_key: "5c7220c5dd51165134a3d2c3a484990afaab491d946baf286d76b71272161750",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "5d442c1fb9fe01aecc5e9a0770d4a73b90136f50f1daa9d9019fa1cfe007ffe8352eb28474c4313ce9f54f6340f3bae18a2d53878da6bd46c62aea044d3c8e32", // wrong sig (bad recovery)
                result: Ok(false),
            },
            VerifyFixture {
                public_key: "8df1a528a75127ae6db6dfcc33c691592ccc20664882632cffcb91ba76ab066a",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "89cd688914c1ce790628ca84571fd83004f4d6ece403865c4a28f06c6a672b1d2e9658fb8e49760972972b3582319fe5c75b6a24eb201b69d5a73fa4ed2b20a8", // bad s
                result: Ok(false),
            },
            VerifyFixture {
                public_key: "5d98ac1465ba641f31c980efc78b6ce968cd1ea78f1c0bd4542f44fd569984a7",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "7e6cd2b6b1f0a233a5e8f135a1041b0deeb53e39b43f9cebf1a42072a360cea33fb26becf5684ec2e705b6081208875050e4c972453ddbf88f22435d89b329e4", // bad s
                result: Ok(false),
            },
            VerifyFixture {
                public_key: "451bc8bd2342e0637b8c71a16b9f943c1b791f726afdd9bf29ade51fb2c0a417",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "2209d881621da775afe04f9511e9985520a7c4becc57cc5d33842767e3a0796c355cc7fa9e8d5710d669a7e293237b0da59342595835b2e9a7e4e3fa1614ebcf", // bad s
                result: Ok(false),
            },
            VerifyFixture {
                public_key: "e6a9a2db3fcd696e49b1fc0a3e706c356dd4315736465bac4ee994e4e35e0a8f",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "bc9916cdae5fa21f7d4aea7cafa544c8f3fc656b6ef33a98887893249f210d8c454269bb3445ec3bd6bb6e31c327049c8359ac1207a1e186c418243cfe06bfa8", // bad r
                result: Ok(false),
            },
            VerifyFixture {
                public_key: "e3361636d32e10e883734af0573f4452d4f01a55c4f9f36a3d622c45b8e5bfaf",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "e38aff4ed424a62ecbaacc05e0bafb2dadbf91f5d7f3e85ae7a18e01e42b451e1e5efe1568a9383f3a193a5d54f9fa5e13ddd688b33ea82f574201c52a6ee76d", // bad r
                result: Ok(false),
            },
            VerifyFixture {
                public_key: "a4b470c46bf2e2302422278875e177068c6ff7fe5d6826a48f713bb1128e4e78",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                signature: "b3484151a37b49f952c4122cfe606eb525b36dde2da0a820ba7c145835399fb95d71ead53c75825dc0be69e860bc507c33dd69bc0f3aa186916eb66ac4f0effa", // bad r
                result: Ok(false),
            }
        ];

        for fixture in fixtures {
            let key = Secp256k1XOnlyPublicKey::from_hex(fixture.public_key).unwrap();
            let signature = MessageSignature::from_raw(&hex_bytes(fixture.signature).unwrap());
            let ver_res = key.verify(&hex_bytes(fixture.data).unwrap(), &signature);

            match (ver_res, fixture.result) {
                (Ok(true), Ok(true)) => {}
                (Ok(false), Ok(false)) => {}
                (Err(e1), Err(e2)) => assert_eq!(e1, e2),
                (Err(e1), _) => {
                    test_debug!("Failed to verify signature: {}", e1);
                    eprintln!(
                        "failed fixture (verification: {:?}): {:#?}",
                        &ver_res, &fixture
                    );
                    assert!(false);
                }
                (_, _) => {
                    eprintln!(
                        "failed fixture (verification: {:?}): {:#?}",
                        &ver_res, &fixture
                    );
                    assert!(false);
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

        for i in 0..100 {
            let privk = Secp256k1PrivateKey::new();
            let pubk = Secp256k1PublicKey::from_private(&privk);

            let mut msg = [0u8; 32];
            rng.fill_bytes(&mut msg);

            let sign_start = get_epoch_time_ms();
            for i in 0..1000 {
                let sig = privk.sign(&msg).unwrap();
            }
            let sign_end = get_epoch_time_ms();

            let sig = privk.sign(&msg).unwrap();
            let secp256k1_msg = LibSecp256k1Message::from_slice(&msg).unwrap();
            let secp256k1_sig = sig.to_secp256k1_recoverable().unwrap();

            let recovered_pubk =
                Secp256k1PublicKey::recover_benchmark(&secp256k1_msg, &secp256k1_sig).unwrap();
            assert_eq!(recovered_pubk, pubk.key);

            let recover_start = get_epoch_time_ms();
            for i in 0..1000 {
                let recovered_pubk =
                    Secp256k1PublicKey::recover_benchmark(&secp256k1_msg, &secp256k1_sig).unwrap();
            }
            let recover_end = get_epoch_time_ms();

            let verify_start = get_epoch_time_ms();
            for i in 0..1000 {
                let valid = pubk.verify(&msg, &sig).unwrap();
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
}
