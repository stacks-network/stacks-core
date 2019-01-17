/*
 copyright: (c) 2013-2018 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

use secp256k1;
use secp256k1::Secp256k1;
use secp256k1::constants as Secp256k1Constants;
use secp256k1::PublicKey as Secp256k1PublicKey;
use secp256k1::Message as Secp256k1Message;
use secp256k1::Signature as Secp256k1Signature;
use secp256k1::Error as Secp256k1Error;

use burnchains::PublicKey;
use util::hash::{hex_bytes, to_hex};

use serde::de::{Deserialize, Deserializer};
use serde::de::Error as de_Error;
use serde::ser::{Serialize, Serializer};

// per-thread Secp256k1 context
use std::cell::RefCell;
thread_local!(static _secp256k1: Secp256k1<secp256k1::All> = Secp256k1::new());

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub struct BitcoinPublicKey {
    // serde is broken for secp256k1, so do it ourselves
    #[serde(serialize_with = "serialize_secp256k1_pubkey", deserialize_with = "deserialize_secp256k1_pubkey")]
    key: Secp256k1PublicKey,
    compressed: bool
}

impl BitcoinPublicKey {
    pub fn from_hex(hex_string: &str) -> Result<BitcoinPublicKey, &'static str> {
        hex_bytes(hex_string)
            .and_then(|vec_bytes| BitcoinPublicKey::from_slice(&vec_bytes[..]))
            .map_err(|_e| "Invalid hex string")
    }
    
    pub fn from_slice(data: &[u8]) -> Result<BitcoinPublicKey, &'static str> {
        _secp256k1.with(|ctx| {
            match Secp256k1PublicKey::from_slice(&ctx, data) {
                Ok(pubkey_res) => 
                    Ok(BitcoinPublicKey {
                        key: pubkey_res,
                        compressed: data.len() == Secp256k1Constants::PUBLIC_KEY_SIZE
                    }),
                Err(_e) => Err("Invalid public key: failed to load")
            }
        })
    }
}

impl PublicKey for BitcoinPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        if self.compressed {
            self.key.serialize().to_vec()
        }
        else {
            self.key.serialize_uncompressed().to_vec()
        }
    }

    fn verify(&self, data_hash: &[u8], sig_der: &[u8]) -> Result<bool, &'static str> {
        _secp256k1.with(|ctx| {
            let msg = Secp256k1Message::from_slice(data_hash)
                .map_err(|_e| "Invalid message: failed to decode data hash: must be a 32-byte hash")?;

            let sig = Secp256k1Signature::from_der(ctx, sig_der)
                .map_err(|_e| "Invalid signature: failed to decode signature: must be DER-encoded")?;

            let v = ctx.verify(&msg, &sig, &self.key);
            return match v {
                Ok(()) => Ok(true),
                Err(e) => 
                    match e {
                        Secp256k1Error::IncorrectSignature => Ok(false),
                        _ => Err("Failed to process public key or signature")
                    }
            };
        })
    }
}

fn serialize_secp256k1_pubkey<S: serde::Serializer>(pubk: &Secp256k1PublicKey, s: S) -> Result<S::Ok, S::Error> {
    let key_hex = to_hex(&pubk.serialize().to_vec());
    s.serialize_str(&key_hex.as_str())
}

fn deserialize_secp256k1_pubkey<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Secp256k1PublicKey, D::Error> {
    let key_hex = String::deserialize(d)?;
    let key_bytes = hex_bytes(&key_hex)
        .map_err(de_Error::custom)?;

    _secp256k1.with(|ctx| {
        Secp256k1PublicKey::from_slice(&ctx, &key_bytes[..])
            .map_err(de_Error::custom)
    })
}

#[cfg(test)]
mod tests {
    use util::hash::hex_bytes;

    use secp256k1;
    use secp256k1::Secp256k1;
    use secp256k1::constants as Secp256k1Constants;
    use secp256k1::PublicKey as Secp256k1PublicKey;
    use secp256k1::Message as Secp256k1Message;
    use secp256k1::Signature as Secp256k1Signature;
    use secp256k1::Error as Secp256k1Error;
    use burnchains::PublicKey;
    use burnchains::bitcoin::keys::BitcoinPublicKey;

    use util::log as logger;

    struct KeyFixture<I, R> {
        input: I,
        result: R
    }

    struct VerifyFixture<R> {
        public_key: &'static str,
        data: &'static str,
        signature: &'static str,
        result: R
    }

    #[test]
    fn test_parse_serialize() {
        let ctx : Secp256k1<secp256k1::All> = Secp256k1::new();
        let fixtures = vec![
            KeyFixture {
                input: "0233d78f74de8ef4a1de815b6d5c5c129c073786305c0826c499b1811c9a12cee5",
                result: Some(BitcoinPublicKey {
                    key: Secp256k1PublicKey::from_slice(&ctx, &hex_bytes("0233d78f74de8ef4a1de815b6d5c5c129c073786305c0826c499b1811c9a12cee5").unwrap()[..]).unwrap(),
                    compressed: true
                })
            },
            KeyFixture {
                input: "044a83ad59dbae1e2335f488dbba5f8604d00f612a43ebaae784b5b7124cc38c3aaf509362787e1a8e25131724d57fec81b87889aabb4edf7bd89f5c4daa4f8aa7",
                result: Some(BitcoinPublicKey {
                    key: Secp256k1PublicKey::from_slice(&ctx, &hex_bytes("044a83ad59dbae1e2335f488dbba5f8604d00f612a43ebaae784b5b7124cc38c3aaf509362787e1a8e25131724d57fec81b87889aabb4edf7bd89f5c4daa4f8aa7").unwrap()[..]).unwrap(),
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
            let key_res = BitcoinPublicKey::from_hex(fixture.input);
            match (key_res, fixture.result) {
                (Ok(key), Some(key_result)) => {
                    assert_eq!(key, key_result);

                    let key_from_slice = BitcoinPublicKey::from_slice(&hex_bytes(fixture.input).unwrap()[..]).unwrap();
                    assert_eq!(key_from_slice, key_result);

                    let key_bytes = key.to_bytes();
                    assert_eq!(key_bytes, hex_bytes(fixture.input).unwrap());
                },
                (Err(_e), None) => {},
                (_, _) => {
                    // either got a key when we didn't expect one, or didn't get a key when we did
                    // expect one.
                    assert!(false);
                }
            }
        }
    }

    #[test]
    fn test_verify() {
        let ctx : Secp256k1<secp256k1::All> = Secp256k1::new();
        let fixtures : Vec<VerifyFixture<Result<bool, &'static str>>> = vec![
            VerifyFixture {
                public_key: "034c35b09b758678165d6ed84a50b329900c99986cf8e9a358ceae0d03af91f5b6",
                signature: "3045022100853ae0bca72d59aaa335ff967f062952348baf7cc03cd1cb60db21eda6c1fecc0220551afcbcfb81a3f2adba18608d474bf296cccc82d8fca9f2bbd1fea96b4b71dc",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",       // sha256 hash of "hello world"
                result: Ok(true)
            },
            VerifyFixture {
                public_key: "034c35b09b758678165d6ed84a50b329900c99986cf8e9a358ceae0d03af91f5b6",
                signature: "3045022100853ae0bca72d59aaa335ff967f062952348baf7cc03cd1cb60db21eda6c1fecc0220551afcbcfb81a3f2adba18608d474bf296cccc82d8fca9f2bbd1fea96b4b71dc",
                data: "ca3704aa0b06f5954c79ee837faa152d84d6b2d42838f0637a15eda8337dbdce",       // sha256 hash of "nope"
                result: Ok(false)
            },
            VerifyFixture {
                public_key: "034c35b09b758678165d6ed84a50b329900c99986cf8e9a358ceae0d03af91f5b6",   // wrong key
                signature: "3045022100be57031bf2c095945ba2876e97b3f86ee051643a29b908f22ed45ccf58620103022061e056e5f48c5a51c66604a1ca28e4bfaabab1478424c9bbb396cc6afe5c222e",
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",       // sha256 hash of "hello world"
                result: Ok(false)
            },
            VerifyFixture {
                public_key: "02ade4d69dc5f11ab372e10c2fa5ea6a2c6c118dc4ae71cbdf1001292411a05457",
                signature: "3045022100853ae0bca72d59aaa335ff967f062952348baf7cc03cd1cb60db21eda6c1fecc0220551afcbcfb81a3f2adba18608d474bf296cccc82d8fca9f2bbd1fea96b4b71dc",    // wrong signature
                data: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",       // sha256 hash of "hello world"
                result: Ok(false)
            }
        ];

        for fixture in fixtures {
            let key = BitcoinPublicKey::from_hex(fixture.public_key).unwrap();
            let ver_res = key.verify(&hex_bytes(fixture.data).unwrap(), &hex_bytes(fixture.signature).unwrap());
            match (ver_res, fixture.result) {
                (Ok(true), Ok(true)) => {},
                (Ok(false), Ok(false)) => {},
                (Err(e1), Err(e2)) => assert_eq!(e1, e2),
                (Err(e1), _) => {
                    test_debug!("Failed to verify signature: {}", e1);
                    assert!(false);
                }
                (_, _) => {
                    assert!(false);
                }
            }
        }
    }
}

