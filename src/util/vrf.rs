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

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]        // TODO: remove once we start using the VRF for things 

/// This codebase is based on routines defined in the IETF draft for verifiable random functions
/// over elliptic curves (https://tools.ietf.org/id/draft-irtf-cfrg-vrf-02.html).
///
/// This module does not implement one of the defined ciphersuites, but instead implements ECVRF
/// over Curve25519 with the SHA512 hash function and the Ristretto elligator map (as opposed to
/// the Elligator 2 map for Ed25519 points).
///
/// THIS CODE HAS NOT BEEN AUDITED.  DO NOT USE IN PRODUCTION SYSTEMS.

use util::hash::to_hex;

use ed25519_dalek::PublicKey as ed25519_PublicKey;
use ed25519_dalek::SecretKey as ed25519_PrivateKey;

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar as ed25519_Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};

use sha2::Digest;
use sha2::Sha512;

use std::fmt;
use std::error;

#[derive(Debug)]
pub enum ECVRF_Error {
    InvalidPublicKey,
    InvalidDataError,
    OSRNGError(rand::Error)
}

impl fmt::Display for ECVRF_Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ECVRF_Error::InvalidPublicKey => f.write_str(error::Error::description(self)),
            ECVRF_Error::InvalidDataError => f.write_str(error::Error::description(self)),
            ECVRF_Error::OSRNGError(ref e) => fmt::Display::fmt(e, f)
        }
    }
}

impl error::Error for ECVRF_Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ECVRF_Error::InvalidPublicKey => None,
            ECVRF_Error::InvalidDataError => None,
            ECVRF_Error::OSRNGError(ref e) => Some(e)
        }
    }

    fn description(&self) -> &str {
        match *self {
            ECVRF_Error::InvalidPublicKey => "Invalid public key",
            ECVRF_Error::InvalidDataError => "No data could be found",
            ECVRF_Error::OSRNGError(ref e) => e.description()
        }
    }
}

pub const SUITE : u8 = 0x05;        /* cipher suite (not standardized yet).  This would be ECVRF-ED25519-SHA512-RistrettoElligator -- i.e. using the Ristretto group on ed25519 and its elligator function */

pub struct ECVRF_Proof {
    pub Gamma: RistrettoPoint,
    pub c: ed25519_Scalar,
    pub s: ed25519_Scalar
}

impl ECVRF_Proof {
    pub fn from_slice(bytes: &[u8]) -> Result<ECVRF_Proof, ECVRF_Error> {
        match bytes.len() {
            80 => {
                // format:
                // 0                            32         48                         80
                // |----------------------------|----------|---------------------------|
                //      Gamma point               c scalar   s scalar
                let gamma_opt = CompressedRistretto::from_slice(&bytes[0..32]).decompress();
                if gamma_opt.is_none() {
                    return Err(ECVRF_Error::InvalidDataError);
                }

                let mut c_buf = [0u8; 32];
                let mut s_buf = [0u8; 32];

                for i in 0..16 {
                    c_buf[i] = bytes[32+i];
                }
                for i in 0..32 {
                    s_buf[i] = bytes[48+i];
                }

                let c = ed25519_Scalar::from_bits(c_buf);
                let s = ed25519_Scalar::from_bits(s_buf);
                
                Ok(ECVRF_Proof {
                    Gamma: gamma_opt.unwrap(),
                    c: c,
                    s: s
                })
            },
            _ => Err(ECVRF_Error::InvalidDataError)
        }
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Result<ECVRF_Proof, ECVRF_Error> {
        ECVRF_Proof::from_slice(&bytes[..])
    }

    pub fn to_bytes(&self) -> Result<[u8; 80], ECVRF_Error> {
        let mut c_bytes_16 = [0u8; 16];
        let c_bytes = self.c.reduce().to_bytes();
        
        // upper 16 bytes of c must be 0's
        for i in 16..32 {
            if c_bytes[i] != 0 {
                return Err(ECVRF_Error::InvalidDataError);
            }

            c_bytes_16[i-16] = c_bytes[i-16];
        }

        let gamma_bytes = self.Gamma.compress().to_bytes();
        let s_bytes = self.s.to_bytes();

        let mut ret : Vec<u8> = Vec::with_capacity(80);
        ret.extend_from_slice(&gamma_bytes);
        ret.extend_from_slice(&c_bytes_16);
        ret.extend_from_slice(&s_bytes);
        
        let mut proof_bytes = [0u8; 80];
        proof_bytes.copy_from_slice(&ret[..]);
        Ok(proof_bytes)
    }
}


fn ECVRF_point_to_string(p: &RistrettoPoint) -> Vec<u8> {
    p.compress().as_bytes().to_vec()
}

/// Ristretto elligator hash-to-curve routine.
/// https://tools.ietf.org/id/draft-irtf-cfrg-vrf-02.html#rfc.section.5.4.1
fn ECVRF_hash_to_curve(y: &ed25519_PublicKey, alpha: &Vec<u8>) -> RistrettoPoint {
    let pk_bytes = y.to_bytes();
    
    let mut hasher = Sha512::new();
    let mut result = [0u8; 64];        // encodes 2 field elements from the hash

    hasher.input(&[SUITE, 0x01]);
    hasher.input(&pk_bytes[..]);
    hasher.input(&alpha[..]);
    
    let rs = &hasher.result()[..];
    result.copy_from_slice(&rs);

    RistrettoPoint::from_uniform_bytes(&result)
}

/// Hash four points to a 16-byte string.
/// Implementation of https://tools.ietf.org/id/draft-irtf-cfrg-vrf-02.html#rfc.section.5.4.2
fn ECVRF_hash_points(p1: &RistrettoPoint, p2: &RistrettoPoint, p3: &RistrettoPoint, p4: &RistrettoPoint) -> [u8; 16] {
    let mut hasher = Sha512::new();
    let mut sha512_result = [0u8; 64];
    let mut hash128 = [0u8; 16];

    let p1_bytes = ECVRF_point_to_string(p1);
    let p2_bytes = ECVRF_point_to_string(p2);
    let p3_bytes = ECVRF_point_to_string(p3);
    let p4_bytes = ECVRF_point_to_string(p4);

    hasher.input(&[SUITE, 0x02]);
    hasher.input(&p1_bytes[..]);
    hasher.input(&p2_bytes[..]);
    hasher.input(&p3_bytes[..]);
    hasher.input(&p4_bytes[..]);
    
    let rs = &hasher.result()[..];
    sha512_result.copy_from_slice(&rs);
    
    for i in 0..16 {
        hash128[i] = sha512_result[i];
    }

    hash128
}

/// Auxilliary function to convert an ed25519 private key into:
/// * its public key (an ed25519 curve point)
/// * a new private key derived from the hash of the private key
/// * a truncated hash of the private key
/// Idea borroed from Algorand (https://github.com/algorand/libsodium/blob/draft-irtf-cfrg-vrf-03/src/libsodium/crypto_vrf/ietfdraft03/prove.c)
fn ECVRF_expand_privkey(secret: &ed25519_PrivateKey) -> (ed25519_PublicKey, ed25519_Scalar, [u8; 32]) {
    let mut hasher = Sha512::new();
    let mut h = [0u8; 64];
    let mut trunc_hash = [0u8; 32];
    let pubkey = ed25519_PublicKey::from_secret::<Sha512>(secret);
    let privkey_buf = secret.to_bytes();

    // hash secret key to produce nonce and intermediate private key
    hasher.input(&privkey_buf[0..32]);
    h.copy_from_slice(&hasher.result()[..]);

    // h will encode a new private key, so we need to twiddle a few bits to make sure it falls in the
    // right range (i.e. the curve order).
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;

    let mut h_32 = [0u8; 32];
    h_32.copy_from_slice(&h[0..32]);
    
    let x_scalar = ed25519_Scalar::from_bits(h_32);
    trunc_hash.copy_from_slice(&h[32..64]);

    (pubkey, x_scalar, trunc_hash)
}

/// RFC8032 nonce generation for ed25519, given part of a hash of a private key and a public key
fn ECVRF_nonce_generation(trunc_hash: &[u8; 32], H_point: &RistrettoPoint) -> ed25519_Scalar {
    let mut hasher = Sha512::new();
    let mut k_string = [0u8; 64];
    let h_string = H_point.compress().to_bytes();

    hasher.input(trunc_hash);
    hasher.input(&h_string);
    let rs = &hasher.result()[..];
    k_string.copy_from_slice(rs);

    let mut k_32 = [0u8; 32];
    k_32.copy_from_slice(&k_string[0..32]);

    let k = ed25519_Scalar::from_bits(k_32);
    k.reduce()
}

/// Convert a 16-byte string into a scalar
fn ECVRF_ed25519_scalar_from_hash128(hash128: &[u8; 16]) -> ed25519_Scalar {
    let mut scalar_buf = [0u8; 32];
    for i in 0..16 {
        scalar_buf[i] = hash128[i];
    }

    ed25519_Scalar::from_bits(scalar_buf)
}

/// ECVRF proof routine
/// https://tools.ietf.org/id/draft-irtf-cfrg-vrf-02.html#rfc.section.5.1
pub fn ECVRF_prove(secret: &ed25519_PrivateKey, alpha: &Vec<u8>) -> ECVRF_Proof {
    let (Y_point, x_scalar, trunc_hash) = ECVRF_expand_privkey(secret);
    let H_point = ECVRF_hash_to_curve(&Y_point, alpha);

    let Gamma_point = &x_scalar * &H_point;
    let k_scalar = ECVRF_nonce_generation(&trunc_hash, &H_point);

    let kB_point = &k_scalar * &RISTRETTO_BASEPOINT_POINT;
    let kH_point = &k_scalar * &H_point;

    let c_hashbuf = ECVRF_hash_points(&H_point, &Gamma_point, &kB_point, &kH_point);
    let c_scalar = ECVRF_ed25519_scalar_from_hash128(&c_hashbuf);
    
    let s_full_scalar = &c_scalar * &x_scalar + &k_scalar;
    let s_scalar = s_full_scalar.reduce();

    ECVRF_Proof {
        Gamma: Gamma_point,
        c: c_scalar,
        s: s_scalar
    }
}

/// Auxilliary routine to convert an ed25519 public key point to a Ristretto point.
/// Not supposed to fail, but you never know!
fn ECVRF_ed25519_PublicKey_to_RistrettoPoint(public_key: &ed25519_PublicKey) -> Result<RistrettoPoint, ECVRF_Error> {
    // for reasons above my pay grade, curve25519_dalek does not expose a RistrettoPoint's internal
    // EdwardsPoint (even though it is, structurally, the same thing).
   
    // ed25519_PublicKey is just a wrapper around CompressedEdwardsY, so this conversion shouldn't fail
    let public_key_edy = CompressedEdwardsY::from_slice(public_key.as_bytes());
    let public_key_ed_opt = public_key_edy.decompress();

    if public_key_ed_opt.is_none() {
        // bad public key
        return Err(ECVRF_Error::InvalidDataError);
    }

    let public_key_ed = public_key_ed_opt.unwrap();
    
    // RistrettoPoint is just a wrapper around EdwardsPoint
    // TODO: see about getting a public constructor here
    use std::mem::transmute;
    let rp = unsafe { transmute::<EdwardsPoint, RistrettoPoint>(public_key_ed) };
    return Ok(rp);
}

/// Given a public key, verify that the private key owner that generate the ECVRF proof did so on the given message.
/// Return Ok(true) if so
/// Return Ok(false) if not
/// Return Err(ECVRF_Error) if the public key is invalid, or we are unable to do one of the
/// necessary internal data conversions.
pub fn ECVRF_verify(Y_point: &ed25519_PublicKey, proof: &ECVRF_Proof, alpha: &Vec<u8>) -> Result<bool, ECVRF_Error> {
    let H_point = ECVRF_hash_to_curve(Y_point, alpha);
    let Y_ristretto_point = ECVRF_ed25519_PublicKey_to_RistrettoPoint(Y_point)?;
    let s_reduced = proof.s.reduce();

    let U_point = &s_reduced * &RISTRETTO_BASEPOINT_POINT - &proof.c * Y_ristretto_point;
    let V_point = &s_reduced * &H_point - &proof.c * &proof.Gamma;

    let c_prime_hashbuf = ECVRF_hash_points(&H_point, &proof.Gamma, &U_point, &V_point);
    let c_prime = ECVRF_ed25519_scalar_from_hash128(&c_prime_hashbuf);

    // NOTE: this leverages constant-time comparison inherited from the Scalar impl
    Ok(c_prime == proof.c)
}

/// Verify that a given byte string is a well-formed EdDSA public key (i.e. it's a compressed
/// Edwards point that is valid).
pub fn ECVRF_check_public_key(pubkey_bytes: &Vec<u8>) -> Option<ed25519_PublicKey> {
    match pubkey_bytes.len() {
        32 => {
            let mut pubkey_slice = [0; 32];
            pubkey_slice.copy_from_slice(&pubkey_bytes[0..32]);

            let checked_pubkey = CompressedEdwardsY(pubkey_slice);
            let full_checked_pubkey = checked_pubkey.decompress();
            if full_checked_pubkey.is_none() {
                // invalid 
                return None;
            }

            let key_res = ed25519_PublicKey::from_bytes(&pubkey_slice);
            match key_res {
                Ok(key) => Some(key),
                Err(_e) => None
            }
        },
        _ => None
    }
}

/// Helper method to turn a public key into a hex string 
pub fn ECVRF_public_key_to_hex(pubkey: &ed25519_PublicKey) -> String {
    to_hex(pubkey.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    use util::hash::hex_bytes;

    use ed25519_dalek::PublicKey as ed25519_PublicKey;
    use ed25519_dalek::SecretKey as ed25519_PrivateKey;

    use curve25519_dalek::scalar::Scalar as ed25519_Scalar;

    use sha2::Sha512;

    use rand::rngs::OsRng;
    use rand::RngCore;

    struct VRF_Proof_Fixture {
        privkey: Vec<u8>,
        message: &'static str,
        proof: Vec<u8>
    }

    struct VRF_Verify_Fixture {
        pubkey: Vec<u8>,
        proof: Vec<u8>,
        message: &'static str,
        result: bool
    }

    struct VRF_Proof_Codec_Fixture {
        proof: Vec<u8>,
        result: bool
    }

    #[test]
    fn test_prove() {
        let proof_fixtures = vec![
            VRF_Proof_Fixture {
                privkey: hex_bytes("5b28b7069b05f2d0731bb6722d7a5bd1669a1112321bb127002e650274d35a87").unwrap(),
                message: "hello world 1",
                proof: hex_bytes("d4d9b8e66c9c0eeea3ad68952936a0d9a83ef1cd4bb6b8b9dd658aa17154b24cd094cba3d09d27113e404cd7d0e7fac593d1e13c8541a119ee2b5e730f99b9649037e0fcc7abad99825055dfe191490e").unwrap()
            },
            VRF_Proof_Fixture {
                privkey: hex_bytes("aa29dc3afa098cdee5352449e664b88436265bd31680d5fa74dedde9d3bd6743").unwrap(),
                message: "hello world 2",
                proof: hex_bytes("b8b1f6f601a9dfe68e8edc68466c163c23d133391285e15c8a69df399ae7cd4818928b7d15eb361b54e23ea5aa5317cfb4119e2e2d5396ed07b77db3772d5e8ba3e63ac2a28ec1836995778fea99f40c").unwrap(),
            },
            VRF_Proof_Fixture {
                privkey: hex_bytes("a5af68df155ae7aee9eab85b293b6ac9475f8a1df72b65acfde062447a7b7b81").unwrap(),
                message: "hello world 3",
                proof: hex_bytes("cab399408ec5ea593b85eba68716eefb44816f7ab88d4cdfd6608bc3a6a21972362bedbb8b35c13c3cbc320026d44233eaf63cf76e99b21f5e09ee5e7959cba5f91ef4b21626e4dde617730ef1e14f03").unwrap(),
            },
            VRF_Proof_Fixture {
                privkey: hex_bytes("f4b124f6cdf10930ca7139e1ff58a3f0419b8f82da163d160a7595a4620e6afd").unwrap(),
                message: "",
                proof: hex_bytes("92edbd66e47b5a063862d98583d939ad234cfcb45a7dd24b5c8436264090d01bf3e70aafe80ccb9cd954d3a2d4229664f02107b2fc0a4922846e1dd02f8bb959528360d1e99f82299e7ee6f98499670e").unwrap()
            }
        ];

        for proof_fixture in proof_fixtures {
            let alpha = proof_fixture.message.as_bytes();
            let privk = ed25519_PrivateKey::from_bytes(&proof_fixture.privkey[..]).unwrap();
            let expected_proof_bytes = &proof_fixture.proof[..];

            let proof = ECVRF_prove(&privk, &alpha.to_vec());
            let proof_bytes = proof.to_bytes().unwrap();

            assert_eq!(proof_bytes.to_vec(), expected_proof_bytes.to_vec());
        }
    }

    #[test]
    fn test_verify() {
        let verify_fixtures = vec![
            VRF_Verify_Fixture { 
                result: true,
                pubkey: hex_bytes("e7ea5f723a5753174ce609a22ca5cbd8e5eee8deee2fbba0e72ff79e5dfc139c").unwrap(),
                message: "hello world 1",
                proof: hex_bytes("94f27ca7ae235c3b9c6df682a0fe314927a4b24b06cb24b61703cbb9ff725c38125cfea5b4c9105db772c9acc17c188032f900a3b85c16775b398347393a70d3afb5bf2095a2375e362f659a8d529b0c").unwrap(),
            },
            VRF_Verify_Fixture {
                result: true,
                pubkey: hex_bytes("b924bc463eddc787eb15673c6baaf0df84fe0e8e2ef58cc35d291aa37edeb4fc").unwrap(),
                message: "hello world 2",
                proof: hex_bytes("024c1484fcb05cecdb4dbfb9bf4e08e7f529aea3b3a2515716ad4e9cf7bace6c91181b6bb7d8201c5a85a11c626d1848aa2ac4d188c7e24a94faa32d1eec48d600fad7c55c7e71adb6a7dd6c73f6fc02").unwrap(),
            },
            VRF_Verify_Fixture {
                result: true,
                pubkey: hex_bytes("a126397fdce063498b9f119e7b75e414fa678ee95ec4a315cfed783304dcee13").unwrap(),
                message: "hello world 3",
                proof: hex_bytes("661c630811ab9573c52d85d51a5d3bc6f7d2cdef389489d35a97602713c4513ed1197b7ae5655bfbeba5913a0607176f41941e5562c4c1ea7912ef0ac5b89249bedb47cdf7c66966194a4d16c2008b03").unwrap(),
            },
            // wrong message
            VRF_Verify_Fixture { 
                result: false,
                pubkey: hex_bytes("e7ea5f723a5753174ce609a22ca5cbd8e5eee8deee2fbba0e72ff79e5dfc139c").unwrap(),
                message: "nope",
                proof: hex_bytes("94f27ca7ae235c3b9c6df682a0fe314927a4b24b06cb24b61703cbb9ff725c38125cfea5b4c9105db772c9acc17c188032f900a3b85c16775b398347393a70d3afb5bf2095a2375e362f659a8d529b0c").unwrap(),
            },
            // wrong key
            VRF_Verify_Fixture {
                result: false,
                pubkey: hex_bytes("a126397fdce063498b9f119e7b75e414fa678ee95ec4a315cfed783304dcee13").unwrap(),
                message: "hello world 2",
                proof: hex_bytes("024c1484fcb05cecdb4dbfb9bf4e08e7f529aea3b3a2515716ad4e9cf7bace6c91181b6bb7d8201c5a85a11c626d1848aa2ac4d188c7e24a94faa32d1eec48d600fad7c55c7e71adb6a7dd6c73f6fc02").unwrap(),
            },
            // wrong proof
            VRF_Verify_Fixture {
                result: false,
                pubkey: hex_bytes("a126397fdce063498b9f119e7b75e414fa678ee95ec4a315cfed783304dcee13").unwrap(),
                message: "hello world 3",
                proof: hex_bytes("024c1484fcb05cecdb4dbfb9bf4e08e7f529aea3b3a2515716ad4e9cf7bace6c91181b6bb7d8201c5a85a11c626d1848aa2ac4d188c7e24a94faa32d1eec48d600fad7c55c7e71adb6a7dd6c73f6fc02").unwrap(),
            },
        ];

        for verify_fixture in verify_fixtures {
            let pubk = ed25519_PublicKey::from_bytes(&verify_fixture.pubkey[..]).unwrap();
            let proof_bytes = &verify_fixture.proof[..];
            let alpha = verify_fixture.message[..].as_bytes();

            let proof = ECVRF_Proof::from_slice(proof_bytes).unwrap();

            let result = ECVRF_verify(&pubk, &proof, &alpha.to_vec()).unwrap();
            assert_eq!(result, verify_fixture.result);
        }
    }

    #[test]
    fn test_random_proof_roundtrip() {
        for _i in 0..100 {
            let mut csprng: OsRng = OsRng::new().unwrap();
            let secret_key: ed25519_PrivateKey = ed25519_PrivateKey::generate(&mut csprng);
            let public_key = ed25519_PublicKey::from_secret::<Sha512>(&secret_key);

            let mut msg = [0u8, 1024];
            csprng.fill_bytes(&mut msg);

            let proof = ECVRF_prove(&secret_key, &msg.to_vec());
            let res = ECVRF_verify(&public_key, &proof, &msg.to_vec()).unwrap();

            assert!(res);
        }
    }

    #[test]
    fn test_proof_codec() {
        let proof_fixtures = vec![
            VRF_Proof_Codec_Fixture {
                proof: hex_bytes("024c1484fcb05cecdb4dbfb9bf4e08e7f529aea3b3a2515716ad4e9cf7bace6c91181b6bb7d8201c5a85a11c626d1848aa2ac4d188c7e24a94faa32d1eec48d600fad7c55c7e71adb6a7dd6c73f6fc02").unwrap(),
                result: true
            },
            VRF_Proof_Codec_Fixture {
                proof: hex_bytes("94f27ca7ae235c3b9c6df682a0fe314927a4b24b06cb24b61703cbb9ff725c38125cfea5b4c9105db772c9acc17c188032f900a3b85c16775b398347393a70d3afb5bf2095a2375e362f659a8d529b0c").unwrap(),
                result: true,
            },
            VRF_Proof_Codec_Fixture {
                proof: hex_bytes("6e7b566536d1e856977263cf0e23dc3c31e79a5a040a37d779feb9b17b61f66a30e7333c7f173a13ffbccb338f2d245bba4539c9f18ebe24c86e1e4301189714deee9ad36d1565f43267034aef6e4a0c").unwrap(),
                result: true,
            },
            VRF_Proof_Codec_Fixture {
                proof: hex_bytes("f4c5ac0fe2ae06b0aae9979be90065d7a13012402b5587b76e3ab000d526e97c70c4fac4c8be99b576881a4f97fc833e7cd17d669b94e15eac894f8e66dacd8ed3c621d5948fffe76ba45121265b0709").unwrap(),
                result: true,
            },
            VRF_Proof_Codec_Fixture {
                proof: hex_bytes("661c630811ab9573c52d85d51a5d3bc6f7d2cdef389489d35a97602713c4513ed1197b7ae5655bfbeba5913a0607176f41941e5562c4c1ea7912ef0ac5b89249bedb47cdf7c66966194a4d16c2008b03").unwrap(),
                result: true,
            },
            VRF_Proof_Codec_Fixture {
                proof: hex_bytes("cc3a7ca8208fa8965d1439ef74ba974154ea8383aa1cbf658b711472b7d32d2f4e31e00db99b81d9428d10b7c03e6cab9894bebd37e9de82dbdeaefff9d1501d875cd220f3a81bf84bd174f29640f509").unwrap(),
                result: true,
            },
            VRF_Proof_Codec_Fixture {
                proof: hex_bytes("94654efaef05909d40ddd4e0bb8aae8fd70780b22bb57844fb4c1d81636ed6556d9725d59ccb0975b9c70b8cb2b20d781455e44d5914d15ed7eefdc58606b085ae13aa9c2e5d03c081e81fc25f945b0c").unwrap(),
                result: true,
            },
            // should fail -- 79 bytes
            VRF_Proof_Codec_Fixture {
                proof: hex_bytes("94654efaef05909d40ddd4e0bb8aae8fd70780b22bb57844fb4c1d81636ed6556d9725d59ccb0975b9c70b8cb2b20d781455e44d5914d15ed7eefdc58606b085ae13aa9c2e5d03c081e81fc25f945b").unwrap(),
                result: false,
            },
            // should fail -- 81 bytes
            VRF_Proof_Codec_Fixture {
                proof: hex_bytes("94654efaef05909d40ddd4e0bb8aae8fd70780b22bb57844fb4c1d81636ed6556d9725d59ccb0975b9c70b8cb2b20d781455e44d5914d15ed7eefdc58606b085ae13aa9c2e5d03c081e81fc25f945b0c01").unwrap(),
                result: false,
            },
            // should fail -- Gamma isn't a valid point
            VRF_Proof_Codec_Fixture {
                proof: hex_bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6d9725d59ccb0975b9c70b8cb2b20d781455e44d5914d15ed7eefdc58606b085ae13aa9c2e5d03c081e81fc25f945b0c").unwrap(),
                result: false,
            },
        ];

        for proof_fixture in proof_fixtures {
            let proof_res = ECVRF_Proof::from_bytes(&proof_fixture.proof);
            if proof_fixture.result {
                // should decode 
                assert!(!proof_res.is_err());
                
                // should re-encode
                assert!(proof_res.unwrap().to_bytes().unwrap().to_vec() == proof_fixture.proof.to_vec());
            }
            else {
                assert!(proof_res.is_err());
            }
        }

        // confirm that a proof structure with an invalid c-value does not encode 
        let valid_proof = ECVRF_Proof::from_bytes(&hex_bytes("024c1484fcb05cecdb4dbfb9bf4e08e7f529aea3b3a2515716ad4e9cf7bace6c91181b6bb7d8201c5a85a11c626d1848aa2ac4d188c7e24a94faa32d1eec48d600fad7c55c7e71adb6a7dd6c73f6fc02").unwrap()).unwrap();
        let bad_proof = ECVRF_Proof {
            Gamma: valid_proof.Gamma,
            c: ed25519_Scalar::from_bits([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
            s: valid_proof.s
        };

        let bad_proof_bytes_res = bad_proof.to_bytes();
        assert!(bad_proof_bytes_res.is_err());
    }

    #[test]
    fn check_valid_public_key() {
        let res1 = ECVRF_check_public_key(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap().to_vec());
        assert!(res1.is_some());

        let res2 = ECVRF_check_public_key(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7b").unwrap().to_vec());
        assert!(res2.is_none());
    }
}
