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

/// This codebase is based on routines defined in the IETF draft for verifiable random functions
/// over elliptic curves (https://tools.ietf.org/id/draft-irtf-cfrg-vrf-02.html).
///
/// This module does not implement one of the defined ciphersuites, but instead implements ECVRF
/// over Curve25519 with the SHA512 hash function and the Ristretto elligator map (as opposed to
/// the Elligator 2 map for Ed25519 points).
///
/// THIS CODE HAS NOT BEEN AUDITED.  DO NOT USE IN PRODUCTION SYSTEMS.

use std::ops::Deref;
use std::ops::DerefMut;
use std::fmt::Debug;
use std::cmp::PartialEq;
use std::cmp::Ord;
use std::cmp::Ordering;
use std::cmp::Eq;
use std::hash::{Hash, Hasher};
use std::clone::Clone;
use util::hash::to_hex;

use ed25519_dalek::PublicKey as ed25519_PublicKey;
use ed25519_dalek::SecretKey as ed25519_PrivateKey;
use ed25519_dalek::Keypair as VRFKeypair;

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar as ed25519_Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};

use sha2::Digest;
use sha2::Sha512;

use std::fmt;
use std::error;

use util::hash::hex_bytes;
use rand;

#[derive(Clone)]
pub struct VRFPublicKey(pub ed25519_PublicKey);

pub struct VRFPrivateKey(pub ed25519_PrivateKey);

// have to do Clone separately since ed25519_PrivateKey doesn't implement Clone
impl Clone for VRFPrivateKey {
    fn clone(&self) -> VRFPrivateKey {
        let bytes = self.to_bytes();
        let pk = ed25519_PrivateKey::from_bytes(&bytes).expect("FATAL: could not do VRFPrivateKey round-trip");
        VRFPrivateKey(pk)
    }
}

impl Deref for VRFPublicKey {
    type Target = ed25519_PublicKey;
    fn deref(&self) -> &ed25519_PublicKey {
        &self.0
    }
}

impl DerefMut for VRFPublicKey {
    fn deref_mut(&mut self) -> &mut ed25519_PublicKey {
        &mut self.0
    }
}

impl Debug for VRFPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_hex())
    }
}

impl PartialEq for VRFPublicKey {
    fn eq(&self, other: &VRFPublicKey) -> bool {
        self.as_bytes().to_vec() == other.as_bytes().to_vec()
    }
}

impl Eq for VRFPublicKey {}

impl PartialOrd for VRFPublicKey {
    fn partial_cmp(&self, other: &VRFPublicKey) -> Option<Ordering> {
        Some(self.as_bytes().to_vec().cmp(&other.as_bytes().to_vec()))
    }
}

impl Ord for VRFPublicKey {
    fn cmp(&self, other: &VRFPublicKey) -> Ordering {
        self.as_bytes().to_vec().cmp(&other.as_bytes().to_vec())
    }
}

impl Hash for VRFPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl Deref for VRFPrivateKey {
    type Target = ed25519_PrivateKey;
    fn deref(&self) -> &ed25519_PrivateKey {
        &self.0
    }
}

impl DerefMut for VRFPrivateKey {
    fn deref_mut(&mut self) -> &mut ed25519_PrivateKey {
        &mut self.0
    }
}

impl Debug for VRFPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_hex())
    }
}

// do NOT ship this comparison code in production -- it's NOT constant-time
#[cfg(test)]
impl PartialEq for VRFPrivateKey {
    fn eq(&self, other: &VRFPrivateKey) -> bool {
        self.as_bytes().to_vec() == other.as_bytes().to_vec()
    }
}

impl VRFPrivateKey {
    pub fn new() -> VRFPrivateKey {
        let mut rng = rand::thread_rng();
        let keypair: VRFKeypair = VRFKeypair::generate(&mut rng);
        VRFPrivateKey(keypair.secret)
    }

    pub fn from_hex(h: &String) -> Option<VRFPrivateKey> {
        match hex_bytes(h) {
            Ok(b) => {
                match ed25519_PrivateKey::from_bytes(&b[..]) {
                    Ok(pk) => Some(VRFPrivateKey(pk)),
                    Err(_) => None
                }
            },
            Err(_) => None
        }
    }

    pub fn from_bytes(b: &[u8]) -> Option<VRFPrivateKey> {
        match ed25519_PrivateKey::from_bytes(b) {
            Ok(pk) => Some(VRFPrivateKey(pk)),
            Err(_) => None
        }
    }

    pub fn to_hex(&self) -> String {
        to_hex(self.as_bytes())
    }
}

impl VRFPublicKey {
    pub fn from_private(pk: &VRFPrivateKey) -> VRFPublicKey {
        VRFPublicKey(ed25519_PublicKey::from(&pk.0))
    }

    pub fn from_bytes(pubkey_bytes: &[u8]) -> Option<VRFPublicKey> {
        match pubkey_bytes.len() {
            32 => {
                let mut pubkey_slice = [0; 32];
                pubkey_slice.copy_from_slice(&pubkey_bytes[0..32]);

                let checked_pubkey = CompressedEdwardsY(pubkey_slice);
                match checked_pubkey.decompress() {
                    Some(_) => {},
                    None => {
                        // invalid
                        return None;
                    }
                }

                match ed25519_PublicKey::from_bytes(&pubkey_slice) {
                    Ok(key) => Some(VRFPublicKey(key)),
                    Err(_) => None
                }
            },
            _ => None
        }
    }

    pub fn from_hex(h: &String) -> Option<VRFPublicKey> {
        match hex_bytes(h) {
            Ok(b) => {
                VRF::check_public_key(&b)
            },
            Err(_) => None
        }
    }
    
    pub fn to_hex(&self) -> String {
        to_hex(self.as_bytes())
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidPublicKey,
    InvalidDataError,
    OSRNGError(rand::Error)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidPublicKey => f.write_str(error::Error::description(self)),
            Error::InvalidDataError => f.write_str(error::Error::description(self)),
            Error::OSRNGError(ref e) => fmt::Display::fmt(e, f)
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::InvalidPublicKey => None,
            Error::InvalidDataError => None,
            Error::OSRNGError(ref e) => Some(e)
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::InvalidPublicKey => "Invalid public key",
            Error::InvalidDataError => "No data could be found",
            Error::OSRNGError(ref e) => e.description()
        }
    }
}

pub const SUITE : u8 = 0x05;        /* cipher suite (not standardized yet).  This would be ECVRF-ED25519-SHA512-RistrettoElligator -- i.e. using the Ristretto group on ed25519 and its elligator function */

#[derive(Debug, Clone, PartialEq)]
pub struct VRFProof {
    // force private so we don't accidentally expose
    // an invalid c point
    Gamma: RistrettoPoint,
    c: ed25519_Scalar,
    s: ed25519_Scalar
}

pub const VRF_PROOF_ENCODED_SIZE : u32 = 80;

impl VRFProof {
    pub fn Gamma(&self) -> &RistrettoPoint {
        &self.Gamma
    }

    pub fn s(&self) -> &ed25519_Scalar {
        &self.s
    }

    pub fn c(&self) -> &ed25519_Scalar {
        &self.c
    }

    pub fn check_c(c: &ed25519_Scalar) -> bool {
        let c_bytes = c.reduce().to_bytes();
        
        // upper 16 bytes of c must be 0's
        for i in 16..32 {
            if c_bytes[i] != 0 {
                return false;
            }
        }
        return true;
    }

    pub fn empty() -> VRFProof {
        VRFProof::from_slice(&[0u8; 80])
    }

    pub fn new(Gamma: RistrettoPoint, c: ed25519_Scalar, s: ed25519_Scalar) -> Result<VRFProof, Error> {
        if !VRFProof::check_c(&c) {
            return Err(Error::InvalidDataError);
        }

        Ok(VRFProof {
            Gamma,
            c,
            s
        })
    }

    pub fn from_slice(bytes: &[u8]) -> Result<VRFProof, Error> {
        match bytes.len() {
            80 => {
                // format:
                // 0                            32         48                         80
                // |----------------------------|----------|---------------------------|
                //      Gamma point               c scalar   s scalar
                let gamma_opt = CompressedRistretto::from_slice(&bytes[0..32]).decompress();
                if gamma_opt.is_none() {
                    return Err(Error::InvalidDataError);
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
                
                Ok(VRFProof {
                    Gamma: gamma_opt.unwrap(),
                    c: c,
                    s: s
                })
            },
            _ => Err(Error::InvalidDataError)
        }
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Result<VRFProof, Error> {
        VRFProof::from_slice(&bytes[..])
    }

    pub fn from_hex(hex_str: &String) -> Result<VRFProof, Error> {
        match hex_bytes(hex_str) {
            Ok(b) => {
                VRFProof::from_slice(&b[..])
            },
            Err(_) => {
                Err(Error::InvalidDataError)
            }
        }
    }

    pub fn to_bytes(&self) -> [u8; 80] {
        let mut c_bytes_16 = [0u8; 16];
        assert!(VRFProof::check_c(&self.c), "FATAL ERROR: somehow constructed an invalid ECVRF proof");

        let c_bytes = self.c.reduce().to_bytes();
        
        // upper 16 bytes of c must be 0's
        for i in 16..32 {
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
        proof_bytes
    }
    
    pub fn to_hex(&self) -> String {
        to_hex(&self.to_bytes())
    }
}

pub struct VRF {}

impl VRF {
    fn point_to_string(p: &RistrettoPoint) -> Vec<u8> {
        p.compress().as_bytes().to_vec()
    }

    /// Ristretto elligator hash-to-curve routine.
    /// https://tools.ietf.org/id/draft-irtf-cfrg-vrf-02.html#rfc.section.5.4.1
    fn hash_to_curve(y: &VRFPublicKey, alpha: &Vec<u8>) -> RistrettoPoint {
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
    fn hash_points(p1: &RistrettoPoint, p2: &RistrettoPoint, p3: &RistrettoPoint, p4: &RistrettoPoint) -> [u8; 16] {
        let mut hasher = Sha512::new();
        let mut sha512_result = [0u8; 64];
        let mut hash128 = [0u8; 16];

        let p1_bytes = VRF::point_to_string(p1);
        let p2_bytes = VRF::point_to_string(p2);
        let p3_bytes = VRF::point_to_string(p3);
        let p4_bytes = VRF::point_to_string(p4);

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
    fn expand_privkey(secret: &VRFPrivateKey) -> (VRFPublicKey, ed25519_Scalar, [u8; 32]) {
        let mut hasher = Sha512::new();
        let mut h = [0u8; 64];
        let mut trunc_hash = [0u8; 32];
        let pubkey = VRFPublicKey::from_private(secret);
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
    fn nonce_generation(trunc_hash: &[u8; 32], H_point: &RistrettoPoint) -> ed25519_Scalar {
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

    /// Convert a 16-byte string into a scalar.
    /// The upper 16 bytes in the resulting scalar MUST BE 0's
    fn ed25519_scalar_from_hash128(hash128: &[u8; 16]) -> ed25519_Scalar {
        let mut scalar_buf = [0u8; 32];
        for i in 0..16 {
            scalar_buf[i] = hash128[i];
        }

        ed25519_Scalar::from_bits(scalar_buf)
    }

    /// ECVRF proof routine
    /// https://tools.ietf.org/id/draft-irtf-cfrg-vrf-02.html#rfc.section.5.1
    pub fn prove(secret: &VRFPrivateKey, alpha: &Vec<u8>) -> VRFProof {
        let (Y_point, x_scalar, trunc_hash) = VRF::expand_privkey(secret);
        let H_point = VRF::hash_to_curve(&Y_point, alpha);

        let Gamma_point = &x_scalar * &H_point;
        let k_scalar = VRF::nonce_generation(&trunc_hash, &H_point);

        let kB_point = &k_scalar * &RISTRETTO_BASEPOINT_POINT;
        let kH_point = &k_scalar * &H_point;

        let c_hashbuf = VRF::hash_points(&H_point, &Gamma_point, &kB_point, &kH_point);
        let c_scalar = VRF::ed25519_scalar_from_hash128(&c_hashbuf);
        
        let s_full_scalar = &c_scalar * &x_scalar + &k_scalar;
        let s_scalar = s_full_scalar.reduce();

        // NOTE: unwrap() won't panic because c_scalar is guaranteed to have 
        // its upper 16 bytes as 0
        VRFProof::new(Gamma_point, c_scalar, s_scalar).expect("FATAL ERROR: upper-16 bytes of proof's C scalar are NOT 0")
    }

    /// Auxilliary routine to convert an ed25519 public key point to a Ristretto point.
    /// Not supposed to fail, but you never know!
    fn VRFPublicKey_to_RistrettoPoint(public_key: &VRFPublicKey) -> Result<RistrettoPoint, Error> {
        // for reasons above my pay grade, curve25519_dalek does not expose a RistrettoPoint's internal
        // EdwardsPoint (even though it is, structurally, the same thing).
       
        // VRFPublicKey is just a wrapper around CompressedEdwardsY, so this conversion shouldn't fail
        let public_key_edy = CompressedEdwardsY::from_slice(public_key.as_bytes());
        let public_key_ed_opt = public_key_edy.decompress();

        if public_key_ed_opt.is_none() {
            // bad public key
            return Err(Error::InvalidDataError);
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
    /// Return Err(Error) if the public key is invalid, or we are unable to do one of the
    /// necessary internal data conversions.
    pub fn verify(Y_point: &VRFPublicKey, proof: &VRFProof, alpha: &Vec<u8>) -> Result<bool, Error> {
        let H_point = VRF::hash_to_curve(Y_point, alpha);
        let Y_ristretto_point = VRF::VRFPublicKey_to_RistrettoPoint(Y_point)?;
        let s_reduced = proof.s().reduce();

        let U_point = &s_reduced * &RISTRETTO_BASEPOINT_POINT - proof.c() * Y_ristretto_point;
        let V_point = &s_reduced * &H_point - proof.c() * proof.Gamma();

        let c_prime_hashbuf = VRF::hash_points(&H_point, proof.Gamma(), &U_point, &V_point);
        let c_prime = VRF::ed25519_scalar_from_hash128(&c_prime_hashbuf);

        // NOTE: this leverages constant-time comparison inherited from the Scalar impl
        Ok(c_prime == *(proof.c()))
    }

    /// Verify that a given byte string is a well-formed EdDSA public key (i.e. it's a compressed
    /// Edwards point that is valid).
    pub fn check_public_key(pubkey_bytes: &Vec<u8>) -> Option<VRFPublicKey> {
        match pubkey_bytes.len() {
            32 => {
                VRFPublicKey::from_bytes(&pubkey_bytes[..])
            },
            _ => None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use util::hash::hex_bytes;

    use curve25519_dalek::scalar::Scalar as ed25519_Scalar;

    use sha2::Sha512;

    use rand;
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
            let privk = VRFPrivateKey::from_bytes(&proof_fixture.privkey[..]).unwrap();
            let expected_proof_bytes = &proof_fixture.proof[..];

            let proof = VRF::prove(&privk, &alpha.to_vec());
            let proof_bytes = proof.to_bytes();

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
            let pubk = VRFPublicKey::from_bytes(&verify_fixture.pubkey[..]).unwrap();
            let proof_bytes = &verify_fixture.proof[..];
            let alpha = verify_fixture.message[..].as_bytes();

            let proof = VRFProof::from_slice(proof_bytes).unwrap();

            let result = VRF::verify(&pubk, &proof, &alpha.to_vec()).unwrap();
            assert_eq!(result, verify_fixture.result);
        }
    }

    #[test]
    fn test_random_proof_roundtrip() {
        for _i in 0..100 {
            let secret_key = VRFPrivateKey::new();
            let public_key = VRFPublicKey::from_private(&secret_key);

            let mut rng = rand::thread_rng();
            let mut msg = [0u8; 1024];
            rng.fill_bytes(&mut msg);

            let proof = VRF::prove(&secret_key, &msg.to_vec());
            let res = VRF::verify(&public_key, &proof, &msg.to_vec()).unwrap();

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
            let proof_res = VRFProof::from_bytes(&proof_fixture.proof);
            if proof_fixture.result {
                // should decode 
                assert!(!proof_res.is_err());
                
                // should re-encode
                assert!(proof_res.unwrap().to_bytes().to_vec() == proof_fixture.proof.to_vec());
            }
            else {
                assert!(proof_res.is_err());
            }
        }
    }

    #[test]
    fn check_valid_public_key() {
        let res1 = VRF::check_public_key(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap().to_vec());
        assert!(res1.is_some());

        let res2 = VRF::check_public_key(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7b").unwrap().to_vec());
        assert!(res2.is_none());
    }
}
