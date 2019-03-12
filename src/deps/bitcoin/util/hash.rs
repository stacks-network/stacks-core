// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Hash functions
//!
//! Utility functions related to hashing data, including merkleization

use std::char::from_digit;
use std::cmp::min;
use std::default::Default;
use std::error;
use std::fmt;
use std::io::Cursor;
use std::mem;
#[cfg(feature = "serde")] use serde;

use byteorder::{LittleEndian, WriteBytesExt};

use ripemd160::Ripemd160;

use deps::bitcoin::network::encodable::{ConsensusDecodable, ConsensusEncodable};
use deps::bitcoin::network::serialize::{self, SimpleEncoder, RawEncoder, BitcoinHash};

use util::uint::Uint256;
use util::hash::DoubleSha256 as Sha256dHash;
use util::hash::Hash160;

use sha2::Sha256;
use sha2::Digest;

/// An object that allows serializing data into a sha256d
pub struct Sha256dEncoder(Sha256);

impl Sha256dEncoder {
    /// Create a new encoder
    pub fn new() -> Sha256dEncoder {
        Sha256dEncoder(Sha256::new())
    }

    /// Extract the hash from an encoder
    pub fn into_hash(self) -> Sha256dHash {
        let mut second_sha = Sha256::new();
        let mut tmp = [0; 32];
        tmp.copy_from_slice(self.0.result().as_slice());
        second_sha.input(&tmp);
        tmp.copy_from_slice(second_sha.result().as_slice());
        Sha256dHash(tmp)
    }
}

impl SimpleEncoder for Sha256dEncoder {
    fn emit_u64(&mut self, v: u64) -> Result<(), serialize::Error> {
        let mut data = [0; 8];
        (&mut data[..]).write_u64::<LittleEndian>(v).unwrap();
        self.0.input(&data);
        Ok(())
    }

    fn emit_u32(&mut self, v: u32) -> Result<(), serialize::Error> {
        let mut data = [0; 4];
        (&mut data[..]).write_u32::<LittleEndian>(v).unwrap();
        self.0.input(&data);
        Ok(())
    }

    fn emit_u16(&mut self, v: u16) -> Result<(), serialize::Error> {
        let mut data = [0; 2];
        (&mut data[..]).write_u16::<LittleEndian>(v).unwrap();
        self.0.input(&data);
        Ok(())
    }

    fn emit_i64(&mut self, v: i64) -> Result<(), serialize::Error> {
        let mut data = [0; 8];
        (&mut data[..]).write_i64::<LittleEndian>(v).unwrap();
        self.0.input(&data);
        Ok(())
    }

    fn emit_i32(&mut self, v: i32) -> Result<(), serialize::Error> {
        let mut data = [0; 4];
        (&mut data[..]).write_i32::<LittleEndian>(v).unwrap();
        self.0.input(&data);
        Ok(())
    }

    fn emit_i16(&mut self, v: i16) -> Result<(), serialize::Error> {
        let mut data = [0; 2];
        (&mut data[..]).write_i16::<LittleEndian>(v).unwrap();
        self.0.input(&data);
        Ok(())
    }

    fn emit_i8(&mut self, v: i8) -> Result<(), serialize::Error> {
        self.0.input(&[v as u8]);
        Ok(())
    }

    fn emit_u8(&mut self, v: u8) -> Result<(), serialize::Error> {
        self.0.input(&[v]);
        Ok(())
    }

    fn emit_bool(&mut self, v: bool) -> Result<(), serialize::Error> {
        self.0.input(&[if v {1} else {0}]);
        Ok(())
    }
}

// This doesn't make much sense to me, but is implicit behaviour
// in the C++ reference client, so we need it for consensus.
impl Default for Sha256dHash {
    #[inline]
    fn default() -> Sha256dHash { Sha256dHash([0u8; 32]) }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Sha256dHash {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::fmt::{self, Formatter};

        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Sha256dHash;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a SHA256d hash")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Sha256dHash::from_hex(v).map_err(E::custom)
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v)
            }
            
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Sha256dHash {
    /// Serialize a `Sha256dHash`.
    ///
    /// Note that this outputs hashes as big endian hex numbers, so this should be
    /// used only for user-facing stuff. Internal and network serialization is
    /// little-endian and should be done using the consensus
    /// [`ConsensusEncodable`][1] interface.
    ///
    /// [1]: ../../network/encodable/trait.ConsensusEncodable.html
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use std::{char, str};

        let mut string = [0; 64];
        for i in 0..32 {
            string[2 * i] = char::from_digit((self.0[31 - i] / 0x10) as u32, 16).unwrap() as u8;
            string[2 * i + 1] = char::from_digit((self.0[31 - i] & 0x0f) as u32, 16).unwrap() as u8;
        }

        let hex_str = unsafe { str::from_utf8_unchecked(&string) };
        serializer.serialize_str(hex_str)
    }
}

// Consensus encoding (no reversing)
impl_newtype_consensus_encoding!(Sha256dHash);

// User RPC/display encoding (reversed)
impl fmt::Display for Sha256dHash {
    /// Output the sha256d hash in reverse, copying Bitcoin Core's behaviour
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl fmt::LowerHex for Sha256dHash {
    /// Output the sha256d hash in reverse, copying Bitcoin Core's behaviour
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let &Sha256dHash(data) = self;
        for ch in data.iter().rev() {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Sha256dHash {
    /// Output the sha256d hash in reverse, copying Bitcoin Core's behaviour
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let &Sha256dHash(data) = self;
        for ch in data.iter().rev() {
            write!(f, "{:02X}", ch)?;
        }
        Ok(())
    }
}


/// Any collection of objects for which a merkle root makes sense to calculate
pub trait MerkleRoot {
    /// Construct a merkle tree from a collection, with elements ordered as
    /// they were in the original collection, and return the merkle root.
    fn merkle_root(&self) -> Sha256dHash;
}

/// Calculates the merkle root of a list of txids hashes directly
pub fn bitcoin_merkle_root(data: Vec<Sha256dHash>) -> Sha256dHash {
    // Base case
    if data.len() < 1 {
        return Default::default();
    }
    if data.len() < 2 {
        return data[0];
    }
    // Recursion
    let mut next = vec![];
    for idx in 0..((data.len() + 1) / 2) {
        let idx1 = 2 * idx;
        let idx2 = min(idx1 + 1, data.len() - 1);
        let mut encoder = RawEncoder::new(Cursor::new(vec![]));
        data[idx1].consensus_encode(&mut encoder).unwrap();
        data[idx2].consensus_encode(&mut encoder).unwrap();
        next.push(encoder.into_inner().into_inner().bitcoin_hash());
    }
    bitcoin_merkle_root(next)
}

impl<'a, T: BitcoinHash> MerkleRoot for &'a [T] {
    fn merkle_root(&self) -> Sha256dHash {
        bitcoin_merkle_root(self.iter().map(|obj| obj.bitcoin_hash()).collect())
    }
}

impl <T: BitcoinHash> MerkleRoot for Vec<T> {
    fn merkle_root(&self) -> Sha256dHash {
        (&self[..]).merkle_root()
    }
}


#[cfg(test)]
mod tests {
    use deps::bitcoin::network::encodable::{ConsensusEncodable, VarInt};
    use deps::bitcoin::network::serialize::{serialize, deserialize};
    use util::uint::Uint256;
    use super::*;

    #[test]
    fn test_sha256d() {
        // nb the 5df6... output is the one you get from sha256sum. this is the
        // "little-endian" hex string since it matches the in-memory representation
        // of a Uint256 (which is little-endian) after transmutation
        assert_eq!(Sha256dHash::from_data(&[]).le_hex_string(),
                   "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");
        assert_eq!(Sha256dHash::from_data(&[]).be_hex_string(),
                   "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d");

        assert_eq!(format!("{}", Sha256dHash::from_data(&[])),
                   "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d");
        assert_eq!(format!("{:?}", Sha256dHash::from_data(&[])),
                   "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");
        assert_eq!(format!("{:x}", Sha256dHash::from_data(&[])),
                   "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d");
        assert_eq!(format!("{:X}", Sha256dHash::from_data(&[])),
                   "56944C5D3F98413EF45CF54545538103CC9F298E0575820AD3591376E2E0F65D");
    }

    #[test]
    fn test_sha256d_data() {
        assert_eq!(
            Sha256dHash::from_data(&[]).as_bytes(),
            &[
                0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3, 0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29,
                0x9f, 0xcc, 0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4, 0x3e, 0x41, 0x98, 0x3f,
                0x5d, 0x4c, 0x94, 0x56,
            ]
        );
    }

    #[test]
    fn sha256d_encoder() {
        let test = vec![true, false, true, true, false];
        let mut enc = Sha256dEncoder::new();
        assert!(test.consensus_encode(&mut enc).is_ok());
        assert_eq!(enc.into_hash(), Sha256dHash::from_data(&serialize(&test).unwrap()));

        macro_rules! array_encode_test (
            ($ty:ty) => ({
                // try serializing the whole array
                let test: [$ty; 1000] = [1; 1000];
                let mut enc = Sha256dEncoder::new();
                assert!((&test[..]).consensus_encode(&mut enc).is_ok());
                assert_eq!(enc.into_hash(), Sha256dHash::from_data(&serialize(&test[..]).unwrap()));

                // try doing it just one object at a time
                let mut enc = Sha256dEncoder::new();
                assert!(VarInt(test.len() as u64).consensus_encode(&mut enc).is_ok());
                for obj in &test[..] {
                    assert!(obj.consensus_encode(&mut enc).is_ok());
                }
                assert_eq!(enc.into_hash(), Sha256dHash::from_data(&serialize(&test[..]).unwrap()));
            })
        );

        array_encode_test!(u64);
        array_encode_test!(u32);
        array_encode_test!(u16);
        array_encode_test!(u8);
        array_encode_test!(i64);
        array_encode_test!(i32);
        array_encode_test!(i16);
        array_encode_test!(i8);
    }

    #[test]
    fn test_consenus_encode_roundtrip() {
        let hash = Sha256dHash::from_data(&[]);
        let serial = serialize(&hash).unwrap();
        let deserial = deserialize(&serial).unwrap();
        assert_eq!(hash, deserial);
    }
}

