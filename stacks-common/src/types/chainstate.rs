use std::fmt;
use std::io::Read;
use std::io::Write;
use std::str::FromStr;

use curve25519_dalek::digest::Digest;
use sha2::{Digest as Sha2Digest, Sha512_256};

use crate::util::hash::{to_hex, Hash160, Sha512Trunc256Sum, HASH160_ENCODED_SIZE};
use crate::util::secp256k1::MessageSignature;
use crate::util::vrf::VRFProof;

use serde::de::Deserialize;
use serde::de::Error as de_Error;
use serde::ser::Error as ser_Error;
use serde::Serialize;

use crate::util::secp256k1::Secp256k1PrivateKey;
use crate::util::secp256k1::Secp256k1PublicKey;
use crate::util::vrf::VRF_PROOF_ENCODED_SIZE;

use crate::codec::{read_next, write_next, Error as CodecError, StacksMessageCodec};

use crate::deps_common::bitcoin::util::hash::Sha256dHash;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};

pub type StacksPublicKey = Secp256k1PublicKey;
pub type StacksPrivateKey = Secp256k1PrivateKey;

/// Hash of a Trie node.  This is a SHA2-512/256.
pub struct TrieHash(pub [u8; 32]);
impl_array_newtype!(TrieHash, u8, 32);
impl_array_hexstring_fmt!(TrieHash);
impl_byte_array_newtype!(TrieHash, u8, 32);
impl_byte_array_serde!(TrieHash);

impl Default for TrieHash {
    fn default() -> TrieHash {
        TrieHash([0x00; 32])
    }
}

pub const TRIEHASH_ENCODED_SIZE: usize = 32;

#[derive(Serialize, Deserialize)]
pub struct BurnchainHeaderHash(pub [u8; 32]);
impl_array_newtype!(BurnchainHeaderHash, u8, 32);
impl_array_hexstring_fmt!(BurnchainHeaderHash);
impl_byte_array_newtype!(BurnchainHeaderHash, u8, 32);

pub struct BlockHeaderHash(pub [u8; 32]);
impl_array_newtype!(BlockHeaderHash, u8, 32);
impl_array_hexstring_fmt!(BlockHeaderHash);
impl_byte_array_newtype!(BlockHeaderHash, u8, 32);
impl_byte_array_serde!(BlockHeaderHash);
pub const BLOCK_HEADER_HASH_ENCODED_SIZE: usize = 32;

/// Identifier used to identify "sortitions" in the
///  SortitionDB. A sortition is the collection of
///  valid burnchain operations (and any dependent
///  variables, e.g., the sortition winner, the
///  consensus hash, the next VRF key)
pub struct SortitionId(pub [u8; 32]);
impl_array_newtype!(SortitionId, u8, 32);
impl_array_hexstring_fmt!(SortitionId);
impl_byte_array_newtype!(SortitionId, u8, 32);
impl_byte_array_rusqlite_only!(SortitionId);

pub struct VRFSeed(pub [u8; 32]);
impl_array_newtype!(VRFSeed, u8, 32);
impl_array_hexstring_fmt!(VRFSeed);
impl_byte_array_newtype!(VRFSeed, u8, 32);
impl_byte_array_serde!(VRFSeed);
pub const VRF_SEED_ENCODED_SIZE: u32 = 32;

/// Identifier used to identify Proof-of-Transfer forks
///  (or Rewards Cycle forks). These identifiers are opaque
///  outside of the PoX DB, however, they are sufficient
///  to uniquely identify a "sortition" when paired with
///  a burn header hash
// TODO: Vec<bool> is an aggressively unoptimized implementation,
//       replace with a real bitvec
#[derive(Clone, Debug, PartialEq)]
pub struct PoxId(Vec<bool>);

impl SortitionId {
    pub fn stubbed(from: &BurnchainHeaderHash) -> SortitionId {
        SortitionId::new(from, &PoxId::stubbed())
    }

    pub fn new(bhh: &BurnchainHeaderHash, pox: &PoxId) -> SortitionId {
        if pox == &PoxId::stubbed() {
            SortitionId(bhh.0.clone())
        } else {
            let mut hasher = Sha512_256::new();
            hasher.update(bhh);
            write!(hasher, "{}", pox).expect("Failed to deserialize PoX ID into the hasher");
            let h = Sha512Trunc256Sum::from_hasher(hasher);
            SortitionId(h.0)
        }
    }
}

impl PoxId {
    pub fn new(contents: Vec<bool>) -> Self {
        PoxId(contents)
    }

    pub fn initial() -> PoxId {
        PoxId(vec![true])
    }

    pub fn from_bools(bools: Vec<bool>) -> PoxId {
        PoxId(bools)
    }

    pub fn extend_with_present_block(&mut self) {
        self.0.push(true);
    }
    pub fn extend_with_not_present_block(&mut self) {
        self.0.push(false);
    }

    pub fn stubbed() -> PoxId {
        PoxId(vec![])
    }

    pub fn has_ith_anchor_block(&self, i: usize) -> bool {
        if i >= self.0.len() {
            false
        } else {
            self.0[i]
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn bit_slice(&self, start: usize, len: usize) -> (Vec<u8>, u64) {
        let mut ret = vec![0x00];
        let mut count = 0;
        for bit in start..(start + len) {
            if bit >= self.len() {
                break;
            }
            let i = bit - start;
            if i > 0 && i % 8 == 0 {
                ret.push(0x00);
            }

            let sz = ret.len() - 1;
            if self.0[bit] {
                ret[sz] |= 1 << (i % 8);
            }
            count += 1;
        }
        (ret, count)
    }

    pub fn num_inventory_reward_cycles(&self) -> usize {
        self.0.len().saturating_sub(1)
    }
}

impl FromStr for PoxId {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = vec![];
        for i in s.chars() {
            if i == '1' {
                result.push(true);
            } else if i == '0' {
                result.push(false);
            } else {
                return Err("Unexpected character in PoX ID serialization");
            }
        }
        Ok(PoxId::new(result))
    }
}

impl fmt::Display for PoxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for val in self.0.iter() {
            write!(f, "{}", if *val { 1 } else { 0 })?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Hash)]
pub struct StacksAddress {
    pub version: u8,
    pub bytes: Hash160,
}

impl StacksMessageCodec for StacksAddress {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.version)?;
        fd.write_all(self.bytes.as_bytes())
            .map_err(CodecError::WriteError)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksAddress, CodecError> {
        let version: u8 = read_next(fd)?;
        let hash160: Hash160 = read_next(fd)?;
        Ok(StacksAddress {
            version: version,
            bytes: hash160,
        })
    }
}

pub const STACKS_ADDRESS_ENCODED_SIZE: u32 = 1 + HASH160_ENCODED_SIZE;

/// How much work has gone into this chain so far?
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StacksWorkScore {
    pub burn: u64, // number of burn tokens destroyed
    pub work: u64, // in Stacks, "work" == the length of the fork
}

pub struct StacksBlockId(pub [u8; 32]);
impl_array_newtype!(StacksBlockId, u8, 32);
impl_array_hexstring_fmt!(StacksBlockId);
impl_byte_array_newtype!(StacksBlockId, u8, 32);
impl_byte_array_rusqlite_only!(StacksBlockId);
impl_byte_array_serde!(StacksBlockId);

pub struct ConsensusHash(pub [u8; 20]);
impl_array_newtype!(ConsensusHash, u8, 20);
impl_array_hexstring_fmt!(ConsensusHash);
impl_byte_array_newtype!(ConsensusHash, u8, 20);
impl_byte_array_serde!(ConsensusHash);

pub const CONSENSUS_HASH_ENCODED_SIZE: u32 = 20;

impl StacksBlockId {
    pub fn new(
        sortition_consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> StacksBlockId {
        let mut hasher = Sha512_256::new();
        hasher.update(block_hash);
        hasher.update(sortition_consensus_hash);

        let h = Sha512Trunc256Sum::from_hasher(hasher);
        StacksBlockId(h.0)
    }
}

impl StacksWorkScore {
    /// Stacks work score for the first-mined block
    pub fn initial() -> StacksWorkScore {
        StacksWorkScore {
            burn: 0,
            work: 1, // block 0 is the boot code
        }
    }

    /// Stacks work score for the boot code block
    pub fn genesis() -> StacksWorkScore {
        StacksWorkScore { burn: 0, work: 0 }
    }
}

impl StacksMessageCodec for VRFProof {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        fd.write_all(&self.to_bytes())
            .map_err(CodecError::WriteError)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<VRFProof, CodecError> {
        let mut bytes = [0u8; VRF_PROOF_ENCODED_SIZE as usize];
        fd.read_exact(&mut bytes).map_err(CodecError::ReadError)?;
        let res = VRFProof::from_slice(&bytes).ok_or(CodecError::DeserializeError(
            "Failed to parse VRF proof".to_string(),
        ))?;

        Ok(res)
    }
}

impl StacksMessageCodec for StacksWorkScore {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.burn)?;
        write_next(fd, &self.work)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksWorkScore, CodecError> {
        let burn = read_next(fd)?;
        let work = read_next(fd)?;

        Ok(StacksWorkScore { burn, work })
    }
}

// Implement rusqlite traits for a bunch of structs that used to be defined
//  in the chainstate code
impl_byte_array_rusqlite_only!(ConsensusHash);
impl_byte_array_rusqlite_only!(Hash160);
impl_byte_array_rusqlite_only!(BlockHeaderHash);
impl_byte_array_rusqlite_only!(VRFSeed);
impl_byte_array_rusqlite_only!(BurnchainHeaderHash);
impl_byte_array_rusqlite_only!(VRFProof);
impl_byte_array_rusqlite_only!(TrieHash);
impl_byte_array_rusqlite_only!(Sha512Trunc256Sum);
impl_byte_array_rusqlite_only!(MessageSignature);

impl_byte_array_message_codec!(TrieHash, TRIEHASH_ENCODED_SIZE as u32);
impl_byte_array_message_codec!(Sha512Trunc256Sum, 32);

impl_byte_array_message_codec!(ConsensusHash, 20);
impl_byte_array_message_codec!(Hash160, 20);
impl_byte_array_message_codec!(BurnchainHeaderHash, 32);
impl_byte_array_message_codec!(BlockHeaderHash, 32);
impl_byte_array_message_codec!(StacksBlockId, 32);
impl_byte_array_message_codec!(MessageSignature, 65);

impl BlockHeaderHash {
    pub fn to_hash160(&self) -> Hash160 {
        Hash160::from_sha256(&self.0)
    }

    pub fn from_serialized_header(buf: &[u8]) -> BlockHeaderHash {
        let h = Sha512Trunc256Sum::from_data(buf);
        let mut b = [0u8; 32];
        b.copy_from_slice(h.as_bytes());
        BlockHeaderHash(b)
    }
}

impl BurnchainHeaderHash {
    /// Instantiate a burnchain block hash from a Bitcoin block header
    pub fn from_bitcoin_hash(bitcoin_hash: &Sha256dHash) -> BurnchainHeaderHash {
        // NOTE: Sha256dhash is the same size as BurnchainHeaderHash, so this should never panic
        BurnchainHeaderHash::from_bytes_be(bitcoin_hash.as_bytes()).unwrap()
    }

    pub fn zero() -> BurnchainHeaderHash {
        BurnchainHeaderHash([0x00; 32])
    }
}

impl FromSql for Sha256dHash {
    fn column_result(value: ValueRef) -> FromSqlResult<Sha256dHash> {
        let hex_str = value.as_str()?;
        let hash = Sha256dHash::from_hex(hex_str).map_err(|_e| FromSqlError::InvalidType)?;
        Ok(hash)
    }
}

impl ToSql for Sha256dHash {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        let hex_str = self.be_hex_string();
        Ok(hex_str.into())
    }
}

impl VRFSeed {
    /// First-ever VRF seed from the genesis block.  It's all 0's
    pub fn initial() -> VRFSeed {
        VRFSeed::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
    }

    pub fn from_proof(proof: &VRFProof) -> VRFSeed {
        let h = Sha512Trunc256Sum::from_data(&proof.to_bytes());
        VRFSeed(h.0)
    }

    pub fn is_from_proof(&self, proof: &VRFProof) -> bool {
        self.as_bytes().to_vec() == VRFSeed::from_proof(proof).as_bytes().to_vec()
    }
}

impl StacksMessageCodec for (ConsensusHash, BurnchainHeaderHash) {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.0)?;
        write_next(fd, &self.1)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(
        fd: &mut R,
    ) -> Result<(ConsensusHash, BurnchainHeaderHash), CodecError> {
        let consensus_hash: ConsensusHash = read_next(fd)?;
        let burn_header_hash: BurnchainHeaderHash = read_next(fd)?;
        Ok((consensus_hash, burn_header_hash))
    }
}
