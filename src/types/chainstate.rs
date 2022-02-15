use std::fmt;
use std::io::Write;
use std::str::FromStr;

use curve25519_dalek::digest::Digest;
use sha2::Sha512Trunc256;

use util::hash::{to_hex, Hash160, Sha512Trunc256Sum, HASH160_ENCODED_SIZE};
use util::secp256k1::MessageSignature;
use util::vrf::VRFProof;

use rusqlite::types::ToSqlOutput;
use rusqlite::Row;
use rusqlite::ToSql;
use types::proof::TrieHash;
use util::db::Error as db_error;
use util::db::FromColumn;

#[derive(Serialize, Deserialize)]
pub struct BurnchainHeaderHash(pub [u8; 32]);
impl_array_newtype!(BurnchainHeaderHash, u8, 32);
impl_array_hexstring_fmt!(BurnchainHeaderHash);
impl_byte_array_newtype!(BurnchainHeaderHash, u8, 32);

impl BurnchainHeaderHash {
    pub fn zero() -> BurnchainHeaderHash {
        BurnchainHeaderHash([0; 32])
    }
}

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
impl_byte_array_from_column!(SortitionId);
impl_byte_array_message_codec!(SortitionId, 32);

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

pub const STACKS_ADDRESS_ENCODED_SIZE: u32 = 1 + HASH160_ENCODED_SIZE;

/// How much work has gone into this chain so far?
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StacksWorkScore {
    pub burn: u64, // number of burn tokens destroyed
    pub work: u64, // in Stacks, "work" == the length of the fork
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// A list of signatures. Used to allow multiple miners to sign a block or micro-block. Supports
/// various kinds of serialization.
pub struct MessageSignatureList {
    signatures: Vec<MessageSignature>,
}

impl MessageSignatureList {
    pub fn empty() -> MessageSignatureList {
        MessageSignatureList { signatures: vec![] }
    }

    pub fn from_single(signature: MessageSignature) -> MessageSignatureList {
        MessageSignatureList {
            signatures: vec![signature],
        }
    }

    pub fn from_vec(signatures: Vec<MessageSignature>) -> MessageSignatureList {
        MessageSignatureList { signatures }
    }

    pub fn add_signature(&mut self, signature: MessageSignature) {
        self.signatures.push(signature);
    }

    pub fn signatures(&self) -> &Vec<MessageSignature> {
        &self.signatures
    }
}

impl ToSql for MessageSignatureList {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        let val = serde_json::to_string(self).expect("FAIL: could not serialize ExecutionCost");
        Ok(ToSqlOutput::from(val))
    }
}

impl FromColumn<MessageSignatureList> for MessageSignatureList {
    fn from_column<'a>(row: &'a Row, column_name: &str) -> Result<MessageSignatureList, db_error> {
        let string_rep: String = row.get_unwrap(column_name);
        let val: MessageSignatureList = serde_json::from_str(&string_rep)
            .expect("FAIL: could not deserialize MessageSignatureList");
        Ok(val)
    }
}

/// The header for an on-chain-anchored Stacks block
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StacksBlockHeader {
    pub version: u8,
    pub total_work: StacksWorkScore, // NOTE: this is the work done on the chain tip this block builds on (i.e. take this from the parent)
    pub proof: VRFProof,
    pub parent_block: BlockHeaderHash, // NOTE: even though this is also present in the burn chain, we need this here for super-light clients that don't even have burn chain headers
    pub parent_microblock: BlockHeaderHash,
    pub parent_microblock_sequence: u16,
    pub tx_merkle_root: Sha512Trunc256Sum,
    pub state_index_root: TrieHash,
    pub microblock_pubkey_hash: Hash160, // we'll get the public key back from the first signature (note that this is the Hash160 of the _compressed_ public key)
    /// Signatures of miners that have signed this block.
    pub miner_signatures: MessageSignatureList,
}

pub struct StacksBlockId(pub [u8; 32]);
impl_array_newtype!(StacksBlockId, u8, 32);
impl_array_hexstring_fmt!(StacksBlockId);
impl_byte_array_newtype!(StacksBlockId, u8, 32);
impl_byte_array_from_column!(StacksBlockId);
impl_byte_array_serde!(StacksBlockId);

/// Header structure for a microblock
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StacksMicroblockHeader {
    pub version: u8,
    pub sequence: u16,
    pub prev_block: BlockHeaderHash,
    pub tx_merkle_root: Sha512Trunc256Sum,
    /// Signatures of miners that have signed this block.
    pub miner_signatures: MessageSignatureList,
}

/// Structure that holds the actual data in a MARF leaf node.
/// It only stores the hash of some value string, but we add 8 extra bytes for future extensions.
/// If not used (the rule today), then they should all be 0.
pub struct MARFValue(pub [u8; 40]);
impl_array_newtype!(MARFValue, u8, 40);
impl_array_hexstring_fmt!(MARFValue);
impl_byte_array_newtype!(MARFValue, u8, 40);
impl_byte_array_message_codec!(MARFValue, 40);
pub const MARF_VALUE_ENCODED_SIZE: u32 = 40;

impl From<u32> for MARFValue {
    fn from(value: u32) -> MARFValue {
        let h = value.to_le_bytes();
        let mut d = [0u8; MARF_VALUE_ENCODED_SIZE as usize];
        if h.len() > MARF_VALUE_ENCODED_SIZE as usize {
            panic!("Cannot convert a u32 into a MARF Value.");
        }
        for i in 0..h.len() {
            d[i] = h[i];
        }
        MARFValue(d)
    }
}
