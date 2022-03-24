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

use std::error;
use std::fmt;
use std::hash::Hash;
use std::io;
use std::io::{Seek, SeekFrom};
use std::ptr;

use sha2::Digest;
use sha2::Sha512_256 as TrieHasher;

use crate::util_lib::db::Error as db_error;
use stacks_common::util::hash::to_hex;
use stacks_common::util::log;

use crate::types::chainstate::BlockHeaderHash;
use crate::types::chainstate::BurnchainHeaderHash;
use crate::types::chainstate::SortitionId;
use crate::types::chainstate::StacksBlockId;
use crate::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};

pub mod bits;
pub mod marf;
pub mod node;
pub mod proofs;
pub mod storage;
pub mod trie;
pub mod trie_sql;

#[derive(Debug)]
pub struct TrieMerkleProof<T: MarfTrieId>(pub Vec<TrieMerkleProofType<T>>);

pub trait ClarityMarfTrieId:
    PartialEq + Clone + std::fmt::Display + std::fmt::Debug + std::convert::From<[u8; 32]>
{
    fn as_bytes(&self) -> &[u8];
    fn to_bytes(self) -> [u8; 32];
    fn from_bytes(from: [u8; 32]) -> Self;
    fn sentinel() -> Self;
}

#[derive(Clone)]
pub enum TrieMerkleProofType<T> {
    Node4((u8, ProofTrieNode<T>, [TrieHash; 3])),
    Node16((u8, ProofTrieNode<T>, [TrieHash; 15])),
    Node48((u8, ProofTrieNode<T>, [TrieHash; 47])),
    Node256((u8, ProofTrieNode<T>, [TrieHash; 255])),
    Leaf((u8, TrieLeaf)),
    Shunt((i64, Vec<TrieHash>)),
}

/// Merkle Proof Trie Pointers have a different structure
///   than the runtime representation --- the proof includes
///   the block header hash for back pointers.
#[derive(Debug, Clone, PartialEq)]
pub struct ProofTrieNode<T> {
    pub id: u8,
    pub path: Vec<u8>,
    pub ptrs: Vec<ProofTriePtr<T>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProofTriePtr<T> {
    pub id: u8,
    pub chr: u8,
    pub back_block: T,
}

/// Leaf of a Trie.
#[derive(Clone)]
pub struct TrieLeaf {
    pub path: Vec<u8>,   // path to be lazily expanded
    pub data: MARFValue, // the actual data
}

pub trait MarfTrieId:
    ClarityMarfTrieId
    + rusqlite::types::ToSql
    + rusqlite::types::FromSql
    + crate::codec::StacksMessageCodec
    + std::convert::From<MARFValue>
{
}

pub const SENTINEL_ARRAY: [u8; 32] = [255u8; 32];

macro_rules! impl_clarity_marf_trie_id {
    ($thing:ident) => {
        impl ClarityMarfTrieId for $thing {
            fn as_bytes(&self) -> &[u8] {
                self.as_ref()
            }
            fn to_bytes(self) -> [u8; 32] {
                self.0
            }
            fn sentinel() -> Self {
                Self(SENTINEL_ARRAY.clone())
            }
            fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl From<MARFValue> for $thing {
            fn from(m: MARFValue) -> Self {
                let h = m.0;
                let mut d = [0u8; 32];
                for i in 0..32 {
                    d[i] = h[i];
                }
                for i in 32..h.len() {
                    if h[i] != 0 {
                        panic!(
                            "Failed to convert MARF value into BHH: data stored after 32nd byte"
                        );
                    }
                }
                Self(d)
            }
        }
    };
}

impl_clarity_marf_trie_id!(BurnchainHeaderHash);
impl_clarity_marf_trie_id!(StacksBlockId);
impl_clarity_marf_trie_id!(SortitionId);
#[cfg(test)]
impl_clarity_marf_trie_id!(BlockHeaderHash);

impl MarfTrieId for SortitionId {}
impl MarfTrieId for StacksBlockId {}
impl MarfTrieId for BurnchainHeaderHash {}
#[cfg(test)]
impl MarfTrieId for BlockHeaderHash {}

pub trait TrieHashExtension {
    fn from_empty_data() -> TrieHash;
    fn from_data(data: &[u8]) -> TrieHash;
    fn from_data_array<B: AsRef<[u8]>>(data: &[B]) -> TrieHash;
    fn to_string(&self) -> String;
}

impl TrieHashExtension for TrieHash {
    /// TrieHash of zero bytes
    fn from_empty_data() -> TrieHash {
        // sha2-512/256 hash of empty string.
        // this is used so frequently it helps performance if we just have a constant for it.
        TrieHash([
            0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28, 0xab, 0x87, 0xc3, 0x62, 0x2c, 0x51,
            0x14, 0x06, 0x9b, 0xdd, 0x3a, 0xd7, 0xb8, 0xf9, 0x73, 0x74, 0x98, 0xd0, 0xc0, 0x1e,
            0xce, 0xf0, 0x96, 0x7a,
        ])
    }

    /// TrieHash from bytes
    fn from_data(data: &[u8]) -> TrieHash {
        if data.len() == 0 {
            return TrieHash::from_empty_data();
        }

        let mut tmp = [0u8; 32];

        let mut hasher = TrieHasher::new();
        hasher.update(data);
        tmp.copy_from_slice(hasher.finalize().as_slice());

        TrieHash(tmp)
    }

    fn from_data_array<B: AsRef<[u8]>>(data: &[B]) -> TrieHash {
        if data.len() == 0 {
            return TrieHash::from_empty_data();
        }

        let mut tmp = [0u8; 32];

        let mut hasher = TrieHasher::new();

        for item in data.iter() {
            hasher.update(item);
        }
        tmp.copy_from_slice(hasher.finalize().as_slice());
        TrieHash(tmp)
    }

    /// Convert to a String that can be used in e.g. sqlite
    fn to_string(&self) -> String {
        let s = format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                          self.0[0],     self.0[1],       self.0[2],       self.0[3],
                          self.0[4],     self.0[5],       self.0[6],       self.0[7],
                          self.0[8],     self.0[9],       self.0[10],      self.0[11],
                          self.0[12],    self.0[13],      self.0[14],      self.0[15],
                          self.0[16],    self.0[17],      self.0[18],      self.0[19],
                          self.0[20],    self.0[21],      self.0[22],      self.0[23],
                          self.0[24],    self.0[25],      self.0[26],      self.0[27],
                          self.0[28],    self.0[29],      self.0[30],      self.0[31]);
        s
    }
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

impl<T: MarfTrieId> From<T> for MARFValue {
    fn from(bhh: T) -> MARFValue {
        let h = bhh.to_bytes();
        let mut d = [0u8; MARF_VALUE_ENCODED_SIZE as usize];
        if h.len() > MARF_VALUE_ENCODED_SIZE as usize {
            panic!("Cannot convert a BHH into a MARF Value.");
        }
        for i in 0..h.len() {
            d[i] = h[i];
        }
        MARFValue(d)
    }
}

impl From<MARFValue> for u32 {
    fn from(m: MARFValue) -> u32 {
        let h = m.0;
        let mut d = [0u8; 4];
        for i in 0..4 {
            d[i] = h[i];
        }
        for i in 4..h.len() {
            if h[i] != 0 {
                panic!("Failed to convert MARF value into u32: data stored after 4th byte");
            }
        }
        u32::from_le_bytes(d)
    }
}

impl MARFValue {
    /// Construct from a TRIEHASH_ENCODED_SIZE-length slice
    pub fn from_value_hash_bytes(h: &[u8; TRIEHASH_ENCODED_SIZE]) -> MARFValue {
        let mut d = [0u8; MARF_VALUE_ENCODED_SIZE as usize];
        for i in 0..TRIEHASH_ENCODED_SIZE {
            d[i] = h[i];
        }
        MARFValue(d)
    }

    /// Construct from a TrieHash
    pub fn from_value_hash(h: &TrieHash) -> MARFValue {
        MARFValue::from_value_hash_bytes(h.as_bytes())
    }

    /// Construct from a String that encodes a value inserted into the underlying data store
    pub fn from_value(s: &str) -> MARFValue {
        let mut tmp = [0u8; 32];

        let mut hasher = TrieHasher::new();
        hasher.update(s.as_bytes());
        tmp.copy_from_slice(hasher.finalize().as_slice());

        MARFValue::from_value_hash_bytes(&tmp)
    }

    /// Convert to a byte vector
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    /// Extract the value hash from the MARF value
    pub fn to_value_hash(&self) -> TrieHash {
        let mut h = [0u8; TRIEHASH_ENCODED_SIZE];
        h.copy_from_slice(&self.0[0..TRIEHASH_ENCODED_SIZE]);
        TrieHash(h)
    }
}

#[derive(Debug)]
pub enum Error {
    NotOpenedError,
    IOError(io::Error),
    SQLError(rusqlite::Error),
    RequestedIdentifierForExtensionTrie,
    NotFoundError,
    BackptrNotFoundError,
    ExistsError,
    BadSeekValue,
    CorruptionError(String),
    BlockHashMapCorruptionError(Option<Box<Error>>),
    ReadOnlyError,
    UnconfirmedError,
    NotDirectoryError,
    PartialWriteError,
    InProgressError,
    WriteNotBegunError,
    CursorError(node::CursorError),
    RestoreMarfBlockError(Box<Error>),
    NonMatchingForks([u8; 32], [u8; 32]),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IOError(err)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Self {
        if let rusqlite::Error::QueryReturnedNoRows = err {
            Error::NotFoundError
        } else {
            Error::SQLError(err)
        }
    }
}

impl From<db_error> for Error {
    fn from(e: db_error) -> Error {
        match e {
            db_error::SqliteError(se) => Error::SQLError(se),
            db_error::NotFoundError => Error::NotFoundError,
            _ => Error::CorruptionError(format!("{}", &e)),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IOError(ref e) => fmt::Display::fmt(e, f),
            Error::SQLError(ref e) => fmt::Display::fmt(e, f),
            Error::CorruptionError(ref s) => fmt::Display::fmt(s, f),
            Error::CursorError(ref e) => fmt::Display::fmt(e, f),
            Error::BlockHashMapCorruptionError(ref opt_e) => {
                f.write_str("Corrupted MARF BlockHashMap")?;
                match opt_e {
                    Some(e) => write!(f, ": {}", e),
                    None => Ok(()),
                }
            }
            Error::NotOpenedError => write!(f, "Tried to read data from unopened storage"),
            Error::NotFoundError => write!(f, "Object not found"),
            Error::BackptrNotFoundError => write!(f, "Object not found from backptrs"),
            Error::ExistsError => write!(f, "Object exists"),
            Error::BadSeekValue => write!(f, "Bad seek value"),
            Error::ReadOnlyError => write!(f, "Storage is in read-only mode"),
            Error::UnconfirmedError => write!(f, "Storage is in unconfirmed mode"),
            Error::NotDirectoryError => write!(f, "Not a directory"),
            Error::PartialWriteError => {
                write!(f, "Data is partially written and not yet recovered")
            }
            Error::InProgressError => write!(f, "Write was in progress"),
            Error::WriteNotBegunError => write!(f, "Write has not begun"),
            Error::RestoreMarfBlockError(_) => write!(
                f,
                "Failed to restore previous open block during block header check"
            ),
            Error::NonMatchingForks(_, _) => {
                write!(f, "The supplied blocks are not in the same fork")
            }
            Error::RequestedIdentifierForExtensionTrie => {
                write!(f, "BUG: MARF requested the identifier for a RAM trie")
            }
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::IOError(ref e) => Some(e),
            Error::SQLError(ref e) => Some(e),
            Error::RestoreMarfBlockError(ref e) => Some(e),
            Error::BlockHashMapCorruptionError(ref opt_e) => match opt_e {
                Some(ref e) => Some(e),
                None => None,
            },
            _ => None,
        }
    }
}

pub trait BlockMap {
    type TrieId: MarfTrieId;
    fn get_block_hash(&self, id: u32) -> Result<Self::TrieId, Error>;
    fn get_block_hash_caching(&mut self, id: u32) -> Result<&Self::TrieId, Error>;
}

#[cfg(test)]
impl BlockMap for () {
    type TrieId = BlockHeaderHash;
    fn get_block_hash(&self, _id: u32) -> Result<BlockHeaderHash, Error> {
        Err(Error::NotFoundError)
    }
    fn get_block_hash_caching(&mut self, _id: u32) -> Result<&BlockHeaderHash, Error> {
        Err(Error::NotFoundError)
    }
}

// test infrastructure common to multiple files in the index
#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::io::{Cursor, Seek, SeekFrom};

    use crate::chainstate::stacks::index::bits::*;
    use crate::chainstate::stacks::index::marf::*;
    use crate::chainstate::stacks::index::node::*;
    use crate::chainstate::stacks::index::proofs::*;
    use crate::chainstate::stacks::index::storage::*;
    use crate::chainstate::stacks::index::trie::*;

    use super::*;

    /// Print out a trie to stderr
    pub fn dump_trie(s: &mut TrieStorageConnection<BlockHeaderHash>) -> () {
        test_debug!("\n----- BEGIN TRIE ------");

        fn space(cnt: usize) -> String {
            let mut ret = vec![];
            for _ in 0..cnt {
                ret.push(" ".to_string());
            }
            ret.join("")
        }

        let root_ptr = s.root_ptr();
        let mut frontier: Vec<(TrieNodeType, usize)> = vec![];
        let (root, _) = Trie::read_root(s).unwrap();
        frontier.push((root, 0));

        while frontier.len() > 0 {
            let (next, depth) = frontier.pop().unwrap();
            let (ptrs, path_len) = match next {
                TrieNodeType::Leaf(ref leaf_data) => {
                    test_debug!("{}{:?}", &space(depth), leaf_data);
                    (vec![], leaf_data.path.len())
                }
                TrieNodeType::Node4(ref data) => {
                    test_debug!("{}{:?}", &space(depth), data);
                    (data.ptrs.to_vec(), data.path.len())
                }
                TrieNodeType::Node16(ref data) => {
                    test_debug!("{}{:?}", &space(depth), data);
                    (data.ptrs.to_vec(), data.path.len())
                }
                TrieNodeType::Node48(ref data) => {
                    test_debug!("{}{:?}", &space(depth), data);
                    (data.ptrs.to_vec(), data.path.len())
                }
                TrieNodeType::Node256(ref data) => {
                    test_debug!("{}{:?}", &space(depth), data);
                    (data.ptrs.to_vec(), data.path.len())
                }
            };
            for ptr in ptrs.iter() {
                if ptr.id() == TrieNodeID::Empty as u8 {
                    continue;
                }
                if !is_backptr(ptr.id()) {
                    let (child_node, _) = s.read_nodetype(ptr).unwrap();
                    frontier.push((child_node, depth + path_len + 1));
                }
            }
        }

        test_debug!("----- END TRIE ------\n");
    }

    pub fn merkle_test(
        s: &mut TrieStorageConnection<BlockHeaderHash>,
        path: &Vec<u8>,
        value: &Vec<u8>,
    ) -> () {
        let (_, root_hash) = Trie::read_root(s).unwrap();
        let triepath = TriePath::from_bytes(&path[..]).unwrap();

        let block_header = BlockHeaderHash([0u8; 32]);
        s.open_block(&block_header).unwrap();

        let mut marf_value = [0u8; 40];
        marf_value.copy_from_slice(&value[0..40]);

        let proof =
            TrieMerkleProof::from_path(s, &triepath, &MARFValue(marf_value.clone()), &block_header)
                .unwrap();
        let empty_root_to_block = HashMap::new();

        assert!(proof.verify(
            &triepath,
            &MARFValue(marf_value.clone()),
            &root_hash,
            &empty_root_to_block
        ));
    }

    pub fn merkle_test_marf(
        s: &mut TrieStorageConnection<BlockHeaderHash>,
        header: &BlockHeaderHash,
        path: &Vec<u8>,
        value: &Vec<u8>,
        root_to_block: Option<HashMap<TrieHash, BlockHeaderHash>>,
    ) -> HashMap<TrieHash, BlockHeaderHash> {
        test_debug!("---------");
        test_debug!(
            "MARF merkle prove: merkle_test_marf({:?}, {:?}, {:?})?",
            header,
            path,
            value
        );
        test_debug!("---------");

        s.open_block(header).unwrap();
        let (_, root_hash) = Trie::read_root(s).unwrap();
        let triepath = TriePath::from_bytes(&path[..]).unwrap();

        let mut marf_value = [0u8; 40];
        marf_value.copy_from_slice(&value[0..40]);

        let proof =
            TrieMerkleProof::from_path(s, &triepath, &MARFValue(marf_value), header).unwrap();

        test_debug!("---------");
        test_debug!("MARF merkle verify: {:?}", &proof);
        test_debug!("MARF merkle verify target root hash: {:?}", &root_hash);
        test_debug!("MARF merkle verify source block: {:?}", header);
        test_debug!("---------");

        let root_to_block = root_to_block.unwrap_or_else(|| s.read_root_to_block_table().unwrap());

        assert!(proof.verify(
            &triepath,
            &MARFValue(marf_value),
            &root_hash,
            &root_to_block
        ));

        root_to_block
    }

    pub fn merkle_test_marf_key_value(
        s: &mut TrieStorageConnection<BlockHeaderHash>,
        header: &BlockHeaderHash,
        key: &String,
        value: &String,
        root_to_block: Option<HashMap<TrieHash, BlockHeaderHash>>,
    ) -> HashMap<TrieHash, BlockHeaderHash> {
        test_debug!("---------");
        test_debug!(
            "MARF merkle prove: merkle_test_marf({:?}, {:?}, {:?})?",
            header,
            key,
            value
        );
        test_debug!("---------");

        s.open_block(header).unwrap();
        let (_, root_hash) = Trie::read_root(s).unwrap();
        let proof = TrieMerkleProof::from_entry(s, key, value, &header).unwrap();

        test_debug!("---------");
        test_debug!("MARF merkle verify: {:?}", &proof);
        test_debug!("MARF merkle verify target root hash: {:?}", &root_hash);
        test_debug!("MARF merkle verify source block: {:?}", header);
        test_debug!("---------");

        let root_to_block = root_to_block.unwrap_or_else(|| s.read_root_to_block_table().unwrap());
        let triepath = TriePath::from_key(key);
        let marf_value = MARFValue::from_value(value);

        assert!(proof.verify(&triepath, &marf_value, &root_hash, &root_to_block));

        root_to_block
    }

    pub fn make_node_path(
        s: &mut TrieStorageConnection<BlockHeaderHash>,
        node_id: u8,
        path_segments: &Vec<(Vec<u8>, u8)>,
        leaf_data: Vec<u8>,
    ) -> (Vec<TrieNodeType>, Vec<TriePtr>, Vec<TrieHash>) {
        // make a fully-fleshed-out path of node's to a leaf
        let root_ptr = s.root_ptr();
        let root = TrieNode256::new(&path_segments[0].0);
        let root_hash = TrieHash::from_data(&[0u8; 32]); // don't care about this in this test
        s.write_node(root_ptr, &root, root_hash.clone()).unwrap();

        let mut parent = TrieNodeType::Node256(Box::new(root));
        let mut parent_ptr = root_ptr;

        let mut nodes = vec![];
        let mut node_ptrs = vec![];
        let mut hashes = vec![];
        let mut seg_id = 0;

        for i in 0..path_segments.len() - 1 {
            let path_segment = &path_segments[i + 1].0;
            let chr = path_segments[i].1;
            // let node_ptr = ftell(s).unwrap();
            let node_ptr = s.last_ptr().unwrap();

            let node = match TrieNodeID::from_u8(node_id).unwrap() {
                TrieNodeID::Node4 => TrieNodeType::Node4(TrieNode4::new(path_segment)),
                TrieNodeID::Node16 => TrieNodeType::Node16(TrieNode16::new(path_segment)),
                TrieNodeID::Node48 => TrieNodeType::Node48(Box::new(TrieNode48::new(path_segment))),
                TrieNodeID::Node256 => {
                    TrieNodeType::Node256(Box::new(TrieNode256::new(path_segment)))
                }
                _ => panic!("invalid node ID"),
            };

            s.write_nodetype(
                node_ptr,
                &node,
                TrieHash::from_data(&[(seg_id + 1) as u8; 32]),
            )
            .unwrap();

            // update parent
            match parent {
                TrieNodeType::Node256(ref mut data) => {
                    assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32)))
                }
                TrieNodeType::Node48(ref mut data) => {
                    assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32)))
                }
                TrieNodeType::Node16(ref mut data) => {
                    assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32)))
                }
                TrieNodeType::Node4(ref mut data) => {
                    assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32)))
                }
                TrieNodeType::Leaf(_) => panic!("can't insert into leaf"),
            };

            s.write_nodetype(
                parent_ptr,
                &parent,
                TrieHash::from_data(&[seg_id as u8; 32]),
            )
            .unwrap();

            nodes.push(parent.clone());
            node_ptrs.push(TriePtr::new(node_id, chr, node_ptr as u32));
            hashes.push(TrieHash::from_data(&[(seg_id + 1) as u8; 32]));

            parent = node;
            parent_ptr = node_ptr;

            seg_id += 1;
        }

        // add a leaf at the end
        let child = TrieLeaf::new(&path_segments[path_segments.len() - 1].0, &leaf_data);
        let child_chr = path_segments[path_segments.len() - 1].1;
        // let child_ptr = ftell(s).unwrap();
        let child_ptr = s.last_ptr().unwrap();
        s.write_node(
            child_ptr,
            &child,
            TrieHash::from_data(&[(seg_id + 1) as u8; 32]),
        )
        .unwrap();

        // update parent
        match parent {
            TrieNodeType::Node256(ref mut data) => assert!(data.insert(&TriePtr::new(
                TrieNodeID::Leaf as u8,
                child_chr,
                child_ptr as u32
            ))),
            TrieNodeType::Node48(ref mut data) => assert!(data.insert(&TriePtr::new(
                TrieNodeID::Leaf as u8,
                child_chr,
                child_ptr as u32
            ))),
            TrieNodeType::Node16(ref mut data) => assert!(data.insert(&TriePtr::new(
                TrieNodeID::Leaf as u8,
                child_chr,
                child_ptr as u32
            ))),
            TrieNodeType::Node4(ref mut data) => assert!(data.insert(&TriePtr::new(
                TrieNodeID::Leaf as u8,
                child_chr,
                child_ptr as u32
            ))),
            TrieNodeType::Leaf(_) => panic!("can't insert into leaf"),
        };

        s.write_nodetype(
            parent_ptr,
            &parent,
            TrieHash::from_data(&[(seg_id) as u8; 32]),
        )
        .unwrap();

        nodes.push(parent.clone());
        node_ptrs.push(TriePtr::new(
            TrieNodeID::Leaf as u8,
            child_chr,
            child_ptr as u32,
        ));
        hashes.push(TrieHash::from_data(&[(seg_id + 1) as u8; 32]));

        (nodes, node_ptrs, hashes)
    }

    pub fn make_node4_path(
        s: &mut TrieStorageConnection<BlockHeaderHash>,
        path_segments: &Vec<(Vec<u8>, u8)>,
        leaf_data: Vec<u8>,
    ) -> (Vec<TrieNodeType>, Vec<TriePtr>, Vec<TrieHash>) {
        make_node_path(s, TrieNodeID::Node4 as u8, path_segments, leaf_data)
    }
}
