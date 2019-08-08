/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

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

pub mod bits;
pub mod fork_table;
pub mod marf;
pub mod node;
pub mod proofs;
pub mod storage;
pub mod trie;

use std::fmt;
use std::error;
use std::ptr;
use std::io;
use std::io::{
    Seek,
    SeekFrom
};

use sha2::Sha512Trunc256 as TrieHasher;
use sha2::Digest;

use chainstate::burn::BlockHeaderHash;

use util::log;

/// Fast extend-from-slice for bytes.  Basically, this is memcpy(3).
/// This is similar to the private append_elements() method in the Vec struct,
/// but noticeably faster in that it requires that target already have sufficient capacity.
/// Based on https://doc.rust-lang.org/std/ptr/fn.copy_nonoverlapping.html
///
/// This method requires that target has enough space to store src, and will panic if not.
#[inline]
pub fn fast_extend_from_slice(target: &mut Vec<u8>, src: &[u8]) -> () {
    if target.capacity() < target.len() + src.len() {
        error!("target.capacity() ({}) < target.len() ({}) + src.len() ({})", target.capacity(), target.len(), src.len());
        assert!(target.capacity() >= target.len() + src.len());
    }
    let target_len = target.len();
    let src_len = src.len();
    let new_len = target_len + src_len;
    unsafe {
        let target_ptr = target.as_mut_ptr().offset(target_len as isize);
        let src_ptr = src.as_ptr();
        ptr::copy_nonoverlapping(src_ptr, target_ptr, src_len);
        target.set_len(new_len);
    }
}

/// Hash of a Trie node.  This is a SHA2-512/256.
pub struct TrieHash(pub [u8; 32]);
impl_array_newtype!(TrieHash, u8, 32);
impl_array_hexstring_fmt!(TrieHash);
impl_byte_array_newtype!(TrieHash, u8, 32);
pub const TRIEHASH_ENCODED_SIZE : usize = 32;

/// Structure that holds the actual data in a MARF leaf node.
/// It only stores the hash of some value string, but we add 8 extra bytes for future extensions.
/// If not used (the rule today), then they should all be 0.
pub struct MARFValue(pub [u8; 40]);
impl_array_newtype!(MARFValue, u8, 40);
impl_array_hexstring_fmt!(MARFValue);
impl_byte_array_newtype!(MARFValue, u8, 40);
pub const MARF_VALUE_ENCODED_SIZE : u32 = 40;

impl TrieHash {
    /// TrieHash of zero bytes
    #[inline]
    fn from_empty_data() -> TrieHash {
        // sha2-512/256 hash of empty string.
        // this is used so frequently it helps performance if we just have a constant for it.
        TrieHash([0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28, 0xab, 0x87, 0xc3, 0x62, 0x2c, 0x51, 0x14, 0x06, 0x9b, 0xdd, 0x3a, 0xd7, 0xb8, 0xf9, 0x73, 0x74, 0x98, 0xd0, 0xc0, 0x1e, 0xce, 0xf0, 0x96, 0x7a])
    }

    /// TrieHash from bytes
    pub fn from_data(data: &[u8]) -> TrieHash {
        if data.len() == 0 {
            return TrieHash::from_empty_data();
        }
        
        let mut tmp = [0u8; 32];
       
        let mut hasher = TrieHasher::new();
        hasher.input(data);
        tmp.copy_from_slice(hasher.result().as_slice());

        TrieHash(tmp)
    }

    /// Convert to a String that can be used in e.g. sqlite
    pub fn to_string(&self) -> String {
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
        hasher.input(s.as_bytes());
        tmp.copy_from_slice(hasher.result().as_slice());

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
    IOError(io::Error),
    NotFoundError,
    BackptrNotFoundError,
    ExistsError,
    BadSeekValue,
    CorruptionError(String),
    ReadOnlyError,
    NotDirectoryError,
    PartialWriteError,
    InProgressError,
    WriteNotBegunError,
    CursorError(node::CursorError)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IOError(ref e) => fmt::Display::fmt(e, f),
            Error::NotFoundError => f.write_str(error::Error::description(self)),
            Error::BackptrNotFoundError => f.write_str(error::Error::description(self)),
            Error::ExistsError => f.write_str(error::Error::description(self)),
            Error::BadSeekValue => f.write_str(error::Error::description(self)),
            Error::CorruptionError(ref s) => fmt::Display::fmt(s, f),
            Error::ReadOnlyError => f.write_str(error::Error::description(self)),
            Error::NotDirectoryError => f.write_str(error::Error::description(self)),
            Error::PartialWriteError => f.write_str(error::Error::description(self)),
            Error::InProgressError => f.write_str(error::Error::description(self)),
            Error::WriteNotBegunError => f.write_str(error::Error::description(self)),
            Error::CursorError(ref e) => fmt::Display::fmt(e, f)
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::IOError(ref e) => Some(e),
            Error::NotFoundError => None,
            Error::BackptrNotFoundError => None,
            Error::ExistsError => None,
            Error::BadSeekValue => None,
            Error::CorruptionError(ref _s) => None,
            Error::ReadOnlyError => None,
            Error::NotDirectoryError => None,
            Error::PartialWriteError => None,
            Error::InProgressError => None,
            Error::WriteNotBegunError => None,
            Error::CursorError(ref e) => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::IOError(ref e) => e.description(),
            Error::NotFoundError => "Object not found",
            Error::BackptrNotFoundError => "Object not found from backptrs",
            Error::ExistsError => "Object exists",
            Error::BadSeekValue => "Bad seek value",
            Error::CorruptionError(ref s) => s.as_str(),
            Error::ReadOnlyError => "Storage is in read-only mode",
            Error::NotDirectoryError => "Not a directory",
            Error::PartialWriteError => "Data is partially written and not yet recovered",
            Error::InProgressError => "Write was in progress",
            Error::WriteNotBegunError => "Write has not begun",
            Error::CursorError(ref e) => e.description()
        }
    }
}

/// PartialEq helper method for slices of arbitrary length.
pub fn slice_partialeq<T: PartialEq>(s1: &[T], s2: &[T]) -> bool {
    if s1.len() != s2.len() {
        return false;
    }
    for i in 0..s1.len() {
        if s1[i] != s2[i] {
            return false;
        }
    }
    true
}

// test infrastructure common to multiple files in the index
#[cfg(test)]
mod test {
    use super::*;
    use chainstate::stacks::index::bits::*;
    use chainstate::stacks::index::fork_table::*;
    use chainstate::stacks::index::marf::*;
    use chainstate::stacks::index::node::*;
    use chainstate::stacks::index::proofs::*;
    use chainstate::stacks::index::storage::*;
    use chainstate::stacks::index::trie::*;

    use hashbrown::HashMap;
    use std::io::{
        Cursor,
        Seek,
        SeekFrom
    };

    /// Print out a trie to stderr
    pub fn dump_trie(s: &mut TrieFileStorage) -> () {
        test_debug!("\n----- BEGIN TRIE ------");
        
        fn space(cnt: usize) -> String {
            let mut ret = vec![];
            for _ in 0..cnt {
                ret.push(" ".to_string());
            }
            ret.join("")
        }

        let root_ptr = s.root_ptr();
        let mut frontier : Vec<(TrieNodeType, usize)> = vec![];
        let (root, _) = Trie::read_root(s).unwrap();
        frontier.push((root, 0));

        while frontier.len() > 0 {
            let (next, depth) = frontier.pop().unwrap();
            let (ptrs, path_len) = match next {
                TrieNodeType::Leaf(ref leaf_data) => {
                    test_debug!("{}{:?}", &space(depth), leaf_data);
                    (vec![], leaf_data.path.len())
                },
                TrieNodeType::Node4(ref data) => {
                    test_debug!("{}{:?}", &space(depth), data);
                    (data.ptrs.to_vec(), data.path.len())
                },
                TrieNodeType::Node16(ref data) => {
                    test_debug!("{}{:?}", &space(depth), data);
                    (data.ptrs.to_vec(), data.path.len())
                },
                TrieNodeType::Node48(ref data) => {
                    test_debug!("{}{:?}", &space(depth), data);
                    (data.ptrs.to_vec(), data.path.len())
                },
                TrieNodeType::Node256(ref data) => {
                    test_debug!("{}{:?}", &space(depth), data);
                    (data.ptrs.to_vec(), data.path.len())
                }
            };
            for ptr in ptrs.iter() {
                if ptr.id() == TrieNodeID::Empty {
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

    pub fn merkle_test(s: &mut TrieFileStorage, path: &Vec<u8>, value: &Vec<u8>) -> () {
        let (_, root_hash) = Trie::read_root(s).unwrap();
        let triepath = TriePath::from_bytes(&path[..]).unwrap();

        let block_header = BlockHeaderHash([0u8; 32]);
        s.open_block(&block_header, false).unwrap();

        let mut marf_value = [0u8; 40];
        marf_value.copy_from_slice(&value[0..40]);

        let proof = TrieMerkleProof::from_path(s, &triepath, &MARFValue(marf_value.clone()), &block_header).unwrap();
        let empty_root_to_block = HashMap::new();
        assert!(proof.verify(&triepath, &MARFValue(marf_value.clone()), &root_hash, &empty_root_to_block));
    }
    
    pub fn merkle_test_marf(s: &mut TrieFileStorage, header: &BlockHeaderHash, path: &Vec<u8>, value: &Vec<u8>) -> () {
        test_debug!("---------");
        test_debug!("MARF merkle prove: merkle_test_marf({:?}, {:?}, {:?})?", header, path, value);
        test_debug!("---------");

        s.open_block(header, false).unwrap();
        let (_, root_hash) = Trie::read_root(s).unwrap();
        let triepath = TriePath::from_bytes(&path[..]).unwrap();

        let mut marf_value = [0u8; 40];
        marf_value.copy_from_slice(&value[0..40]);

        let proof = TrieMerkleProof::from_path(s, &triepath, &MARFValue(marf_value), header).unwrap();

        test_debug!("---------");
        test_debug!("MARF merkle verify: {:?}", &proof);
        test_debug!("MARF merkle verify target root hash: {:?}", &root_hash);
        test_debug!("MARF merkle verify source block: {:?}", header);
        test_debug!("---------");

        let root_to_block = s.read_root_to_block_table().unwrap();
        assert!(proof.verify(&triepath, &MARFValue(marf_value), &root_hash, &root_to_block));
    }
    
    pub fn merkle_test_marf_key_value(s: &mut TrieFileStorage, header: &BlockHeaderHash, key: &String, value: &String) -> () {
        test_debug!("---------");
        test_debug!("MARF merkle prove: merkle_test_marf({:?}, {:?}, {:?})?", header, key, value);
        test_debug!("---------");

        s.open_block(header, false).unwrap();
        let (_, root_hash) = Trie::read_root(s).unwrap();
        let proof = TrieMerkleProof::from_entry(s, key, value, &header).unwrap();

        test_debug!("---------");
        test_debug!("MARF merkle verify: {:?}", &proof);
        test_debug!("MARF merkle verify target root hash: {:?}", &root_hash);
        test_debug!("MARF merkle verify source block: {:?}", header);
        test_debug!("---------");

        let root_to_block = s.read_root_to_block_table().unwrap();
        let triepath = TriePath::from_key(key);
        let marf_value = MARFValue::from_value(value);
        assert!(proof.verify(&triepath, &marf_value, &root_hash, &root_to_block));
    }
    
    pub fn make_node_path(s: &mut TrieFileStorage, node_id: u8, path_segments: &Vec<(Vec<u8>, u8)>, leaf_data: Vec<u8>) -> (Vec<TrieNodeType>, Vec<TriePtr>, Vec<TrieHash>) {
        // make a fully-fleshed-out path of node's to a leaf 
        let root_ptr = s.root_ptr();
        let root = TrieNode256::new(&path_segments[0].0);
        let root_hash = TrieHash::from_data(&[0u8; 32]);        // don't care about this in this test
        s.write_node(root_ptr, &root, root_hash.clone()).unwrap();

        let mut parent = TrieNodeType::Node256(root);
        let mut parent_ptr = root_ptr;

        let mut nodes = vec![];
        let mut node_ptrs = vec![];
        let mut hashes = vec![];
        let mut seg_id = 0;

        for i in 0..path_segments.len() - 1 {
            let path_segment = &path_segments[i+1].0;
            let chr = path_segments[i].1;
            // let node_ptr = ftell(s).unwrap();
            let node_ptr = s.last_ptr().unwrap();

            let node = match node_id {
                TrieNodeID::Node4 => TrieNodeType::Node4(TrieNode4::new(path_segment)),
                TrieNodeID::Node16 => TrieNodeType::Node16(TrieNode16::new(path_segment)),
                TrieNodeID::Node48 => TrieNodeType::Node48(TrieNode48::new(path_segment)),
                TrieNodeID::Node256 => TrieNodeType::Node256(TrieNode256::new(path_segment)),
                _ => panic!("invalid node ID")
            };

            s.write_nodetype(node_ptr, &node, TrieHash::from_data(&[(seg_id+1) as u8; 32])).unwrap();
            
            // update parent 
            match parent {
                TrieNodeType::Node256(ref mut data) => assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32))),
                TrieNodeType::Node48(ref mut data) => assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32))),
                TrieNodeType::Node16(ref mut data) => assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32))),
                TrieNodeType::Node4(ref mut data) => assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32))),
                TrieNodeType::Leaf(_) => panic!("can't insert into leaf"),
            };

            s.write_nodetype(parent_ptr, &parent, TrieHash::from_data(&[seg_id as u8; 32])).unwrap();
            
            nodes.push(parent.clone());
            node_ptrs.push(TriePtr::new(node_id, chr, node_ptr as u32));
            hashes.push(TrieHash::from_data(&[(seg_id+1) as u8; 32]));

            parent = node;
            parent_ptr = node_ptr;

            seg_id += 1;
        }

        // add a leaf at the end 
        let child = TrieLeaf::new(&path_segments[path_segments.len()-1].0, &leaf_data);
        let child_chr = path_segments[path_segments.len()-1].1;
        // let child_ptr = ftell(s).unwrap();
        let child_ptr = s.last_ptr().unwrap();
        s.write_node(child_ptr, &child, TrieHash::from_data(&[(seg_id+1) as u8; 32])).unwrap();

        // update parent
        match parent {
            TrieNodeType::Node256(ref mut data) => assert!(data.insert(&TriePtr::new(TrieNodeID::Leaf, child_chr, child_ptr as u32))),
            TrieNodeType::Node48(ref mut data) => assert!(data.insert(&TriePtr::new(TrieNodeID::Leaf, child_chr, child_ptr as u32))),
            TrieNodeType::Node16(ref mut data) => assert!(data.insert(&TriePtr::new(TrieNodeID::Leaf, child_chr, child_ptr as u32))),
            TrieNodeType::Node4(ref mut data) => assert!(data.insert(&TriePtr::new(TrieNodeID::Leaf, child_chr, child_ptr as u32))),
            TrieNodeType::Leaf(_) => panic!("can't insert into leaf"),
        };

        s.write_nodetype(parent_ptr, &parent, TrieHash::from_data(&[(seg_id) as u8; 32])).unwrap();

        nodes.push(parent.clone());
        node_ptrs.push(TriePtr::new(TrieNodeID::Leaf, child_chr, child_ptr as u32));
        hashes.push(TrieHash::from_data(&[(seg_id+1) as u8; 32]));

        (nodes, node_ptrs, hashes)
    }
    
    pub fn make_node4_path(s: &mut TrieFileStorage, path_segments: &Vec<(Vec<u8>, u8)>, leaf_data: Vec<u8>) -> (Vec<TrieNodeType>, Vec<TriePtr>, Vec<TrieHash>) {
        make_node_path(s, TrieNodeID::Node4, path_segments, leaf_data)
    }    
}

