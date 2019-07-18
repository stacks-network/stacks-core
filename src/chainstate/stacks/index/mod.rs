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
    assert!(target.capacity() >= target.len() + src.len());
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
            Error::NotDirectoryError => "Not a directory"
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
    pub fn dump_trie<S: TrieStorage + Seek>(s: &mut S) -> () {
        test_debug!("\n----- BEGIN TRIE ------");
        
        fn space(cnt: usize) -> String {
            let mut ret = vec![];
            for _ in 0..cnt {
                ret.push(" ".to_string());
            }
            ret.join("")
        }

        let root_ptr = s.root_ptr();
        fseek(s, root_ptr).unwrap();

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
                    let (child_node, _) = Trie::read_node(s, ptr).unwrap();
                    frontier.push((child_node, depth + path_len + 1));
                }
            }
        }
        
        test_debug!("----- END TRIE ------\n");
    }

    // ram-disk trie (for testing encoding/decoding and cursor walking)
    // NOTE: does not support forks
    pub struct TrieIOBuffer {
        bufs: HashMap<BlockHeaderHash, Cursor<Vec<u8>>>,
        buf_order: Vec<BlockHeaderHash>,
        block_header: BlockHeaderHash,
        readonly: bool,
        
        read_count: u64,
        read_backptr_count: u64,
        read_node_count: u64,
        read_leaf_count: u64,

        write_count: u64,
        write_node_count: u64,
        write_leaf_count: u64,
    }

    impl TrieIOBuffer {
        pub fn new(buf: Cursor<Vec<u8>>) -> TrieIOBuffer {
            let mut ret = TrieIOBuffer {
                bufs: HashMap::new(),
                buf_order: vec![],
                block_header: BlockHeaderHash([0u8; 32]),
                readonly: false,
                
                read_count: 0,
                read_backptr_count: 0,
                read_node_count: 0,
                read_leaf_count: 0,

                write_count: 0,
                write_node_count: 0,
                write_leaf_count: 0
            };
            ret.bufs.insert(ret.block_header.clone(), buf);
            ret
        }

        #[allow(dead_code)]
        pub fn stats(&mut self) -> (u64, u64) {
            let r = self.read_count;
            let w = self.write_count;
            self.read_count = 0;
            self.write_count = 0;
            (r, w)
        }
        
        #[allow(dead_code)]
        pub fn node_stats(&mut self) -> (u64, u64, u64) {
            let nr = self.read_node_count;
            let br = self.read_backptr_count;
            let nw = self.write_node_count;

            self.read_node_count = 0;
            self.read_backptr_count = 0;
            self.write_node_count = 0;

            (nr, br, nw)
        }

        #[allow(dead_code)]
        pub fn leaf_stats(&mut self) -> (u64, u64) {
            let lr = self.read_leaf_count;
            let lw = self.write_leaf_count;

            self.read_leaf_count = 0;
            self.write_leaf_count = 0;

            (lr, lw)
        }
    }

    impl TrieStorage for TrieIOBuffer {
        fn extend(&mut self, bhh: &BlockHeaderHash) -> Result<(), Error> {
            if self.bufs.contains_key(bhh) {
                return Err(Error::ExistsError);
            }
            test_debug!("Extend to {:?}", bhh);
            self.bufs.insert((*bhh).clone(), Cursor::new(vec![]));
            self.buf_order.push(self.block_header.clone());
            self.block_header = bhh.clone();
            self.readonly = false;
            Ok(())
        }

        fn open(&mut self, bhh: &BlockHeaderHash, readwrite: bool) -> Result<(), Error> {
            if !self.bufs.contains_key(bhh) {
                test_debug!("Block not found: {:?}", bhh);
                return Err(Error::NotFoundError);
            }
            self.block_header = bhh.clone();
            self.readonly = !readwrite;
            Ok(())
        }
        
        fn tell(&self) -> BlockHeaderHash {
            self.block_header.clone()
        }

        fn block_walk(&mut self, back_block: u32) -> Result<BlockHeaderHash, Error> {
            if back_block == 0 {
                return Ok(self.block_header.clone());
            }
            if (back_block as usize) < self.buf_order.len() {
                return Ok(self.buf_order[self.buf_order.len() - 1 - (back_block as usize)].clone());
            }
            return Err(Error::NotFoundError);
        }
        
        fn root_ptr(&self) -> u64 { 0 }

        fn readwrite(&self) -> bool {
            !self.readonly
        }

        fn format(&mut self) -> Result<(), Error> {
            if self.readonly {
                test_debug!("Read-only!");
                return Err(Error::ReadOnlyError);
            }

            self.bufs.clear();
            Ok(())
        }

        fn read_node_hash_bytes(&mut self, ptr: &TriePtr, hash_buf: &mut Vec<u8>) -> Result<(), Error> {
            match self.bufs.get_mut(&self.block_header) {
                Some(ref mut buf) => {
                    read_node_hash_bytes(buf, ptr, hash_buf)
                }
                None => {
                    test_debug!("Node hash not found: {:?}", ptr);
                    Err(Error::NotFoundError)
                }
            }
        }

        fn read_node(&mut self, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash), Error> {
            test_debug!("read_node({:?}): {:?}", &self.block_header, ptr);
            
            self.read_count += 1;
            if is_backptr(ptr.id()) {
                self.read_backptr_count += 1;
            }
            else if ptr.id() == TrieNodeID::Leaf {
                self.read_leaf_count += 1;
            }
            else {
                self.read_node_count += 1;
            }

            let clear_ptr = TriePtr::new(clear_backptr(ptr.id()), ptr.chr(), ptr.ptr());

            match self.bufs.get_mut(&self.block_header) {
                Some(ref mut buf) => {
                    read_nodetype(buf, &clear_ptr)
                },
                None => {
                    test_debug!("Node not found: {:?}", &clear_ptr);
                    Err(Error::NotFoundError)
                }
            }
        }
        
        fn write_node(&mut self, node: &TrieNodeType, hash: TrieHash) -> Result<(), Error> {
            if self.readonly {
                test_debug!("Read-only!");
                return Err(Error::ReadOnlyError);
            }

            let disk_ptr = ftell(self)?;
            test_debug!("write_node({:?}): at {}: {:?} {:?}", &self.block_header, disk_ptr, &hash, node);
            
            self.write_count += 1;
            match node {
                TrieNodeType::Leaf(ref data) => {
                    self.write_leaf_count += 1;
                },
                TrieNodeType::Node4(ref data) => {
                    self.write_node_count += 1;
                }
                TrieNodeType::Node16(ref data) => {
                    self.write_node_count += 1;
                }
                TrieNodeType::Node48(ref data) => {
                    self.write_node_count += 1;
                }
                TrieNodeType::Node256(ref data) => {
                    self.write_node_count += 1;
                },
            }

            match self.bufs.get_mut(&self.block_header) {
                Some(ref mut buf) => {
                    match node {
                        TrieNodeType::Leaf(ref data) => write_node_bytes(buf, data, hash),
                        TrieNodeType::Node4(ref data) => write_node_bytes(buf, data, hash),
                        TrieNodeType::Node16(ref data) => write_node_bytes(buf, data, hash),
                        TrieNodeType::Node48(ref data) => write_node_bytes(buf, data, hash),
                        TrieNodeType::Node256(ref data) => write_node_bytes(buf, data, hash),
                    }?;
                    Ok(())
                },
                None => {
                    test_debug!("Block data does not exist for {:?}", &self.block_header);
                    Err(Error::NotFoundError)
                }
            }
        }
        
        fn flush(&mut self) -> Result<(), Error> {
            Ok(())
        }

        fn num_blocks(&self) -> usize {
            self.bufs.len()
        }
    }

    impl Seek for TrieIOBuffer {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            match self.bufs.get_mut(&self.block_header) {
                Some(ref mut buf) => {
                    buf.seek(pos)
                },
                None => {
                    Err(io::Error::new(io::ErrorKind::Other, Error::NotFoundError))
                }
            }
        }
    }

    pub fn merkle_test<S: TrieStorage + Seek>(s: &mut S, path: &Vec<u8>, value: &Vec<u8>) -> () {
        let (_, root_hash) = Trie::read_root(s).unwrap();
        let triepath = TriePath::from_bytes(&path[..]).unwrap();

        let block_header = BlockHeaderHash([0u8; 32]);
        s.open(&block_header, false).unwrap();

        let proof = TrieMerkleProof::from_path(s, &triepath, &TrieLeaf::new(&vec![], value), &block_header).unwrap();
        let empty_root_to_block = HashMap::new();
        assert!(proof.verify(&root_hash, &empty_root_to_block));
    }
    
    pub fn merkle_test_marf(s: &mut TrieFileStorage, header: &BlockHeaderHash, path: &Vec<u8>, value: &Vec<u8>) -> () {
        test_debug!("---------");
        test_debug!("MARF merkle prove: merkle_test_marf({:?}, {:?}, {:?})?", header, path, value);
        test_debug!("---------");

        s.open(header, false).unwrap();
        let (_, root_hash) = Trie::read_root(s).unwrap();
        let triepath = TriePath::from_bytes(&path[..]).unwrap();
        let proof = TrieMerkleProof::from_path(s, &triepath, &TrieLeaf::new(&vec![], value), header).unwrap();

        test_debug!("---------");
        test_debug!("MARF merkle verify: {:?}", &proof);
        test_debug!("MARF merkle verify target root hash: {:?}", &root_hash);
        test_debug!("MARF merkle verify source block: {:?}", header);
        test_debug!("---------");

        let root_to_block = s.read_root_to_block_table().unwrap();
        assert!(proof.verify(&root_hash, &root_to_block));
    }

    pub fn make_node_path<S: TrieStorage + Seek>(s: &mut S, node_id: u8, path_segments: &Vec<(Vec<u8>, u8)>, leaf_data: Vec<u8>) -> (Vec<TrieNodeType>, Vec<TriePtr>, Vec<TrieHash>) {
        // make a fully-fleshed-out path of node's to a leaf 
        let root_ptr = s.root_ptr();
        fseek(s, root_ptr).unwrap();
        
        let root = TrieNode256::new(&path_segments[0].0);
        let root_hash = TrieHash::from_data(&[0u8; 32]);        // don't care about this in this test
        Trie::write_node(s, &root, root_hash.clone()).unwrap();

        let mut parent = TrieNodeType::Node256(root);
        let mut parent_ptr = 0;

        let mut nodes = vec![];
        let mut node_ptrs = vec![];
        let mut hashes = vec![];
        let mut seg_id = 0;

        for i in 0..path_segments.len() - 1 {
            let path_segment = &path_segments[i+1].0;
            let chr = path_segments[i].1;
            let node_ptr = ftell(s).unwrap();

            let node = match node_id {
                TrieNodeID::Node4 => TrieNodeType::Node4(TrieNode4::new(path_segment)),
                TrieNodeID::Node16 => TrieNodeType::Node16(TrieNode16::new(path_segment)),
                TrieNodeID::Node48 => TrieNodeType::Node48(TrieNode48::new(path_segment)),
                TrieNodeID::Node256 => TrieNodeType::Node256(TrieNode256::new(path_segment)),
                _ => panic!("invalid node ID")
            };

            Trie::write_nodetype(s, &node, TrieHash::from_data(&[(seg_id+1) as u8; 32])).unwrap();
            
            let sav = ftell(s).unwrap();

            // update parent 
            fseek(s, parent_ptr).unwrap();

            match parent {
                TrieNodeType::Node256(ref mut data) => assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32))),
                TrieNodeType::Node48(ref mut data) => assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32))),
                TrieNodeType::Node16(ref mut data) => assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32))),
                TrieNodeType::Node4(ref mut data) => assert!(data.insert(&TriePtr::new(node_id, chr, node_ptr as u32))),
                TrieNodeType::Leaf(_) => panic!("can't insert into leaf"),
            };

            Trie::write_nodetype(s, &parent, TrieHash::from_data(&[seg_id as u8; 32])).unwrap();
            
            fseek(s, sav).unwrap();
            
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
        let child_ptr = ftell(s).unwrap();
        Trie::write_node(s, &child, TrieHash::from_data(&[(seg_id+1) as u8; 32])).unwrap();

        // update parent
        let sav = ftell(s).unwrap();
        fseek(s, parent_ptr).unwrap();

        match parent {
            TrieNodeType::Node256(ref mut data) => assert!(data.insert(&TriePtr::new(TrieNodeID::Leaf, child_chr, child_ptr as u32))),
            TrieNodeType::Node48(ref mut data) => assert!(data.insert(&TriePtr::new(TrieNodeID::Leaf, child_chr, child_ptr as u32))),
            TrieNodeType::Node16(ref mut data) => assert!(data.insert(&TriePtr::new(TrieNodeID::Leaf, child_chr, child_ptr as u32))),
            TrieNodeType::Node4(ref mut data) => assert!(data.insert(&TriePtr::new(TrieNodeID::Leaf, child_chr, child_ptr as u32))),
            TrieNodeType::Leaf(_) => panic!("can't insert into leaf"),
        };

        Trie::write_nodetype(s, &parent, TrieHash::from_data(&[(seg_id) as u8; 32])).unwrap();

        fseek(s, sav).unwrap();

        nodes.push(parent.clone());
        node_ptrs.push(TriePtr::new(TrieNodeID::Leaf, child_chr, child_ptr as u32));
        hashes.push(TrieHash::from_data(&[(seg_id+1) as u8; 32]));

        let root_ptr = s.root_ptr();
        fseek(s, root_ptr).unwrap();
        (nodes, node_ptrs, hashes)
    }
    
    pub fn make_node4_path<S: TrieStorage + Seek>(s: &mut S, path_segments: &Vec<(Vec<u8>, u8)>, leaf_data: Vec<u8>) -> (Vec<TrieNodeType>, Vec<TriePtr>, Vec<TrieHash>) {
        make_node_path(s, TrieNodeID::Node4, path_segments, leaf_data)
    }    
}

