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

use std::fmt;
use std::error;
use std::io;
use std::io::{
    Read,
    Write,
    Seek,
    SeekFrom,
    Cursor,
    BufReader
};

use std::char::from_digit;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use hashbrown::{HashMap, HashSet};
use std::collections::VecDeque;

use std::fs;
use std::path::{
    Path,
    PathBuf
};

use std::os;
use std::iter::FromIterator;

#[cfg(target_os = "unix")]
use std::os::unix::io::AsRawFd;

#[cfg(target_os = "unix")]
use libc;

use regex::Regex;

use chainstate::burn::BlockHeaderHash;
use chainstate::burn::BLOCK_HEADER_HASH_ENCODED_SIZE;

use chainstate::stacks::index::{
    TrieHash,
    TRIEHASH_ENCODED_SIZE,
    fast_extend_from_slice,
};

use chainstate::stacks::index::bits::{
    get_node_byte_len,
    write_nodetype_bytes,
    read_hash_bytes,
    read_4_bytes,
    read_node_hash_bytes,
    read_nodetype,
    get_node_hash,
    trie_hash_from_bytes
};

use chainstate::stacks::index::node::{
    is_backptr,
    clear_backptr,
    set_backptr,
    TrieNodeType,
    TrieNode4,
    TrieNode16,
    TrieNode48,
    TrieNode256,
    TrieLeaf,
    TrieNodeID,
    TriePtr,
    TriePath,
    TrieNode
};

use chainstate::stacks::index::Error as Error;

use util::log;

pub fn ftell<F: Seek>(f: &mut F) -> Result<u64, Error> {
    f.seek(SeekFrom::Current(0))
        .map_err(Error::IOError)
}

pub fn fseek<F: Seek>(f: &mut F, off: u64) -> Result<u64, Error> {
    f.seek(SeekFrom::Start(off))
        .map_err(Error::IOError)
}

pub fn fseek_end<F: Seek>(f: &mut F) -> Result<u64, Error> {
    f.seek(SeekFrom::End(0))
        .map_err(Error::IOError)
}

#[derive(Clone)]
pub struct BlockHashMap {
    next_identifier: u32,
    map: Vec<BlockHeaderHash>
}

impl BlockHashMap {
    pub fn new(initial_size: Option<u32>) -> BlockHashMap {
        if let Some(initial_size) = initial_size {
            let mut map = Vec::with_capacity(initial_size as usize);
            map.resize(initial_size as usize, TrieFileStorage::block_sentinel());
            BlockHashMap { next_identifier: initial_size,
                           map }
        } else {
            BlockHashMap { next_identifier: 0,
                           map: Vec::new() }
        }
    }

    pub fn add_block(&mut self, block: &BlockHeaderHash) -> u32 {
        let identifier = self.next_identifier;
        self.map.push(block.clone());
        if self.map.len() - 1 != (identifier as usize) {
            panic!("BlockHashMap corruption!");
        }
        self.next_identifier = self.next_identifier.checked_add(1)
            .expect("Block overflow -- MARF cannot track more than 2**31 - 1 blocks.");

        identifier
    }

    pub fn set_block(&mut self, block: BlockHeaderHash, identifier: u32) {
        if identifier >= self.next_identifier || (identifier as usize) >= self.map.len() {
            panic!("BlockHashMap corruption. Attempted to set block {} to id {}, but map is only length {}.",
                   &block, &identifier, self.map.len());
        }
        self.map[identifier as usize] = block;
    }

    pub fn iter(&self) -> std::slice::Iter<BlockHeaderHash> {
        self.map.iter()
    }

    pub fn get_block_header_hash(&self, identifier: u32) -> Option<&BlockHeaderHash> {
        self.map.get(identifier as usize)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.next_identifier = 0;
    }
}

/// In-RAM trie storage.
/// Used by TrieFileStorage to buffer the next trie being built.
pub struct TrieRAM {
    data: Vec<(TrieNodeType, TrieHash)>,
    block_header: BlockHeaderHash,
    readonly: bool,

    read_count: u64,
    read_backptr_count: u64,
    read_node_count: u64,
    read_leaf_count: u64,

    write_count: u64,
    write_node_count: u64,
    write_leaf_count: u64,

    total_bytes: usize,

    identifier: u32,
    parent: BlockHeaderHash
}

// Trie in RAM without the serialization overhead
impl TrieRAM {
    pub fn new(block_header: &BlockHeaderHash, capacity_hint: usize, identifier: u32, parent: &BlockHeaderHash) -> TrieRAM {
        TrieRAM {
            data: Vec::with_capacity(capacity_hint),
            block_header: block_header.clone(),
            readonly: false,

            read_count: 0,
            read_backptr_count: 0,
            read_node_count: 0,
            read_leaf_count: 0,

            write_count: 0,
            write_node_count: 0,
            write_leaf_count: 0,

            total_bytes: 0,

            identifier: identifier,
            parent: parent.clone(),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn stats(&mut self) -> (u64, u64) {
        let r = self.read_count;
        let w = self.write_count;
        self.read_count = 0;
        self.write_count = 0;
        (r, w)
    }

    #[cfg(test)]
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

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn leaf_stats(&mut self) -> (u64, u64) {
        let lr = self.read_leaf_count;
        let lw = self.write_leaf_count;

        self.read_leaf_count = 0;
        self.write_leaf_count = 0;

        (lr, lw)
    }

    pub fn write_trie_file<F: Read + Write + Seek>(f: &mut F, node_data: &[(TrieNodeType, TrieHash)], offsets: &[u32],
                                                   identifier: u32, parent_hash: &BlockHeaderHash) -> Result<(), Error> {
        // write parent block ptr
        fseek(f, 0)?;
        f.write_all(parent_hash.as_bytes())
            .map_err(|e| Error::IOError(e))?;
        // write identifier
        fseek(f, BLOCK_HEADER_HASH_ENCODED_SIZE as u64)?;
        f.write_all(&identifier.to_le_bytes())
            .map_err(|e| Error::IOError(e))?;

        for i in 0..node_data.len() {
            // dump the node to storage
            write_nodetype_bytes(f, &node_data[i].0, node_data[i].1)?;
            
            // next node
            fseek(f, offsets[i] as u64)?;
        }

        Ok(())
    }

    /// Walk through the bufferred TrieNodes and dump them to f.
    fn dump_traverse<F: Read + Write + Seek>(&mut self, f: &mut F, root: &TrieNodeType, hash: &TrieHash) -> Result<u64, Error> {
        let mut frontier : VecDeque<(TrieNodeType, TrieHash)> = VecDeque::new();

        let mut node_data = vec![];
        let mut offsets = vec![];

        frontier.push_back((root.clone(), hash.clone()));

        // first 32 bytes is reserved for the parent block hash
        //    next 4 bytes is the local block identifier
        let mut ptr = BLOCK_HEADER_HASH_ENCODED_SIZE as u64 +
            4;
        
        // step 1: write out each node in breadth-first order to get their ptr offsets
        while frontier.len() > 0 {
            let (node, node_hash) = match frontier.pop_front() {
                Some((n, h)) => (n, h),
                None => {
                    break;
                }
            };

            // calculate size
            let num_written = get_node_byte_len(&node);
            ptr += num_written as u64;
            
            // queue each child
            if !node.is_leaf() {
                let ptrs = node.ptrs();
                let num_children = ptrs.len();
                for i in 0..num_children {
                    if ptrs[i].id != TrieNodeID::Empty && !is_backptr(ptrs[i].id) {
                        let (child, child_hash) = self.read_nodetype(&ptrs[i])?;
                        frontier.push_back((child, child_hash));
                    }
                }
            }
            
            node_data.push((node, node_hash));
            offsets.push(ptr as u32);
        }

        assert_eq!(offsets.len(), node_data.len());

        // step 2: update ptrs in all nodes
        let mut i = 0;
        for j in 0..node_data.len() {
            let next_node = &mut node_data[j].0;
            if !next_node.is_leaf() {
                let mut ptrs = next_node.ptrs_mut();
                let num_children = ptrs.len();
                for k in 0..num_children {
                    if ptrs[k].id != TrieNodeID::Empty && !is_backptr(ptrs[k].id) {
                        ptrs[k].ptr = offsets[i];
                        i += 1;
                    }
                }
            }
        }

        // step 3: write out each node (now that they have the write ptrs)
        TrieRAM::write_trie_file(f, node_data.as_slice(), offsets.as_slice(), self.identifier, &self.parent)?;

        Ok(ptr)
    }

    /// Dump ourself to f
    pub fn dump<F: Read + Write + Seek>(&mut self, f: &mut F, bhh: &BlockHeaderHash) -> Result<u64, Error> {
        if self.block_header == *bhh {
            let (root, hash) = self.read_nodetype(&TriePtr::new(TrieNodeID::Node256, 0, 0))?;
            self.dump_traverse(f, &root, &hash)
        }
        else {
            trace!("Failed to dump {:?}: not the current block", bhh);
            Err(Error::NotFoundError)
        }
    }

    fn size_hint(&self) -> usize {
        self.total_bytes
    }

    pub fn format(&mut self) -> Result<(), Error> {
        if self.readonly {
            trace!("Read-only!");
            return Err(Error::ReadOnlyError);
        }

        self.data.clear();
        Ok(())
    }

    pub fn read_node_hash_bytes(&mut self, ptr: &TriePtr, buf: &mut Vec<u8>) -> Result<(), Error> {
        if (ptr.ptr() as u64) >= (self.data.len() as u64) {
            trace!("TrieRAM: Failed to read node bytes: {} >= {}", ptr.ptr(), self.data.len());
            Err(Error::NotFoundError)
        }
        else {
            fast_extend_from_slice(buf, self.data[ptr.ptr() as usize].1.as_bytes());
            Ok(())
        }
    }

    pub fn read_nodetype(&mut self, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash), Error> {
        trace!("TrieRAM: read_nodetype({:?}): at {:?}", &self.block_header, ptr);

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

        if (ptr.ptr() as u64) >= (self.data.len() as u64) {
            trace!("TrieRAM: Failed to read node: {} >= {}", ptr.ptr(), self.data.len());
            Err(Error::NotFoundError)
        }
        else {
            Ok(self.data[ptr.ptr() as usize].clone())
        }
    }

    pub fn write_nodetype(&mut self, node_array_ptr: u32, node: &TrieNodeType, hash: TrieHash) -> Result<(), Error> {
        if self.readonly {
            trace!("Read-only!");
            return Err(Error::ReadOnlyError);
        }

        trace!("TrieRAM: write_nodetype({:?}): at {}: {:?} {:?}", &self.block_header, node_array_ptr, &hash, node);
        
        self.write_count += 1;
        match node {
            TrieNodeType::Leaf(_) => {
                self.write_leaf_count += 1;
            },
            _ => {
                self.write_node_count += 1;
            }
        }

        if node_array_ptr < (self.data.len() as u32) {
            self.data[node_array_ptr as usize] = (node.clone(), hash);
            Ok(())
        }
        else if node_array_ptr == (self.data.len() as u32) {
            self.data.push((node.clone(), hash));
            self.total_bytes += get_node_byte_len(node);
            Ok(())
        }
        else {
            trace!("Failed to write node bytes: off the end of the buffer");
            Err(Error::NotFoundError)
        }
    }

    /// Get the next ptr value for a node to store.
    pub fn last_ptr(&mut self) -> Result<u32, Error> {
        Ok(self.data.len() as u32)
    }
}

enum FileStorageTypes {
    BufferedReader(BufReader<fs::File>),
    File(fs::File)
}

impl FileStorageTypes {
    pub fn read_block_identifier(&mut self) -> Result<u32, Error> {
        match self {
            FileStorageTypes::BufferedReader(ref mut b) => TrieFileStorage::read_block_identifier_from_fd(b),
            FileStorageTypes::File(ref mut b) => TrieFileStorage::read_block_identifier_from_fd(b)
        }
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        match self {
            FileStorageTypes::BufferedReader(ref mut b) => Err(Error::ReadOnlyError),
            FileStorageTypes::File(ref mut b) => b.flush().map_err(Error::IOError)
        }
    }

    pub fn read_nodetype(&mut self, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash), Error> {
        match self {
            FileStorageTypes::BufferedReader(ref mut b) => read_nodetype(b, ptr),
            FileStorageTypes::File(ref mut b) => read_nodetype(b, ptr)
        }
    }

    pub fn read_node_hash_bytes(&mut self, ptr: &TriePtr, buf: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            FileStorageTypes::BufferedReader(ref mut b) => read_node_hash_bytes(b, ptr, buf),
            FileStorageTypes::File(ref mut b) => read_node_hash_bytes(b, ptr, buf)
        }
    }
}

// disk-backed Trie.
// Keeps the last-extended Trie in-RAM and flushes it to disk on either a call to flush() or a call
// to extend_to_block() with a different block header hash.
pub struct TrieFileStorage {
    pub dir_path: String,
    readonly: bool,

    last_extended: Option<BlockHeaderHash>,
    last_extended_trie: Option<TrieRAM>,
    
    cur_block: BlockHeaderHash,
    cur_block_fd: Option<FileStorageTypes>,
    
    read_count: u64,
    read_backptr_count: u64,
    read_node_count: u64,
    read_leaf_count: u64,

    write_count: u64,
    write_node_count: u64,
    write_leaf_count: u64,

    // map block identifiers to their parent identifiers
    pub block_map: BlockHashMap,
    chain_tips: HashSet<BlockHeaderHash>,

    // cache of block paths (they're surprisingly expensive to generate)
    block_path_cache: HashMap<BlockHeaderHash, PathBuf>,

    pub trie_ancestor_hash_bytes_cache: Option<(BlockHeaderHash, Vec<u8>)>,

    pub test_genesis_block: Option<BlockHeaderHash>,
}

impl TrieFileStorage {
    pub fn new(dir_path: &str) -> Result<TrieFileStorage, Error> {
        match fs::metadata(dir_path) {
            Ok(md) => {
                if !md.is_dir() {
                    return Err(Error::NotDirectoryError);
                }
            },
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    return Err(Error::IOError(e));
                }
                // try to make it
                fs::create_dir_all(dir_path)
                    .map_err(Error::IOError)?;
            }
        }

        let dir_path = dir_path.to_string();
        let partially_written_state = TrieFileStorage::scan_tmp_blocks(&dir_path)?;
        if partially_written_state.len() > 0 {
            return Err(Error::PartialWriteError);
        }

        let (block_map, chain_tips) = TrieFileStorage::read_block_hash_map(&dir_path, &TrieFileStorage::block_sentinel())?;

        let ret = TrieFileStorage {
            dir_path,
            readonly: false,

            last_extended: None,
            last_extended_trie: None,

            cur_block: TrieFileStorage::block_sentinel(),
            cur_block_fd: None,
            
            read_count: 0,
            read_backptr_count: 0,
            read_node_count: 0,
            read_leaf_count: 0,

            write_count: 0,
            write_node_count: 0,
            write_leaf_count: 0,

            block_map: block_map,
            chain_tips: chain_tips,

            block_path_cache: HashMap::new(),
            trie_ancestor_hash_bytes_cache: None,
  

            // these are only ever used in testing, we should flag on cfg(test).
            test_genesis_block: None,
        };

        Ok(ret)
    }

    pub fn set_cached_ancestor_hashes_bytes(&mut self, bhh: &BlockHeaderHash, bytes: Vec<u8>) {
        self.trie_ancestor_hash_bytes_cache = Some((bhh.clone(), bytes));
    }

    pub fn check_cached_ancestor_hashes_bytes(&mut self, bhh: &BlockHeaderHash) -> Option<Vec<u8>> {
        if let Some((ref cached_bhh, ref cached_bytes)) = self.trie_ancestor_hash_bytes_cache {
            if cached_bhh == bhh {
                return Some(cached_bytes.clone())
            }
        }
        None
    }

    /// Set up a new Trie forest on disk.  If there is data there already, obliterate it first.
    #[cfg(test)]
    pub fn new_overwrite(dir_path: &str) -> Result<TrieFileStorage, Error> {
        match fs::metadata(dir_path) {
            Ok(_) => {
                fs::remove_dir_all(dir_path).unwrap();
            },
            Err(e) => {
            }
        };
        TrieFileStorage::new(dir_path)
    }

    /// Get the block hash of the "parent of the root".  This does not correspond to a real block,
    /// but instead is a sentinel value that is all 1's
    pub fn block_sentinel() -> BlockHeaderHash {
        BlockHeaderHash([255u8; BLOCK_HEADER_HASH_ENCODED_SIZE as usize])
    }

    #[cfg(test)]
    pub fn stats(&mut self) -> (u64, u64) {
        let r = self.read_count;
        let w = self.write_count;
        self.read_count = 0;
        self.write_count = 0;
        (r, w)
    }
    
    #[cfg(test)]
    pub fn node_stats(&mut self) -> (u64, u64, u64) {
        let nr = self.read_node_count;
        let br = self.read_backptr_count;
        let nw = self.write_node_count;

        self.read_node_count = 0;
        self.read_backptr_count = 0;
        self.write_node_count = 0;

        (nr, br, nw)
    }

    #[cfg(test)]
    pub fn leaf_stats(&mut self) -> (u64, u64) {
        let lr = self.read_leaf_count;
        let lw = self.write_leaf_count;

        self.read_leaf_count = 0;
        self.write_leaf_count = 0;

        (lr, lw)
    }

    // last two bytes form the directory name
    pub fn block_dir(dir_path: &String, bhh: &BlockHeaderHash) -> PathBuf {
        let bhh_bytes = bhh.as_bytes();
        let bhh_1 = format!("{:02x}", bhh_bytes[31]);
        let bhh_2 = format!("{:02x}", bhh_bytes[30]);
        let p = Path::new(dir_path)
                    .join(bhh_1)
                    .join(bhh_2);
        p
    }

    pub fn block_path(dir_path: &String, bhh: &BlockHeaderHash) -> PathBuf {
        // it looks awkward, but it's waaaay faster than just doing to_hex()
        let bhh_bytes = bhh.as_bytes();
        let bhh_name = format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                              bhh_bytes[0],     bhh_bytes[1],       bhh_bytes[2],       bhh_bytes[3],
                              bhh_bytes[4],     bhh_bytes[5],       bhh_bytes[6],       bhh_bytes[7],
                              bhh_bytes[8],     bhh_bytes[9],       bhh_bytes[10],      bhh_bytes[11],
                              bhh_bytes[12],    bhh_bytes[13],      bhh_bytes[14],      bhh_bytes[15],
                              bhh_bytes[16],    bhh_bytes[17],      bhh_bytes[18],      bhh_bytes[19],
                              bhh_bytes[20],    bhh_bytes[21],      bhh_bytes[22],      bhh_bytes[23],
                              bhh_bytes[24],    bhh_bytes[25],      bhh_bytes[26],      bhh_bytes[27],
                              bhh_bytes[28],    bhh_bytes[29],      bhh_bytes[30],      bhh_bytes[31]);

        TrieFileStorage::block_dir(dir_path, bhh).join(bhh_name)
    }

    pub fn block_path_tmp(dir_path: &String, bhh: &BlockHeaderHash) -> PathBuf {
        // it looks awkward, but it's waaaay faster than just doing to_hex()
        let bhh_bytes = bhh.as_bytes();
        let bhh_name = format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.tmp",
                              bhh_bytes[0],     bhh_bytes[1],       bhh_bytes[2],       bhh_bytes[3],
                              bhh_bytes[4],     bhh_bytes[5],       bhh_bytes[6],       bhh_bytes[7],
                              bhh_bytes[8],     bhh_bytes[9],       bhh_bytes[10],      bhh_bytes[11],
                              bhh_bytes[12],    bhh_bytes[13],      bhh_bytes[14],      bhh_bytes[15],
                              bhh_bytes[16],    bhh_bytes[17],      bhh_bytes[18],      bhh_bytes[19],
                              bhh_bytes[20],    bhh_bytes[21],      bhh_bytes[22],      bhh_bytes[23],
                              bhh_bytes[24],    bhh_bytes[25],      bhh_bytes[26],      bhh_bytes[27],
                              bhh_bytes[28],    bhh_bytes[29],      bhh_bytes[30],      bhh_bytes[31]);

        TrieFileStorage::block_dir(dir_path, bhh).join(bhh_name)
    }

    fn cached_block_path(&mut self, bhh: &BlockHeaderHash) -> PathBuf {
        let (p, miss) = match self.block_path_cache.get(bhh) {
            Some(ref p) => {
                ((*p).clone(), false)
            }
            None => {
                (TrieFileStorage::block_path(&self.dir_path, bhh), true)
            }
        };
        
        if miss {
            self.block_path_cache.insert(bhh.clone(), p.clone());
        }
        p
    }

    fn read_block_identifier_and_parent(block_path: &PathBuf) -> Result<(u32, BlockHeaderHash), Error> {
        let mut fd = fs::OpenOptions::new()
                    .read(true)
                    .write(false)
                    .open(block_path)
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            error!("File not found: {:?}", &block_path);
                            Error::NotFoundError
                        }
                        else {
                            Error::IOError(e)
                        }
                    })?;
        let id = TrieFileStorage::read_block_identifier_from_fd(&mut fd)?;
        fseek(&mut fd, 0)?;
        let bytes = read_hash_bytes(&mut fd)?;
        Ok((id, BlockHeaderHash(bytes)))
    }

    fn read_block_identifier_from_fd<F: Seek + Read>(fd: &mut F) -> Result<u32, Error> {
        fseek(fd, BLOCK_HEADER_HASH_ENCODED_SIZE as u64)?;
        let bytes = read_4_bytes(fd)?;

        Ok( u32::from_le_bytes(bytes) )
    }


    /// Scan the block directory and get all block header hashes,
    ///   invoking the passed closure on each block header hash.
    fn scan_blocks <F> (dir_path: &String, mut f: F) -> Result<(), Error>
        where F: FnMut(String, PathBuf) -> Result<(), Error> {
        for dir_1_res in fs::read_dir(dir_path).map_err(Error::IOError)? {
            let dir_1_entry = dir_1_res.map_err(Error::IOError)?;
            for dir_2_res in fs::read_dir(&dir_1_entry.path()).map_err(Error::IOError)? {
                let dir_2_entry = dir_2_res.map_err(Error::IOError)?;
                for block_file_res in fs::read_dir(&dir_2_entry.path()).map_err(Error::IOError)? {
                    let block_file = block_file_res.map_err(Error::IOError)?;
                    if !block_file.path().is_file() {
                        trace!("Skip {:?}", &block_file.path());
                        continue;
                    }

                    let block_path = block_file.path();
                    let block_name = match block_path.file_name() {
                        Some(name) => match name.to_str() {
                            Some(name_str) => name_str.to_string(),
                            None => {
                                trace!("Skip {:?}", &block_path);
                                continue;
                            }
                        },
                        None => {
                            trace!("Skip {:?}", &block_path);
                            continue;
                        }
                    };

                    f(block_name, block_path)?;
                }
            }
        }
        
        Ok(())
    }

    /// Find all partially-written files and return their list of paths
    pub fn scan_tmp_blocks(dir_path: &String) -> Result<Vec<PathBuf>, Error> {
        let mut ret = vec![];
        let path_regex = Regex::new(r"^[0-9a-f]{64}.tmp$")
            .map_err(|e| panic!("Invalid regex"))?;

        TrieFileStorage::scan_blocks(dir_path, |block_name, block_path| {
            if !path_regex.is_match(&block_name) {
                trace!("Skip non-tmp file {:?}", &block_path);
            } else {
                ret.push(block_path);
            }
            Ok(())
        })?;

        Ok(ret)
    }

    /// Recover from partially-written state -- i.e. blow it away.
    /// Doesn't get called automatically.
    pub fn recover(dir_path: &String) -> Result<(), Error> {
        let partial_writes = TrieFileStorage::scan_tmp_blocks(dir_path)?;
        for path in partial_writes {
            debug!("Remove partially-written index file {:?}", path);
            fs::remove_file(path)
                .map_err(|e| Error::IOError(e))?;
        }
        Ok(())
    }

    fn read_block_hash_map(dir_path: &String, root_hash: &BlockHeaderHash) -> Result<(BlockHashMap, HashSet<BlockHeaderHash>), Error> {
        let mut blocks = vec![];

        let mut parents = HashSet::new();

        TrieFileStorage::scan_blocks(dir_path, |block_name, block_path| {
            let bhh = match BlockHeaderHash::from_hex(&block_name) {
                Ok(h) => h,
                Err(_) => {
                    trace!("Skip {:?}", &block_path);
                    return Ok(());
                }
            };
            let (identifier, parent) = TrieFileStorage::read_block_identifier_and_parent(&block_path)?;
            blocks.push((bhh, identifier));
            parents.insert(parent);
            Ok(())
        })?;

        if blocks.len() > (u32::max_value() as usize) {
            return Err(Error::CorruptionError("Too many blocks have been found.".to_string()));
        }

        let mut block_hash_map = BlockHashMap::new(Some(blocks.len() as u32));
        let mut chain_tips = HashSet::new();

        for (bhh, identifier) in blocks.drain(..) {
            if ! parents.contains(&bhh) {
                chain_tips.insert(bhh.clone());
            }
            block_hash_map.set_block(bhh, identifier);
        }

        Ok((block_hash_map, chain_tips))
    }

    /// Read the Trie root node's hash from the block file in the given path.
    #[cfg(test)]
    fn read_block_root_hash_by_path(&self, path: &PathBuf) -> Result<TrieHash, Error> {
        let mut fd = fs::OpenOptions::new()
                    .read(true)
                    .write(false)
                    .open(&path)
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            error!("File not found: {:?}", path);
                            Error::NotFoundError
                        }
                        else {
                            Error::IOError(e)
                        }
                    })?;

        let root_hash_ptr = self.root_trieptr();
        let mut hash_buf = Vec::with_capacity(BLOCK_HEADER_HASH_ENCODED_SIZE as usize);
        read_node_hash_bytes(&mut fd, &root_hash_ptr, &mut hash_buf)?;

        // safe because this is _also_ TRIEHASH_ENCODED_SIZE bytes long
        Ok(trie_hash_from_bytes(&hash_buf))
    }

    #[cfg(test)]
    pub fn read_block_root_hash(&self, bhh: &BlockHeaderHash) -> Result<TrieHash, Error> {
        let path = TrieFileStorage::block_path(&self.dir_path, bhh);
        self.read_block_root_hash_by_path(&path)
    }
    
    #[cfg(test)]
    pub fn read_tmp_block_root_hash(&self, bhh: &BlockHeaderHash) -> Result<TrieHash, Error> {
        let path = TrieFileStorage::block_path_tmp(&self.dir_path, bhh);
        self.read_block_root_hash_by_path(&path)
    }

    /// Generate a mapping between Trie root hashes and the blocks that contain them
    #[cfg(test)]
    pub fn read_root_to_block_table(&mut self) -> Result<HashMap<TrieHash, BlockHeaderHash>, Error> {
        let last_extended_opt = self.last_extended.clone();

        let mut ret = HashMap::new();

        for bhh in self.block_map.iter() {
            if let Some(ref last_extended) = last_extended_opt {
                if *last_extended == *bhh {
                    // this hasn't been dumped yet
                    continue;
                }
            }

            if *bhh == TrieFileStorage::block_sentinel() {
                continue;
            }

            let root_hash = match self.read_block_root_hash(bhh) {
                Ok(h) => {
                    h
                },
                Err(e) => {
                    let h = self.read_tmp_block_root_hash(bhh)?;
                    trace!("Read {:?} from tmp file for {:?} instead", &h, bhh);
                    h
                }
            };

            ret.insert(root_hash.clone(), bhh.clone());
        }

        let (last_extended_opt, last_extended_trie_opt) = match (self.last_extended.take(), self.last_extended_trie.take()) {
            (Some(bhh), Some(mut trie_ram)) => {
                let ptr = TriePtr::new(set_backptr(TrieNodeID::Node256), 0, 0);

                let mut root_hash_bytes = Vec::with_capacity(TRIEHASH_ENCODED_SIZE);
                trie_ram.read_node_hash_bytes(&ptr, &mut root_hash_bytes)?;

                // safe because this is TRIEHASH_ENCODED_SIZE bytes long
                let root_hash = trie_hash_from_bytes(&root_hash_bytes);
                
                ret.insert(root_hash.clone(), bhh.clone());
                (Some(bhh), Some(trie_ram))
            }
            (_, _) => {
                (None, None)
            }
        };

        self.last_extended = last_extended_opt;
        self.last_extended_trie = last_extended_trie_opt;

        Ok(ret)
    }

    /// Extend the forest of Tries to include a new block.
    pub fn extend_to_block(&mut self, bhh: &BlockHeaderHash) -> Result<(), Error> {
        /*

        TODO:
          must still test that:
             * cur_block has an identifier.
             * cur_block has written it's block height
        
         */
        
        self.readonly = false;
        self.flush()?;

        let size_hint = match self.last_extended_trie {
            Some(ref trie_storage) => trie_storage.size_hint() * 2,
            None => (1024 * 1024)
        };

        let identifier = self.block_map.add_block(bhh);
        if self.chain_tips.contains(&self.cur_block) {
            self.chain_tips.remove(&self.cur_block);
        }
        // this *requires* that bhh hasn't been the parent of any prior
        //   extended blocks.
        // this is currently enforced if you use the "public" interfaces
        //   to marfs, but could definitely be violated via raw updates
        //   to trie structures.
        self.chain_tips.insert(bhh.clone());

        let trie_buf = TrieRAM::new(bhh, size_hint, identifier, &self.cur_block);

        // create an empty file for this block, so we can't extend to it again
        let block_dir = TrieFileStorage::block_dir(&self.dir_path, bhh);
        let block_path = TrieFileStorage::block_path(&self.dir_path, bhh);
        let block_path_tmp = TrieFileStorage::block_path_tmp(&self.dir_path, bhh);
        // check if block_path exists
        match fs::metadata(&block_path) {
            Ok(_) => {
                trace!("Block path exists: {:?}", &block_path);
                return Err(Error::ExistsError);
            },
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    return Err(Error::IOError(e));
                }
            }
        };
        // check if block_path_tmp exists
        match fs::metadata(&block_path_tmp) {
            Ok(_) => {
                error!("Tried to create index block {:?} twice", bhh);
                return Err(Error::ExistsError);
            },
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    return Err(Error::IOError(e));
                }
            }
        };

        fs::create_dir_all(block_dir)
            .map_err(Error::IOError)?;

        trace!("Extend from {:?} to {:?} in {:?}", &self.cur_block, bhh, &block_path_tmp);

        // write the new file out and add its parent
        let mut fd = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&block_path_tmp)
            .map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    error!("File not found: {:?}", &block_path_tmp);
                    Error::NotFoundError
                }
                else {
                    Error::IOError(e)
                }
            })?;

        TrieRAM::write_trie_file(&mut fd, &[], &[], identifier, bhh)?;

        fd.write_all(self.cur_block.as_bytes())
            .map_err(|e| Error::IOError(e))?;

        // update internal structures
        self.cur_block = bhh.clone();
        self.cur_block_fd = None;

        self.last_extended = Some(bhh.clone());
        self.last_extended_trie = Some(trie_buf);
                
        trace!("Extended to {:?} in {:?}", &self.cur_block, &block_path);
        Ok(())
    }

    pub fn open_block(&mut self, bhh: &BlockHeaderHash, readwrite: bool) -> Result<(), Error> {
        let sentinel = TrieFileStorage::block_sentinel();
        if *bhh == sentinel {
            // just reset to newly opened state
            self.cur_block_fd = None;
            self.cur_block = sentinel;
            self.readonly = !readwrite;
            return Ok(());
        }

        if Some(*bhh) == self.last_extended {
            // nothing to do -- we're already ready.
            // just clear out.
            self.cur_block_fd = None;
            self.cur_block = bhh.clone();
            self.readonly = !readwrite;
            return Ok(());
        }

        // opening a different Trie than the one we're extending
        let block_path = self.cached_block_path(bhh);
        let fd = fs::OpenOptions::new()
                    .read(true)
                    .write(readwrite)
                    .open(&block_path)
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            trace!("File not found: {:?}", &block_path);
                            Error::NotFoundError
                        }
                        else {
                            Error::IOError(e)
                        }
                    })?;

        // NOTE:
        //   this doesn't really seem to improve performance.
        let filestore_type = if readwrite {
            FileStorageTypes::File(fd)
        } else {
            FileStorageTypes::BufferedReader(BufReader::new(fd))
        };

        self.cur_block = bhh.clone();
        self.cur_block_fd = Some(filestore_type);
        self.readonly = !readwrite;
        Ok(())
    }

    pub fn get_cur_block_identifier(&mut self) -> Result<u32, Error> {
        if Some(self.cur_block) == self.last_extended {
            self.last_extended_trie
                .as_ref()
                .map(|trie_ram| trie_ram.identifier)
                .ok_or_else(|| Error::CorruptionError(format!("last_extended is_some(), but last_extended_trie is none")))
        } else if let Some(ref mut cur_block_fd) = self.cur_block_fd {
            cur_block_fd.read_block_identifier()
        } else {
            Err(Error::NotOpenedError)
        }
    }
    
    pub fn get_cur_block(&self) -> BlockHeaderHash {
        self.cur_block.clone()
    }

    pub fn get_block_from_local_id(&self, local_id: u32) -> Result<&BlockHeaderHash, Error> {
        self.block_map.get_block_header_hash(local_id)
            .ok_or_else(|| Error::NotFoundError)
    }

    pub fn root_ptr(&self) -> u32 {
        if Some(self.cur_block) == self.last_extended {
            0
        }
        else {
            // first 32 bytes are the block parent hash 
            //   next 4 are the identifier
            (BLOCK_HEADER_HASH_ENCODED_SIZE as u32) + 4
        }
    }

    pub fn root_trieptr(&self) -> TriePtr {
        TriePtr::new(TrieNodeID::Node256, 0, self.root_ptr())
    }

    pub fn readwrite(&self) -> bool {
        !self.readonly
    }

    pub fn format(&mut self) -> Result<(), Error> {
        if self.readonly {
            trace!("Read-only!");
            return Err(Error::ReadOnlyError);
        }

        // blow away and recreate the Trie directory
        fs::remove_dir_all(self.dir_path.clone())
            .map_err(Error::IOError)?;

        fs::create_dir_all(self.dir_path.clone())
            .map_err(Error::IOError)?;

        match self.last_extended_trie {
            Some(ref mut trie_storage) => trie_storage.format()?,
            None => {}
        };

        self.cur_block = TrieFileStorage::block_sentinel();
        self.cur_block_fd = None;
        self.last_extended = None;
        self.last_extended_trie = None;

        self.block_map.clear();
        self.chain_tips.clear();

        Ok(())
    }

    pub fn read_node_hash_bytes(&mut self, ptr: &TriePtr, buf: &mut Vec<u8>) -> Result<(), Error> {
        if Some(self.cur_block) == self.last_extended {
            // special case 
            let trie_ram = self.last_extended_trie.as_mut()
                .expect("MARF CORRUPTION: last_extended is set, but last_extended_trie is None.");
            return trie_ram.read_node_hash_bytes(ptr, buf)
        }
        // some other block or ptr, or cache miss
        match self.cur_block_fd {
            Some(ref mut f) => {
                f.read_node_hash_bytes(ptr, buf)?;
                Ok(())
            },
            None => {
                trace!("Not found (no file is open)");
                Err(Error::NotFoundError)
            }
        }
    }

    // NOTE: ptr will not be treated as a backptr
    pub fn read_nodetype(&mut self, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash), Error> {
        trace!("read_nodetype({:?}): {:?}", &self.cur_block, ptr);

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
        
        let clear_ptr = ptr.from_backptr();

        if Some(self.cur_block) == self.last_extended {
            // special case
            assert!(self.last_extended_trie.is_some());
            return match self.last_extended_trie {
                Some(ref mut trie_storage) => trie_storage.read_nodetype(&clear_ptr),
                None => unreachable!()
            };
        }

        // some other block
        match self.cur_block_fd {
            Some(ref mut f) => f.read_nodetype(&clear_ptr),
            None => {
                trace!("Not found (no file is open)");
                Err(Error::NotFoundError)
            }
        }
    }
    
    pub fn write_nodetype(&mut self, disk_ptr: u32, node: &TrieNodeType, hash: TrieHash) -> Result<(), Error> {
        if self.readonly {
            trace!("Read-only!");
            return Err(Error::ReadOnlyError);
        }

        trace!("write_nodetype({:?}): at {}: {:?} {:?}", &self.cur_block, disk_ptr, &hash, node);
        
        self.write_count += 1;
        match node {
            TrieNodeType::Leaf(_) => {
                self.write_leaf_count += 1;
            },
            _ => {
                self.write_node_count += 1;
            }
        }

        if Some(self.cur_block) == self.last_extended {
            // special case
            assert!(self.last_extended_trie.is_some());
            return match self.last_extended_trie {
                Some(ref mut trie_storage) => trie_storage.write_nodetype(disk_ptr, node, hash),
                None => unreachable!()
            };
        }
        
        panic!("Tried to write to another Trie besides the currently-bufferred one.  This should never happen -- only flush() can write to disk!");
    }

    pub fn write_node<T: TrieNode + std::fmt::Debug>(&mut self, ptr: u32, node: &T, hash: TrieHash) -> Result<(), Error> {
        match node.id() {
            TrieNodeID::Node4 => self.write_nodetype(ptr, &node.try_as_node4().unwrap(), hash),
            TrieNodeID::Node16 => self.write_nodetype(ptr, &node.try_as_node16().unwrap(), hash),
            TrieNodeID::Node48 => self.write_nodetype(ptr, &node.try_as_node48().unwrap(), hash),
            TrieNodeID::Node256 => self.write_nodetype(ptr, &node.try_as_node256().unwrap(), hash),
            TrieNodeID::Leaf => self.write_nodetype(ptr, &node.try_as_leaf().unwrap(), hash),
            _ => panic!("Unknown node type {}", node.id())
        }
    }
    
    pub fn flush(&mut self) -> Result<(), Error> {
        // save the currently-bufferred Trie to disk, and atomically put it into place.
        // Idempotent.
        // Panics on I/O error.
        match (self.last_extended.take(), self.last_extended_trie.take()) {
            (Some(ref bhh), Some(ref mut trie_ram)) => {
                let block_path_tmp = TrieFileStorage::block_path_tmp(&self.dir_path, bhh);
                let block_path = self.cached_block_path(bhh);
                
                trace!("Flush {:?} to {:?} and then rename to {:?}", bhh, &block_path_tmp, block_path);

                let mut fd = fs::OpenOptions::new()
                            .read(false)
                            .write(true)
                            .truncate(true)
                            .open(&block_path_tmp)
                            .map_err(|e| {
                                if e.kind() == io::ErrorKind::NotFound {
                                    error!("File not found: {:?}", &block_path_tmp);
                                    Error::NotFoundError
                                }
                                else {
                                    Error::IOError(e)
                                }
                            })?;

                trace!("Flush: identifier of {:?} is {:?}", bhh, trie_ram.identifier);
                trie_ram.dump(&mut fd, bhh)?;

                #[cfg(target_os = "unix")] {
                    let fsync_ret = unsafe {
                        libc::fsync(fd.as_raw_fd())
                    };

                    if fsync_ret != 0 {
                        let last_errno = std::io::Error::last_os_error().raw_os_error();
                        panic!("Failed to fsync() on file descriptor for {:?}: error {:?}", &block_path_tmp, last_errno);
                    }
                }

                // TODO: I don't know if there's a way to do the above in Windows

                // atomically put this trie file in place
                trace!("Rename {:?} to {:?}", &block_path_tmp, &block_path);
                fs::rename(&block_path_tmp, &block_path)
                    .map_err(|e| panic!("Failed to rename {:?} to {:?}", &block_path_tmp, &block_path))?;
            },
            (None, None) => {},
            (_, _) => {
                // should never happen 
                panic!("Inconsistent state: have either block header hash or trie IO buffer, but not both");
            }
        }

        if !self.readonly {
            match self.cur_block_fd {
                Some(ref mut f) => f.flush()?,
                None => {}
            };
        }

        Ok(())
    }

    pub fn last_ptr(&mut self) -> Result<u32, Error> {
        if self.readonly {
            error!("TrieFileStorage is opened in read-only mode");
            return Err(Error::ReadOnlyError);
        }

        if self.last_extended_trie.is_some() {
            match self.last_extended_trie {
                Some(ref mut trie_storage) => trie_storage.last_ptr(),
                _ => unreachable!()
            }
        }
        else {
            panic!("Cannot allocate new ptrs in a Trie that is not in RAM");
        }
    }

    pub fn num_blocks(&self) -> usize {
        self.block_map.len()
    }
    
    pub fn chain_tips(&self) -> Vec<BlockHeaderHash> {
        let mut r = Vec::with_capacity(self.chain_tips.len());
        r.extend(self.chain_tips.iter());
        r
    }
}

