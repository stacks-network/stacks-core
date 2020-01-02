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
    BufWriter,
};

use std::char::from_digit;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::collections::{VecDeque, HashMap, HashSet};

use std::fs;
use std::path::{
    Path,
    PathBuf
};

use std::os;
use std::iter::FromIterator;

use regex::Regex;

use chainstate::burn::BlockHeaderHash;
use chainstate::burn::BLOCK_HEADER_HASH_ENCODED_SIZE;

use chainstate::stacks::index::{
    TrieHash,
    TRIEHASH_ENCODED_SIZE,
};

use chainstate::stacks::index::bits::{
    get_node_byte_len,
    write_nodetype_bytes,
    read_hash_bytes,
    read_block_identifier,
    read_node_hash_bytes,
    read_nodetype,
    get_node_hash,
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

trait NodeHashReader {
    fn read_node_hash_bytes<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), Error>;
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

    // TODO: make more efficient with a hash table
    pub fn find_id(&self, target_bhh: &BlockHeaderHash) -> Option<u32> {
        for i in 0..self.map.len() {
            if self.map[i] == *target_bhh {
                return Some(i as u32);
            }
        }
        return None;
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

    pub fn write_trie_file<F: Write + Seek>(f: &mut F, node_data: &[(TrieNodeType, TrieHash)], offsets: &[u32],
                                                   identifier: u32, parent_hash: &BlockHeaderHash) -> Result<(), Error> {
        assert_eq!(node_data.len(), offsets.len());

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
    fn dump_traverse<F: Write + Seek>(&mut self, f: &mut F, root: &TrieNodeType, hash: &TrieHash) -> Result<u64, Error> {
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
    pub fn dump<F: Write + Seek>(&mut self, f: &mut F, bhh: &BlockHeaderHash) -> Result<u64, Error> {
        if self.block_header == *bhh {
            let (root, hash) = self.read_nodetype(&TriePtr::new(TrieNodeID::Node256, 0, 0))?;
            self.dump_traverse(f, &root, &hash)
        }
        else {
            error!("Failed to dump {:?}: not the current block", bhh);
            Err(Error::NotFoundError)
        }
    }

    fn size_hint(&self) -> usize {
        self.write_count as usize
        // the size hint is used for a capacity guess on the data vec, which is _nodes_
        //  NOT bytes. this led to enormous over-allocations
    }

    pub fn format(&mut self) -> Result<(), Error> {
        if self.readonly {
            trace!("Read-only!");
            return Err(Error::ReadOnlyError);
        }

        self.data.clear();
        Ok(())
    }

    pub fn read_node_hash(&self, ptr: &TriePtr) -> Result<TrieHash, Error> {
        let (_, node_trie_hash) = self.data.get(ptr.ptr() as usize)
            .ok_or_else(|| {
                error!("TrieRAM: Failed to read node bytes: {} >= {}", ptr.ptr(), self.data.len());
                Error::NotFoundError
            })?;

        Ok(node_trie_hash.clone())
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
            error!("TrieRAM read_nodetype({:?}): Failed to read node {:?}: {} >= {}", &self.block_header, ptr, ptr.ptr(), self.data.len());
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
            error!("Failed to write node bytes: off the end of the buffer");
            Err(Error::NotFoundError)
        }
    }

    /// Get the next ptr value for a node to store.
    pub fn last_ptr(&mut self) -> Result<u32, Error> {
        Ok(self.data.len() as u32)
    }
}

impl NodeHashReader for TrieRAM {
    fn read_node_hash_bytes<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), Error> {
        let (_, node_trie_hash) = self.data.get(ptr.ptr() as usize)
            .ok_or_else(|| {
                error!("TrieRAM: Failed to read node bytes: {} >= {}", ptr.ptr(), self.data.len());
                Error::NotFoundError
            })?;
        w.write_all(node_trie_hash.as_bytes())?;
        Ok(())
    }
}

impl NodeHashReader for fs::File {
    fn read_node_hash_bytes<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), Error> {
        w.write_all(&read_node_hash_bytes(self, ptr)?)?;
        Ok(())
    }
}

// disk-backed Trie.
// Keeps the last-extended Trie in-RAM and flushes it to disk on either a call to flush() or a call
// to extend_to_block() with a different block header hash.
pub struct TrieFileStorage {
    pub dir_path: String,

    last_extended: Option<(BlockHeaderHash, TrieRAM)>,
    
    cur_block: BlockHeaderHash,
    cur_block_fd: Option<fs::File>,
    
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

    pub trie_ancestor_hash_bytes_cache: Option<(BlockHeaderHash, Vec<TrieHash>)>,

    miner_tip: Option<BlockHeaderHash>,

    // used in testing in order to short-circuit block-height lookups
    //   when the trie struct is tested outside of marf.rs usage
    #[cfg(test)]
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
        test_debug!("Opened TrieFileStorage {}; {} blocks", dir_path, block_map.len());

        let ret = TrieFileStorage {
            dir_path,

            last_extended: None,

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
  
            miner_tip: None,
            
            // used in testing in order to short-circuit block-height lookups
            //   when the trie struct is tested outside of marf.rs usage
            #[cfg(test)]
            test_genesis_block: None,
        };

        Ok(ret)
    }

    pub fn set_miner_tip(&mut self, miner_tip: BlockHeaderHash) {
        self.miner_tip = Some(miner_tip)
    }

    pub fn get_miner_tip(&self) -> Option<BlockHeaderHash> {
        self.miner_tip.clone()
    }

    pub fn set_cached_ancestor_hashes_bytes(&mut self, bhh: &BlockHeaderHash, bytes: Vec<TrieHash>) {
        self.trie_ancestor_hash_bytes_cache = Some((bhh.clone(), bytes));
    }

    pub fn check_cached_ancestor_hashes_bytes(&mut self, bhh: &BlockHeaderHash) -> Option<Vec<TrieHash>> {
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
        read_block_identifier(fd)
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
            .expect("Invalid regex");

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

        let root_hash_ptr =
            TriePtr::new(TrieNodeID::Node256, 0, TrieFileStorage::root_ptr_disk());
        let hash = read_node_hash_bytes(&mut fd, &root_hash_ptr)?;

        Ok(TrieHash(hash))
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
        let mut ret = HashMap::new();

        for bhh in self.block_map.iter() {
            if let Some((ref last_extended, _)) = self.last_extended {
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

        let last_extended = match self.last_extended.take() {
            Some((bhh, trie_ram)) => {
                let ptr = TriePtr::new(set_backptr(TrieNodeID::Node256), 0, 0);

                let root_hash = trie_ram.read_node_hash(&ptr)?;

                ret.insert(root_hash.clone(), bhh.clone());
                Some((bhh, trie_ram))
            },
            _ => {
                None
            }
        };

        self.last_extended = last_extended;

        Ok(ret)
    }

    /// Extend the forest of Tries to include a new block.
    pub fn extend_to_block(&mut self, bhh: &BlockHeaderHash) -> Result<(), Error> {
        self.flush()?;

        let size_hint = match self.last_extended {
            Some((_, ref trie_storage)) => 2*trie_storage.size_hint(),
            None => (1024) // don't try to guess _byte_ allocation here.
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

        self.last_extended = Some((bhh.clone(), trie_buf));

        trace!("Extended to {:?} in {:?}", &self.cur_block, &block_path);
        Ok(())
    }

    pub fn open_block(&mut self, bhh: &BlockHeaderHash) -> Result<(), Error> {
        if *bhh == self.cur_block && self.cur_block_fd.is_some() {
            // no-op
            return Ok(())
        }

        let sentinel = TrieFileStorage::block_sentinel();
        if *bhh == sentinel {
            // just reset to newly opened state
            self.cur_block_fd = None;
            self.cur_block = sentinel;
            return Ok(());
        }

        if let Some((ref last_extended, _)) = self.last_extended {
            if last_extended == bhh {
                // nothing to do -- we're already ready.
                // just clear out.
                self.cur_block_fd = None;
                self.cur_block = bhh.clone();
                return Ok(());
            }
        }

        // opening a different Trie than the one we're extending
        let block_path = self.cached_block_path(bhh);
        let fd = fs::OpenOptions::new()
                    .read(true)
                    .write(false)
                    .open(&block_path)
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            debug!("File not found: {:?}", &block_path);
                            Error::NotFoundError
                        }
                        else {
                            Error::IOError(e)
                        }
                    })?;

        self.cur_block = bhh.clone();
        self.cur_block_fd = Some(fd);

        Ok(())
    }

    pub fn get_cur_block_identifier(&mut self) -> Result<u32, Error> {
        if let Some((ref last_extended, ref last_extended_trie)) = self.last_extended {
            if &self.cur_block == last_extended {
                return Ok(last_extended_trie.identifier)
            }
        }

        if let Some(ref mut cur_block_fd) = self.cur_block_fd {
            TrieFileStorage::read_block_identifier_from_fd(cur_block_fd)
        } else {
            Err(Error::NotOpenedError)
        }
    }
    
    pub fn get_cur_block(&self) -> BlockHeaderHash {
        self.cur_block.clone()
    }

    pub fn get_block_from_local_id(&self, local_id: u32) -> Result<&BlockHeaderHash, Error> {
        self.block_map.get_block_header_hash(local_id)
            .ok_or_else(|| {
                error!("Failed to get block header hash of local ID {} (only {} present)", local_id, self.block_map.len());
                Error::NotFoundError
            })
    }

    pub fn root_ptr(&self) -> u32 {
        if let Some((ref last_extended, ref last_extended_trie)) = self.last_extended {
            if &self.cur_block == last_extended {
                return 0
            }
        }

        TrieFileStorage::root_ptr_disk()
    }

    pub fn root_trieptr(&self) -> TriePtr {
        TriePtr::new(TrieNodeID::Node256, 0, self.root_ptr())
    }

    pub fn root_ptr_disk() -> u32 {
        // first 32 bytes are the block parent hash 
        //   next 4 are the identifier
        (BLOCK_HEADER_HASH_ENCODED_SIZE as u32) + 4
    }

    pub fn format(&mut self) -> Result<(), Error> {
        debug!("Format TrieFileStorage {}", &self.dir_path);

        // blow away and recreate the Trie directory
        fs::remove_dir_all(self.dir_path.clone())
            .map_err(Error::IOError)?;

        fs::create_dir_all(self.dir_path.clone())
            .map_err(Error::IOError)?;

        match self.last_extended {
            Some((_, ref mut trie_storage)) => trie_storage.format()?,
            None => {}
        };

        self.cur_block = TrieFileStorage::block_sentinel();
        self.cur_block_fd = None;
        self.last_extended = None;

        self.block_map.clear();
        self.chain_tips.clear();

        Ok(())
    }

    /// Read a node's children's hashes into the provided <Write> implementation.
    /// This only works for intermediate nodes and leafs (the latter of which have no children).
    ///
    /// This method is designed to only access hashes that are either (1) in this Trie, or (2) in
    /// RAM already (i.e. as part of the block map)
    ///
    /// This means that the hash of a node that is in a previous Trie will _not_ be its
    /// hash (as that would require a disk access), but would instead be the root hash of the Trie
    /// that contains it.  While this makes the Merkle proof construction a bit more complicated,
    /// it _significantly_ improves the performance of this method (which is crucial since this is on
    /// the write path, which must be as short as possible).
    ///
    /// Rules:
    /// If a node is empty, pass in an empty hash.
    /// If a node is in this Trie, pass its hash.
    /// If a node is in a previous Trie, pass the root hash of its Trie.
    ///
    /// On err, S may point to a prior block.  The caller should call s.open(...) if an error
    /// occurs.
    pub fn write_children_hashes<W: Write>(&mut self, node: &TrieNodeType, w: &mut W) -> Result<(), Error> {
        trace!("get_children_hashes_bytes for {:?}", node);

        let block_map = &self.block_map;

        if let Some((ref last_extended, ref mut last_extended_trie)) = self.last_extended {
            if &self.cur_block == last_extended {
                let hash_reader = last_extended_trie;
                return TrieFileStorage::inner_write_children_hashes(hash_reader, block_map, node, w)
            }
        }

        // otherwise, the current block is open as an FD
        let hash_reader = self.cur_block_fd.as_mut()
            .ok_or_else(|| {
                error!("Failed to get cur block fd as hash reader");
                Error::NotFoundError
            })?;

        TrieFileStorage::inner_write_children_hashes(hash_reader, block_map, node, w)
    }

    fn inner_write_children_hashes<W: Write, H: NodeHashReader>(
        hash_reader: &mut H, block_map: &BlockHashMap, node: &TrieNodeType, w: &mut W) -> Result<(), Error> {
        for ptr in node.ptrs().iter() {
            if ptr.id() == TrieNodeID::Empty {
                // hash of empty string
                w.write_all(TrieHash::from_data(&[]).as_bytes())?;
            }
            else if !is_backptr(ptr.id()) {
                // hash is in the same block as this node
                hash_reader.read_node_hash_bytes(ptr, w)?;
            }
            else {
                // AARON:
                //   I *think* this is no longer necessary in the fork-table-less construction.
                //   the back_pointer's consensus bytes uses this block_hash instead of a back_block
                //   integer. This means that it would _always_ be included the node's hash computation.
                let block_hash = block_map.get_block_header_hash(ptr.back_block())
                    .ok_or_else(|| {
                        error!("Failed to look up block at {}", ptr.back_block());
                        Error::NotFoundError
                    })?;
                w.write_all(block_hash.as_bytes())?;
            }
        }

        Ok(())
    }

    pub fn read_node_hash_bytes(&mut self, ptr: &TriePtr) -> Result<TrieHash, Error> {
        if let Some((ref last_extended, ref mut trie_ram)) = self.last_extended {
            // special case 
            if &self.cur_block == last_extended {
                return trie_ram.read_node_hash(ptr)
            }
        }

        // some other block or ptr, or cache miss
        match self.cur_block_fd {
            Some(ref mut f) => {
                read_node_hash_bytes(f, ptr)
                    .map(TrieHash)
            },
            None => {
                error!("Not found (no file is open)");
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

        if let Some((ref last_extended, ref mut trie_storage)) = self.last_extended {
            // special case 
            if &self.cur_block == last_extended {
                return trie_storage.read_nodetype(&clear_ptr)
            }
        }

        // some other block
        match self.cur_block_fd {
            Some(ref mut f) => read_nodetype(f, &clear_ptr),
            None => {
                error!("Not found (no file is open)");
                Err(Error::NotFoundError)
            }
        }
    }
    
    pub fn write_nodetype(&mut self, disk_ptr: u32, node: &TrieNodeType, hash: TrieHash) -> Result<(), Error> {
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

        // Only allow writes when the cur_block is the current in-RAM extending block.
        if let Some((ref last_extended, ref mut trie_storage)) = self.last_extended {
            if &self.cur_block == last_extended {
                return trie_storage.write_nodetype(disk_ptr, node, hash)
            }
        }

        panic!("Tried to write to another Trie besides the currently-bufferred one.  This should never happen -- only flush() can write to disk!");
    }

    pub fn write_node<T: TrieNode + std::fmt::Debug>(&mut self, ptr: u32, node: &T, hash: TrieHash) -> Result<(), Error> {
        let node_type = node.as_trie_node_type();
        self.write_nodetype(ptr, &node_type, hash)
    }

    /// If we opened a block with a given hash, but want to store it as a block with a *different*
    /// hash, then call this method to update the internal storage state to make it so.  This is
    /// necessary for validating blocks in the blockchain, since the miner will always build a
    /// block whose hash is all 0's (since it can't know the final block hash).  As such, a peer
    /// will process a block as if it's hash is all 0's (in order to validate the state root), and
    /// then use this method to switch over the block hash to the "real" block hash.
    fn block_retarget(&mut self, cur_bhh: &BlockHeaderHash, new_bhh: &BlockHeaderHash) -> Result<(), Error> {
        debug!("Retarget block {} to {}", cur_bhh.to_hex(), new_bhh.to_hex());

        // switch over state
        let block_dir = TrieFileStorage::block_dir(&self.dir_path, new_bhh);
        fs::create_dir_all(block_dir)
            .map_err(Error::IOError)?;

        // make it as if we had inserted this block the whole time
        if self.chain_tips.contains(cur_bhh) {
            self.chain_tips.remove(cur_bhh);
        }
        self.chain_tips.insert(new_bhh.clone());

        let block_id_opt = self.block_map.find_id(cur_bhh);
        match block_id_opt {
            Some(id) => self.block_map.set_block(new_bhh.clone(), id),
            None => {
                panic!("Block {} was never in the block map", cur_bhh);
            }
        }

        self.trie_ancestor_hash_bytes_cache = None;

        self.cur_block = new_bhh.clone();
        Ok(())
    }
    
    pub fn flush_to(&mut self, final_bhh: Option<&BlockHeaderHash>) -> Result<(), Error> {
        // save the currently-bufferred Trie to disk, and atomically put it into place (possibly to
        // a different block than the one opened, as indicated by final_bhh).
        // Runs once -- subsequent calls are no-ops.
        // Panics on a failure to rename the Trie file into place (i.e. if the the actual commitment
        // fails).
        // TODO: this needs to be more robust.  Also fsync the parent directory itself, before and
        // after.  Turns out rename(2) isn't crash-consistent, and turns out syscalls can get
        // reordered.
        if let Some((ref bhh, ref mut trie_ram)) = self.last_extended.take() {
            let block_path_tmp = TrieFileStorage::block_path_tmp(&self.dir_path, bhh);
            let (block_path, real_bhh) = match final_bhh {
                Some(real_bhh) => {
                    if *real_bhh != *bhh {
                        self.block_retarget(bhh, real_bhh)?;
                        assert_eq!(self.block_map.find_id(real_bhh), Some(trie_ram.identifier));
                        trie_ram.identifier = self.block_map.find_id(real_bhh).expect("FATAL: no idenifier for new block hash");
                    }
                    (self.cached_block_path(real_bhh), real_bhh.clone())
                }
                None => (self.cached_block_path(bhh), bhh.clone())
            };
            
            debug!("Flush {:?} to {:?}", bhh, block_path);

            // wrap in context to force the FD to _close_ before we execute
            //   a rename. would never be an issue in linux, but might cause problems
            //   in Windows.
            {
                let mut writer = BufWriter::new(fs::OpenOptions::new()
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
                            })?);

                debug!("Flush: identifier of {:?} is {:?}", real_bhh, trie_ram.identifier);
                trie_ram.dump(&mut writer, bhh)?;

                // this OS-generic fsync's.
                let fd = writer.into_inner()
                    .map_err(|e| { io::Error::from(e) })?;
                fd.sync_all()?;
            }   

            // atomically put this trie file in place
            debug!("Rename {:?} to {:?}", &block_path_tmp, &block_path);
            fs::rename(&block_path_tmp, &block_path)
                .unwrap_or_else(|_| panic!("Failed to rename {:?} to {:?}", &block_path_tmp, &block_path));
        }

        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        self.flush_to(None)
    }

    pub fn drop_extending_trie(&mut self) {
        if let Some((ref bhh, ref mut trie_ram)) = self.last_extended.take() {
            let block_path_tmp = TrieFileStorage::block_path_tmp(&self.dir_path, bhh);
            match fs::metadata(&block_path_tmp) {
                Ok(_md) => {
                    let res = fs::remove_file(&block_path_tmp);
                    match res {
                        Ok(_) => {},
                        Err(e) => {
                            warn!("Failed to remove '{:?}': {:?}", &block_path_tmp, &e);
                        }
                    };
                },
                Err(e) => {}
            }
        }

        self.last_extended = None;
    }

    pub fn last_ptr(&mut self) -> Result<u32, Error> {
        if let Some((_, ref mut trie_ram)) = self.last_extended {
            trie_ram.last_ptr()
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

