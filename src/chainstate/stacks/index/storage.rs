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
    Cursor
};

use std::char::from_digit;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use hashbrown::HashMap;
use std::collections::VecDeque;

use std::fs;
use std::path::{
    Path,
    PathBuf
};

use chainstate::burn::BlockHeaderHash;
use chainstate::burn::BLOCK_HEADER_HASH_ENCODED_SIZE;

use chainstate::stacks::index::{
    TrieHash,
    TRIEHASH_ENCODED_SIZE,
    fast_extend_from_slice,
};

use chainstate::stacks::index::bits::{
    get_node_byte_len,
    write_node_bytes,
    read_hash_bytes,
    read_node_hash_bytes,
    read_nodetype,
    get_node_hash
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
    TrieCursor
};

use chainstate::stacks::index::fork_table::{
    TrieForkPtr,
    TrieForkTable
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

pub fn read_all<R: Read>(f: &mut R, buf: &mut [u8]) -> Result<usize, Error> {
    let mut cnt = 0;
    while cnt < buf.len() {
        let nr = f.read(&mut buf[cnt..])
            .map_err(Error::IOError)?;

        if nr == 0 {
            break;
        }

        cnt += nr;
    }
    Ok(cnt)
}

pub fn write_all<W: Write>(f: &mut W, buf: &[u8]) -> Result<usize, Error> {
    let mut cnt = 0;
    while cnt < buf.len() {
        let nw = f.write(&buf[cnt..buf.len()])
            .map_err(Error::IOError)?;
        cnt += nw;
    }
    Ok(cnt)
}

/// A trait that defines all the operations needed to store index data.
pub trait TrieStorage {
    fn extend(&mut self, bhh: &BlockHeaderHash) -> Result<(), Error>;
    fn open(&mut self, bhh: &BlockHeaderHash, readwrite: bool) -> Result<(), Error>;
    fn tell(&self) -> BlockHeaderHash;
    fn root_ptr(&self) -> u64;
    fn block_walk(&mut self, back_block: u32) -> Result<BlockHeaderHash, Error>;
    fn readwrite(&self) -> bool;
    fn format(&mut self) -> Result<(), Error>;
    fn read_node_hash_bytes(&mut self, ptr: &TriePtr, buf: &mut Vec<u8>) -> Result<(), Error>;
    fn read_node(&mut self, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash), Error>;
    fn write_node(&mut self, node: &TrieNodeType, hash: TrieHash) -> Result<(), Error>;
    fn flush(&mut self) -> Result<(), Error>;
    fn num_blocks(&self) -> usize;
}


/// In-RAM trie storage.
/// Used by TrieFileStorage to buffer the next trie being built.
pub struct TrieRAM {
    data: Vec<(TrieNodeType, TrieHash)>,
    offset: u64,
    num_nodes: u64,
    block_header: BlockHeaderHash,
    readonly: bool,

    read_count: u64,
    read_backptr_count: u64,
    read_node_count: u64,
    read_leaf_count: u64,

    write_count: u64,
    write_node_count: u64,
    write_leaf_count: u64,

    total_bytes: usize
}

// Trie in RAM without the serialization overhead
impl TrieRAM {
    pub fn new(block_header: &BlockHeaderHash, capacity_hint: usize) -> TrieRAM {
        TrieRAM {
            data: Vec::with_capacity(capacity_hint),
            offset: 0,
            num_nodes: 0,
            block_header: block_header.clone(),
            readonly: false,

            read_count: 0,
            read_backptr_count: 0,
            read_node_count: 0,
            read_leaf_count: 0,

            write_count: 0,
            write_node_count: 0,
            write_leaf_count: 0,

            total_bytes: 0
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

    /// Walk through the bufferred TrieNodes and dump them to f.
    fn dump_traverse<F: Read + Write + Seek>(&mut self, f: &mut F, root: &TrieNodeType, hash: &TrieHash, parent_hash: &BlockHeaderHash) -> Result<u64, Error> {
        let mut frontier : VecDeque<(TrieNodeType, TrieHash)> = VecDeque::new();

        let mut node_data = vec![];
        let mut offsets = vec![];

        frontier.push_back((root.clone(), hash.clone()));

        let mut ptr = BLOCK_HEADER_HASH_ENCODED_SIZE as u64;       // first 32 bytes is reserved for the parent block hash
        
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
            match node {
                TrieNodeType::Leaf(_) => {},
                TrieNodeType::Node4(ref data) => {
                    for i in 0..4 {
                        if data.ptrs[i].id != TrieNodeID::Empty && !is_backptr(data.ptrs[i].id) {
                            let (child, child_hash) = self.read_node(&data.ptrs[i])?;
                            frontier.push_back((child, child_hash));
                        }
                    }
                },
                TrieNodeType::Node16(ref data) => {
                    for i in 0..16 {
                        if data.ptrs[i].id != TrieNodeID::Empty && !is_backptr(data.ptrs[i].id) {
                            let (child, child_hash) = self.read_node(&data.ptrs[i])?;
                            frontier.push_back((child, child_hash));
                        }
                    }
                },
                TrieNodeType::Node48(ref data) => {
                    for i in 0..48 {
                        if data.ptrs[i].id != TrieNodeID::Empty && !is_backptr(data.ptrs[i].id) {
                            let (child, child_hash) = self.read_node(&data.ptrs[i])?;
                            frontier.push_back((child, child_hash));
                        }
                    }
                },
                TrieNodeType::Node256(ref data) => {
                    for i in 0..256 {
                        if data.ptrs[i].id != TrieNodeID::Empty && !is_backptr(data.ptrs[i].id) {
                            let (child, child_hash) = self.read_node(&data.ptrs[i])?;
                            frontier.push_back((child, child_hash));
                        }
                    }
                },
            }
            
            node_data.push((node, node_hash));
            offsets.push(ptr as u32);
        }

        assert_eq!(offsets.len(), node_data.len());

        // step 2: update ptrs in all nodes
        let mut i = 0;
        for j in 0..node_data.len() {
            match node_data[j].0 {
                TrieNodeType::Leaf(_) => {},
                TrieNodeType::Node4(ref mut data) => {
                    for k in 0..4 {
                        if data.ptrs[k].id != TrieNodeID::Empty && !is_backptr(data.ptrs[k].id) {
                            data.ptrs[k].ptr = offsets[i];
                            i += 1;
                        }
                    }
                },
                TrieNodeType::Node16(ref mut data) => {
                    for k in 0..16 {
                        if data.ptrs[k].id != TrieNodeID::Empty && !is_backptr(data.ptrs[k].id) {
                            data.ptrs[k].ptr = offsets[i];
                            i += 1;
                        }
                    }
                },
                TrieNodeType::Node48(ref mut data) => {
                    for k in 0..48 {
                        if data.ptrs[k].id != TrieNodeID::Empty && !is_backptr(data.ptrs[k].id) {
                            data.ptrs[k].ptr = offsets[i];
                            i += 1;
                        }
                    }
                },
                TrieNodeType::Node256(ref mut data) => {
                    for k in 0..256 {
                        if data.ptrs[k].id != TrieNodeID::Empty && !is_backptr(data.ptrs[k].id) {
                            data.ptrs[k].ptr = offsets[i];
                            i += 1;
                        }
                    }
                }
            }
        }

        // step 3: write out each node (now that they have the write ptrs)
        frontier.push_back((root.clone(), hash.clone()));

        // write parent block ptr
        fseek(f, 0)?;
        write_all(f, parent_hash.as_bytes())?;

        for i in 0..node_data.len() {
            // dump the node to storage
            let node_hash = node_data[i].1;
            let _ = match node_data[i].0 {
                TrieNodeType::Leaf(ref data) => write_node_bytes(f, data, node_hash),
                TrieNodeType::Node4(ref data) => write_node_bytes(f, data, node_hash),
                TrieNodeType::Node16(ref data) => write_node_bytes(f, data, node_hash),
                TrieNodeType::Node48(ref data) => write_node_bytes(f, data, node_hash),
                TrieNodeType::Node256(ref data) => write_node_bytes(f, data, node_hash),
            }?;
            
            // next node
            fseek(f, offsets[i] as u64)?;
        }

        Ok(ptr)
    }

    /// Dump ourself to f
    pub fn dump<F: Read + Write + Seek>(&mut self, f: &mut F, bhh: &BlockHeaderHash, parent_bhh: &BlockHeaderHash) -> Result<u64, Error> {
        if self.block_header == *bhh {
            let root_ptr = self.root_ptr();
            let (root, hash) = self.read_node(&TriePtr::new(TrieNodeID::Node256, 0, root_ptr as u32))?;
            self.dump_traverse(f, &root, &hash, parent_bhh)
        }
        else {
            trace!("Failed to dump {:?}: not the current block", bhh);
            Err(Error::NotFoundError)
        }
    }

    fn size_hint(&self) -> usize {
        self.total_bytes
    }
}

impl TrieStorage for TrieRAM {
    fn extend(&mut self, bhh: &BlockHeaderHash) -> Result<(), Error> {
        if self.block_header == *bhh {
            return Err(Error::ExistsError);
        }
        trace!("Extend to {:?}", bhh);
        self.block_header = bhh.clone();
        self.offset = 0;
        self.num_nodes = 0;
        self.data.clear();
        self.readonly = false;
        Ok(())
    }

    fn open(&mut self, bhh: &BlockHeaderHash, readwrite: bool) -> Result<(), Error> {
        if self.block_header != *bhh {
            trace!("Failed to open {:?}: not the current block", bhh);
            return Err(Error::NotFoundError);
        }
        self.block_header = bhh.clone();
        self.offset = 0;
        self.num_nodes = self.data.len() as u64;
        self.readonly = !readwrite;
        Ok(())
    }

    fn tell(&self) -> BlockHeaderHash {
        self.block_header.clone()
    }
    
    fn block_walk(&mut self, _back_block: u32) -> Result<BlockHeaderHash, Error> {
        panic!("Not implemented for TrieRAM");
    }

    fn root_ptr(&self) -> u64 { 0 }

    fn readwrite(&self) -> bool {
        !self.readonly
    }

    fn format(&mut self) -> Result<(), Error> {
        if self.readonly {
            trace!("Read-only!");
            return Err(Error::ReadOnlyError);
        }

        self.data.clear();
        self.offset = 0;
        self.num_nodes = 0;
        Ok(())
    }

    fn read_node_hash_bytes(&mut self, ptr: &TriePtr, buf: &mut Vec<u8>) -> Result<(), Error> {
        if (ptr.ptr() as u64) >= (self.data.len() as u64) {
            trace!("TrieRAM: Failed to read node bytes: {} >= {}", ptr.ptr(), self.data.len());
            Err(Error::NotFoundError)
        }
        else {
            // buf.extend_from_slice(self.data[ptr.ptr() as usize].1.as_bytes());
            fast_extend_from_slice(buf, self.data[ptr.ptr() as usize].1.as_bytes());
            Ok(())
        }
    }

    fn read_node(&mut self, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash), Error> {
        let disk_ptr = ftell(self)?;
        trace!("TrieRAM: read_node({:?}): at {}: {:?}", &self.block_header, disk_ptr, ptr);

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

    fn write_node(&mut self, node: &TrieNodeType, hash: TrieHash) -> Result<(), Error> {
        if self.readonly {
            trace!("Read-only!");
            return Err(Error::ReadOnlyError);
        }

        let disk_ptr = ftell(self)?;
        trace!("TrieRAM: write_node({:?}): at {}: {:?} {:?}", &self.block_header, disk_ptr, &hash, node);
        
        self.write_count += 1;
        match node {
            TrieNodeType::Leaf(_) => {
                self.write_leaf_count += 1;
            },
            _ => {
                self.write_node_count += 1;
            }
        }

        if self.offset < (self.data.len() as u64) {
            self.data[self.offset as usize] = (node.clone(), hash);
            self.offset += 1;
            Ok(())
        }
        else if self.offset == (self.data.len() as u64) {
            self.data.push((node.clone(), hash));
            self.offset += 1;
            self.num_nodes += 1;
            self.total_bytes += get_node_byte_len(node);
            Ok(())
        }
        else {
            trace!("Failed to write node bytes: off the end of the buffer");
            Err(Error::NotFoundError)
        }
    }

    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn num_blocks(&self) -> usize {
        1
    }
}

impl Seek for TrieRAM {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(ref loc) => {
                let prev = self.offset;
                self.offset = *loc;
                Ok(prev)
            },
            SeekFrom::End(ref loc) => {
                let prev = self.num_nodes;
                let abs_loc = (*loc).abs() as u64;
                if abs_loc > self.num_nodes {
                    // can't seek behind 0
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, Error::BadSeekValue));
                }

                let new_offset = (self.num_nodes as i128) + (*loc as i128);
                if new_offset > ((1 as i128) << 64) - 1 {
                    // overflow 
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, Error::BadSeekValue));
                }

                self.offset = new_offset as u64;
                Ok(prev)
            },
            SeekFrom::Current(ref loc) => {
                let prev = self.offset;
                let abs_loc = (*loc).abs() as u64;
                if abs_loc > self.num_nodes {
                    // can't seek behind 0
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, Error::BadSeekValue));
                }

                let new_offset = (self.offset as i128) + (*loc as i128);
                if new_offset > ((1 as i128) << 64) - 1 {
                    // overflow 
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, Error::BadSeekValue));
                }

                self.offset = new_offset as u64;
                Ok(prev)
            }
        }
    }
}

// disk-backed Trie.
// Keeps the last-extended Trie in-RAM and flushes it to disk on either a call to flush() or a call
// to extend() with a different block header hash.
pub struct TrieFileStorage {
    pub dir_path: String,
    readonly: bool,

    last_extended: Option<BlockHeaderHash>,
    last_extended_trie: Option<TrieRAM>,
    
    cur_block: BlockHeaderHash,
    cur_block_fd: Option<fs::File>,
    cur_block_fork_ptr: Option<TrieForkPtr>,        // the fork_ptr in the fork_table where cur_block lives (it's unreasonably effective to cache this)
    
    read_count: u64,
    read_backptr_count: u64,
    read_node_count: u64,
    read_leaf_count: u64,

    write_count: u64,
    write_node_count: u64,
    write_leaf_count: u64,

    // map chain tips to the list of their ancestors
    pub fork_table: TrieForkTable,

    // cache of block paths (they're surprisingly expensive to generate)
    block_path_cache: HashMap<BlockHeaderHash, PathBuf>,
}

impl TrieFileStorage {
    pub fn new(dir_path: &String) -> Result<TrieFileStorage, Error> {
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
        
        let fork_table = TrieFileStorage::read_fork_table(dir_path, &TrieFileStorage::block_sentinel())?;

        let ret = TrieFileStorage {
            dir_path: dir_path.clone(),
            readonly: false,

            last_extended: None,
            last_extended_trie: None,

            cur_block: TrieFileStorage::block_sentinel(),
            cur_block_fd: None,
            cur_block_fork_ptr: None,
            
            read_count: 0,
            read_backptr_count: 0,
            read_node_count: 0,
            read_leaf_count: 0,

            write_count: 0,
            write_node_count: 0,
            write_leaf_count: 0,

            fork_table: fork_table,
            block_path_cache: HashMap::new(),
        };

        Ok(ret)
    }

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

    pub fn read_block_parent(dir_path: &String, bhh: &BlockHeaderHash) -> Result<BlockHeaderHash, Error> {
        let block_path = TrieFileStorage::block_path(dir_path, bhh);
        let mut fd = fs::OpenOptions::new()
                    .read(true)
                    .write(false)
                    .open(&block_path)
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            trace!("Not found: {:?}", &block_path);
                            Error::NotFoundError
                        }
                        else {
                            Error::IOError(e)
                        }
                    })?;

        let mut hashbuf = Vec::with_capacity(TRIEHASH_ENCODED_SIZE);
        fseek(&mut fd, 0)?;
        read_hash_bytes(&mut fd, &mut hashbuf)?;

        let mut hashbuf_slice = [0u8; TRIEHASH_ENCODED_SIZE];
        hashbuf_slice.copy_from_slice(&hashbuf[0..TRIEHASH_ENCODED_SIZE]);

        Ok(BlockHeaderHash(hashbuf_slice))
    }

    /// Scan the block directory and get all child --> parent mappings
    /// and parent --> [children] mappings
    pub fn scan_blocks(dir_path: &String) -> Result<HashMap<BlockHeaderHash, Vec<BlockHeaderHash>>, Error> {
        let mut parent_children : HashMap<BlockHeaderHash, Vec<BlockHeaderHash>> = HashMap::new();

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
                    let block_name_opt = block_path.file_name();
                    let block_name = match block_name_opt {
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

                    let bhh = match BlockHeaderHash::from_hex(&block_name) {
                        Ok(h) => h,
                        Err(_) => {
                            trace!("Skip {:?}", &block_path);
                            continue;
                        }
                    };

                    let bhh_parent = TrieFileStorage::read_block_parent(dir_path, &bhh)?;
                    if parent_children.contains_key(&bhh_parent) {
                        match parent_children.get_mut(&bhh_parent) {
                            Some(ref mut children) => {
                                children.push(bhh);
                            },
                            None => {
                                unreachable!();
                            }
                        }
                    }
                    else {
                        parent_children.insert(bhh_parent, vec![bhh]);
                    }
                }
            }
        }
        
        Ok(parent_children)
    }

    fn read_fork_table(dir_path: &String, root_hash: &BlockHeaderHash) -> Result<TrieForkTable, Error> {
        // maps a block hash to its list of unique ancestors.
        // has an entry for block hashes that are either chain tips, or parents of two or more forks.
        let parent_children = TrieFileStorage::scan_blocks(dir_path)?;
        TrieForkTable::new(root_hash, &parent_children)
    }

    #[cfg(test)]
    pub fn read_block_root_hash(&self, bhh: &BlockHeaderHash) -> Result<TrieHash, Error> {
        let path = TrieFileStorage::block_path(&self.dir_path, bhh);
        let mut fd = fs::OpenOptions::new()
                    .read(true)
                    .write(false)
                    .open(&path)
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            trace!("Not found: {:?}", &path);
                            Error::NotFoundError
                        }
                        else {
                            Error::IOError(e)
                        }
                    })?;

        let root_ptr = TriePtr::new(TrieNodeID::Node256, 0, 32);
        let mut hash_buf = Vec::with_capacity(TRIEHASH_ENCODED_SIZE);
        read_node_hash_bytes(&mut fd, &root_ptr, &mut hash_buf)?;

        Ok(TrieHash::from_bytes(&hash_buf[..]).unwrap())
    }

    #[cfg(test)]
    pub fn read_root_to_block_table(&mut self) -> Result<HashMap<TrieHash, BlockHeaderHash>, Error> {
        let mut ret = HashMap::new();
        for fork_column in self.fork_table.fork_table.iter() {
            for bhh in fork_column.iter() {
                if *bhh == TrieFileStorage::block_sentinel() {
                    continue;
                }
                let root_hash = self.read_block_root_hash(bhh)?;
                ret.insert(root_hash, bhh.clone());
            }
        }

        let (last_extended_opt, last_extended_trie_opt) = match (self.last_extended.take(), self.last_extended_trie.take()) {
            (Some(bhh), Some(mut trie_ram)) => {
                let ptr = TriePtr::new(set_backptr(TrieNodeID::Node256), 0, trie_ram.root_ptr() as u32);
                let mut root_hash_bytes = Vec::with_capacity(TRIEHASH_ENCODED_SIZE);
                trie_ram.read_node_hash_bytes(&ptr, &mut root_hash_bytes)?;
                let root_hash = TrieHash::from_bytes(&root_hash_bytes[..]).unwrap();
                ret.insert(root_hash, bhh.clone());
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
}

impl TrieStorage for TrieFileStorage {
    fn extend(&mut self, bhh: &BlockHeaderHash) -> Result<(), Error> {
        if self.fork_table.size() > 0 {
            if !self.fork_table.contains(&self.cur_block) {
                return Err(Error::CorruptionError(format!("Current block {:?} not in fork table", &self.cur_block)));
            }
        }
        if self.fork_table.contains(bhh) {
            trace!("Block {:?} is in the fork table already", bhh);
            return Err(Error::ExistsError);
        }
        
        self.readonly = false;
        self.flush()?;

        let size_hint = match self.last_extended_trie {
            Some(ref trie_storage) => trie_storage.size_hint() * 2,
            None => (1024 * 1024)
        };

        let trie_buf = TrieRAM::new(bhh, size_hint);

        // create an empty file for this block, so we can't extend to it again
        let block_dir = TrieFileStorage::block_dir(&self.dir_path, bhh);
        let block_path = TrieFileStorage::block_path(&self.dir_path, bhh);
        match fs::metadata(&block_path) {
            Ok(_) => {
                trace!("Block path exists: {:?}", &block_path);
                return Err(Error::ExistsError);
            },
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    return Err(Error::IOError(e));
                }
                fs::create_dir_all(block_dir)
                    .map_err(Error::IOError)?;

                trace!("Extend from {:?} to {:?} in {:?}", &self.cur_block, bhh, &block_path);

                // write the file out and add its parent
                let mut fd = fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create_new(true)
                            .open(&block_path)
                            .map_err(|e| {
                                if e.kind() == io::ErrorKind::NotFound {
                                    trace!("Not found: {:?}", &block_path);
                                    Error::NotFoundError
                                }
                                else {
                                    Error::IOError(e)
                                }
                            })?;

                write_all(&mut fd, self.cur_block.as_bytes())?;
            }
        }

        // extend the fork table
        self.fork_table.extend(&self.cur_block, bhh)?;
       
        // update internal structures
        self.cur_block = bhh.clone();
        self.cur_block_fd = None;
        self.cur_block_fork_ptr = None;

        self.last_extended = Some(bhh.clone());
        self.last_extended_trie = Some(trie_buf);
                
        trace!("Extended to {:?} in {:?}", &self.cur_block, &block_path);
        Ok(())
    }

    fn open(&mut self, bhh: &BlockHeaderHash, readwrite: bool) -> Result<(), Error> {
        let block_fork_ptr = self.fork_table.get_fork_ptr(bhh)?;

        if Some(*bhh) == self.last_extended {
            // nothing to do -- we're already ready.
            // just clear out.
            self.cur_block_fd = None;
            self.cur_block = bhh.clone();
            self.cur_block_fork_ptr = Some(block_fork_ptr);
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
                            trace!("Not found: {:?}", &block_path);
                            Error::NotFoundError
                        }
                        else {
                            Error::IOError(e)
                        }
                    })?;

        self.cur_block = bhh.clone();
        self.cur_block_fd = Some(fd);
        self.cur_block_fork_ptr = Some(block_fork_ptr);
        self.readonly = !readwrite;
        Ok(())
    }
    
    fn tell(&self) -> BlockHeaderHash {
        self.cur_block.clone()
    }
    
    fn block_walk(&mut self, back_block: u32) -> Result<BlockHeaderHash, Error> {
        trace!("block_walk from {:?} back {}", &self.cur_block, back_block);

        let prev_block = match self.cur_block_fork_ptr {
            Some(ref fork_ptr) => {
                self.fork_table.walk_back_from(fork_ptr, &self.cur_block, back_block)?
            },
            None => {
                let fork_ptr = self.fork_table.get_fork_ptr(&self.cur_block)?;
                self.cur_block_fork_ptr = Some(fork_ptr.clone());
                self.fork_table.walk_back_from(&fork_ptr, &self.cur_block, back_block)?
            }
        };
        
        if prev_block == TrieFileStorage::block_sentinel() {
            trace!("Not found: {:?} back {}", &self.cur_block, back_block);
            return Err(Error::NotFoundError);
        }
        
        trace!("block_walk from {:?} back {} is {:?}", &self.cur_block, back_block, &prev_block);
        Ok(prev_block)
    }
    
    fn root_ptr(&self) -> u64 {
        if Some(self.cur_block) == self.last_extended {
            0
        }
        else {
            // first 32 bytes are the block parent hash 
            32
        }
    }

    fn readwrite(&self) -> bool {
        !self.readonly
    }

    fn format(&mut self) -> Result<(), Error> {
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
        self.cur_block_fork_ptr = None;
        self.last_extended = None;
        self.last_extended_trie = None;
        self.fork_table.clear();
        
        Ok(())
    }

    fn read_node_hash_bytes(&mut self, ptr: &TriePtr, buf: &mut Vec<u8>) -> Result<(), Error> {
        if Some(self.cur_block) == self.last_extended {
            // special case 
            assert!(self.last_extended_trie.is_some());
            return match self.last_extended_trie {
                Some(ref mut trie_storage) => trie_storage.read_node_hash_bytes(ptr, buf),
                None => unreachable!()
            };
        }
        // some other block or ptr, or cache miss
        match self.cur_block_fd {
            Some(ref mut f) => {
                read_node_hash_bytes(f, ptr, buf)?;
                Ok(())
            },
            None => {
                trace!("Not found (no file is open)");
                Err(Error::NotFoundError)
            }
        }
    }

    // NOTE: ptr will not be treated as a backptr
    fn read_node(&mut self, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash), Error> {
        trace!("read_node({:?}): {:?}", &self.cur_block, ptr);

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

        if Some(self.cur_block) == self.last_extended {
            // special case
            assert!(self.last_extended_trie.is_some());
            return match self.last_extended_trie {
                Some(ref mut trie_storage) => trie_storage.read_node(&clear_ptr),
                None => unreachable!()
            };
        }

        // some other block
        match self.cur_block_fd {
            Some(ref mut f) => read_nodetype(f, &clear_ptr),
            None => {
                trace!("Not found (no file is open)");
                Err(Error::NotFoundError)
            }
        }
    }
    
    fn write_node(&mut self, node: &TrieNodeType, hash: TrieHash) -> Result<(), Error> {
        if self.readonly {
            trace!("Read-only!");
            return Err(Error::ReadOnlyError);
        }

        let disk_ptr = ftell(self)?;
        trace!("write_node({:?}): at {}: {:?} {:?}", &self.cur_block, disk_ptr, &hash, node);
        
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
                Some(ref mut trie_storage) => trie_storage.write_node(node, hash),
                None => unreachable!()
            };
        }

        match self.cur_block_fd {
            Some(_) => {
                // should never be reached -- the only disk writes occur on flush()
                panic!("Tried to write to an open file");
            },
            None => {
                trace!("Not found (no file is open)");
                Err(Error::NotFoundError)
            }
        }
    }
    
    fn flush(&mut self) -> Result<(), Error> {
        // save the currently-bufferred Trie to disk
        match (self.last_extended.take(), self.last_extended_trie.take()) {
            (Some(ref bhh), Some(ref mut trie_storage)) => {
                let block_path = self.cached_block_path(bhh);
                
                trace!("Flush {:?} to {:?}", bhh, &block_path);

                let parent_bhh = match self.fork_table.get_parent(bhh) {
                    Ok(parent) => {
                        parent
                    },
                    Err(e) => {
                        if self.fork_table.contains(bhh) {
                            // first block ever dumped
                            TrieFileStorage::block_sentinel()
                        }
                        else {
                            return Err(e);
                        }
                    }
                };

                let mut fd = fs::OpenOptions::new()
                            .read(false)
                            .write(true)
                            .truncate(true)
                            .open(&block_path)
                            .map_err(|e| {
                                if e.kind() == io::ErrorKind::NotFound {
                                    trace!("Not found: {:?}", &block_path);
                                    Error::NotFoundError
                                }
                                else {
                                    Error::IOError(e)
                                }
                            })?;

                trace!("Flush: parent of {:?} is {:?}", bhh, parent_bhh);
                trie_storage.dump(&mut fd, bhh, &parent_bhh)?;
            },
            (None, None) => {},
            (_, _) => {
                // should never happen 
                panic!("Inconsistent state: have either block header hash or trie IO buffer, but not both");
            }
        }

        if !self.readonly {
            match self.cur_block_fd {
                Some(ref mut f) => f.flush().map_err(Error::IOError)?,
                None => {}
            };
        }

        Ok(())
    }

    fn num_blocks(&self) -> usize {
        self.fork_table.size()
    }
}

impl Seek for TrieFileStorage {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        if Some(self.cur_block) == self.last_extended {
            assert!(self.last_extended_trie.is_some());
            return match self.last_extended_trie {
                Some(ref mut trie_storage) => trie_storage.seek(pos),
                None => unreachable!()
            };
        }

        match self.cur_block_fd {
            Some(ref mut f) => f.seek(pos),
            None => Err(io::Error::new(io::ErrorKind::Other, Error::BadSeekValue))
        }
    }
}

