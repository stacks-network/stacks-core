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
    BlockMap,
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

use rusqlite::{
    Connection, OptionalExtension,
    types::{ FromSql,
             ToSql },
    NO_PARAMS
};

use std::convert::{
    TryFrom,
    TryInto
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

trait NodeHashReader {
    fn read_node_hash_bytes<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), Error>;
}

pub struct TrieSQL {}

impl BlockMap for TrieFileStorage {
    fn get_block_hash(&self, id: u32) -> Result<BlockHeaderHash, Error> {
        TrieSQL::get_block_hash(&self.db, id)
    }

    fn get_block_hash_caching(&mut self, id: u32) -> Result<&BlockHeaderHash, Error> {
        if !self.block_hash_cache.contains_key(&id) {
            self.block_hash_cache.insert(id, self.get_block_hash(id)?);
        }
        Ok(&self.block_hash_cache[&id])
    }
}

impl BlockMap for TrieSqlHashMapCursor<'_> {
    fn get_block_hash(&self, id: u32) -> Result<BlockHeaderHash, Error> {
        TrieSQL::get_block_hash(&self.db, id)
    }

    fn get_block_hash_caching(&mut self, id: u32) -> Result<&BlockHeaderHash, Error> {
        if !self.cache.contains_key(&id) {
            self.cache.insert(id, self.get_block_hash(id)?);
        }
        Ok(&self.cache[&id])
    }
}

static SQL_MARF_DATA_TABLE: &str = "
CREATE TABLE IF NOT EXISTS marf_data (
   block_id INTEGER PRIMARY KEY, 
   block_hash TEXT UNIQUE NOT NULL,
   data BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS block_hash_marf_data ON marf_data(block_hash);
";
static SQL_CHAIN_TIPS_TABLE: &str = "
CREATE TABLE IF NOT EXISTS chain_tips (block_hash TEXT UNIQUE NOT NULL);

CREATE INDEX IF NOT EXISTS block_hash_chain_tips ON chain_tips(block_hash);
";
static SQL_EXTENSION_LOCKS_TABLE: &str = "
CREATE TABLE IF NOT EXISTS block_extension_locks (block_hash TEXT UNIQUE NOT NULL);

CREATE INDEX IF NOT EXISTS block_hash_locks ON block_extension_locks(block_hash);
";

impl TrieSQL {
    pub fn create_tables_if_needed(conn: &mut Connection) -> Result<(), Error> {
        let tx = conn.transaction()?;

        tx.execute_batch(SQL_MARF_DATA_TABLE)?;
        tx.execute_batch(SQL_CHAIN_TIPS_TABLE)?;
        tx.execute_batch(SQL_EXTENSION_LOCKS_TABLE)?;

        tx.commit().map_err(|e| e.into())
    }

    pub fn get_block_identifier(conn: &Connection, bhh: &BlockHeaderHash) -> Result<u32, Error> {
        conn.query_row("SELECT block_id FROM marf_data WHERE block_hash = ?", &[bhh],
                       |row| row.get("block_id"))
            .map_err(|e| e.into())
    }

    pub fn get_block_hash(conn: &Connection, local_id: u32) -> Result<BlockHeaderHash, Error> {
        let result = conn.query_row("SELECT block_hash FROM marf_data WHERE block_id = ?", &[local_id],
                                    |row| row.get("block_hash"))
            .optional()?;
        result.ok_or_else(|| {
            error!("Failed to get block header hash of local ID {}", local_id);
            Error::NotFoundError
        })
    }

    pub fn write_trie_blob(conn: &Connection, block_hash: &BlockHeaderHash, data: &[u8]) -> Result<u32, Error> {
        let args: &[&dyn ToSql] = &[block_hash, &data];
        let mut s = conn.prepare("INSERT INTO marf_data (block_hash, data) VALUES (?, ?)")?;
        let block_id = s.insert(args)?
            .try_into()
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
        Ok(block_id)
    }

    #[cfg(test)]
    pub fn read_all_block_hashes_and_roots(conn: &Connection) -> Result<Vec<(TrieHash, BlockHeaderHash)>, Error> {
        let mut s = conn.prepare("SELECT block_hash, data FROM marf_data")?;
        let rows = s.query_and_then(NO_PARAMS, |row| {
            let block_hash: BlockHeaderHash = row.get("block_hash");
            let data = row.get_raw("data")
                .as_blob().expect("DB Corruption: MARF data is non-blob");
            let start = TrieFileStorage::root_ptr_disk() as usize;
            let trie_hash = TrieHash(read_hash_bytes(&mut &data[start..])?);
            Ok((trie_hash, block_hash))
        })?;
        rows.collect()
    }

    pub fn read_node_hash_bytes<W: Write>(conn: &Connection, w: &mut W, block_id: u32, ptr: &TriePtr) -> Result<(), Error> {
        let row_id: i64 = conn.query_row("SELECT block_id FROM marf_data WHERE block_id = ?",
                                         &[block_id], |r| r.get("block_id"))?;
        let mut blob = conn.blob_open(rusqlite::DatabaseName::Main, "marf_data", "data", row_id, true)?;
        let hash_buff = read_node_hash_bytes(&mut blob, ptr)?;
        w.write_all(&hash_buff)
            .map_err(|e| e.into())
    }

    pub fn read_node_hash_bytes_by_bhh<W: Write>(conn: &Connection, w: &mut W, bhh: &BlockHeaderHash, ptr: &TriePtr) -> Result<(), Error> {
        let row_id: i64 = conn.query_row("SELECT block_id FROM marf_data WHERE block_hash = ?",
                                         &[bhh], |r| r.get("block_id"))?;
        let mut blob = conn.blob_open(rusqlite::DatabaseName::Main, "marf_data", "data", row_id, true)?;
        let hash_buff = read_node_hash_bytes(&mut blob, ptr)?;
        w.write_all(&hash_buff)
            .map_err(|e| e.into())
    }

    pub fn read_node_type(conn: &Connection, block_id: u32, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash), Error> {
        let row_id: i64 = conn.query_row("SELECT block_id FROM marf_data WHERE block_id = ?",
                                         &[block_id], |r| r.get("block_id"))?;
        let mut blob = conn.blob_open(rusqlite::DatabaseName::Main, "marf_data", "data", row_id, true)?;
        read_nodetype(&mut blob, ptr)
    }

    pub fn get_node_hash_bytes(conn: &Connection, block_id: u32, ptr: &TriePtr) -> Result<TrieHash, Error> {
        let row_id: i64 = conn.query_row("SELECT block_id FROM marf_data WHERE block_id = ?",
                                         &[block_id], |r| r.get("block_id"))?;
        let mut blob = conn.blob_open(rusqlite::DatabaseName::Main, "marf_data", "data", row_id, true)?;
        let hash_buff = read_node_hash_bytes(&mut blob, ptr)?;
        Ok(TrieHash(hash_buff))
    }

    pub fn get_node_hash_bytes_by_bhh(conn: &Connection, bhh: &BlockHeaderHash, ptr: &TriePtr) -> Result<TrieHash, Error> {
        let row_id: i64 = conn.query_row("SELECT block_id FROM marf_data WHERE block_hash = ?",
                                         &[bhh], |r| r.get("block_id"))?;
        let mut blob = conn.blob_open(rusqlite::DatabaseName::Main, "marf_data", "data", row_id, true)?;
        let hash_buff = read_node_hash_bytes(&mut blob, ptr)?;
        Ok(TrieHash(hash_buff))
    }

    pub fn get_chain_tips(conn: &Connection) -> Result<Vec<BlockHeaderHash>, Error> {
        let mut s = conn.prepare("SELECT block_hash FROM chain_tips")?;
        let rows = s.query_map(NO_PARAMS, |row| row.get("block_hash"))?;
        rows.map(|i| i.map_err(|e| e.into())).collect()
    }

    pub fn remove_chain_tip_if_present(conn: &Connection, bhh: &BlockHeaderHash) -> Result<(), Error> {
        conn.execute("DELETE FROM chain_tips WHERE block_hash = ?", &[bhh])?;
        Ok(())
    }

    pub fn add_chain_tip(conn: &Connection, bhh: &BlockHeaderHash) -> Result<(), Error> {
        conn.execute("INSERT INTO chain_tips (block_hash) VALUES (?)", &[bhh])?;
        Ok(())
    }

    pub fn retarget_chain_tip_entry(conn: &Connection, from: &BlockHeaderHash, to: &BlockHeaderHash) -> Result<(), Error> {
        conn.execute("UPDATE chain_tips SET block_hash = ? WHERE block_hash = ?",
                     &[to, from])?;
        Ok(())
    }

    pub fn lock_bhh_for_extension(conn: &mut Connection, bhh: &BlockHeaderHash) -> Result<bool, Error> {
        let tx = conn.transaction()?;
        let is_bhh_committed = tx.query_row("SELECT 1 FROM marf_data WHERE block_hash = ? LIMIT 1", &[bhh],
                                            |_row| ()).optional()?.is_some();
        if is_bhh_committed {
            return Ok(false)
        }

        let is_bhh_locked = tx.query_row("SELECT 1 FROM block_extension_locks WHERE block_hash = ? LIMIT 1", &[bhh],
                                         |_row| ()).optional()?.is_some();
        if is_bhh_locked {
            return Ok(false)
        }

        tx.execute("INSERT INTO block_extension_locks (block_hash) VALUES (?)", &[bhh])?;

        tx.commit()?;
        Ok(true)
    }

    pub fn count_blocks(conn: &Connection) -> Result<u32, Error> {
        let result = conn.query_row("SELECT COUNT(1) AS count FROM marf_data", NO_PARAMS, |row| row.get("count"))?;
        Ok(result)
    }

    pub fn drop_lock(conn: &Connection, bhh: &BlockHeaderHash) -> Result<(), Error> {
        conn.execute("DELETE FROM block_extension_locks WHERE block_hash = ?", &[bhh])?;
        Ok(())
    }

    pub fn clear_lock_data(conn: &Connection) -> Result<(), Error> {
        conn.execute("DELETE FROM block_extension_locks", NO_PARAMS)?;
        Ok(())
    }

    pub fn clear_tables(conn: &mut Connection) -> Result<(), Error> {
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM block_extension_locks", NO_PARAMS)?;
        tx.execute("DELETE FROM marf_data", NO_PARAMS)?;
        tx.execute("DELETE FROM chain_tips", NO_PARAMS)?;
        tx.commit().map_err(|e| e.into())
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

    parent: BlockHeaderHash
}

// Trie in RAM without the serialization overhead
impl TrieRAM {
    pub fn new(block_header: &BlockHeaderHash, capacity_hint: usize, parent: &BlockHeaderHash) -> TrieRAM {
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
                                            parent_hash: &BlockHeaderHash) -> Result<(), Error> {
        assert_eq!(node_data.len(), offsets.len());

        // write parent block ptr
        fseek(f, 0)?;
        f.write_all(parent_hash.as_bytes())
            .map_err(|e| Error::IOError(e))?;
        // write zero-identifier (TODO: this is a convenience hack for now, we should remove the
        //    identifier from the trie data blob)
        fseek(f, BLOCK_HEADER_HASH_ENCODED_SIZE as u64)?;
        f.write_all(&0u32.to_le_bytes())
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
        TrieRAM::write_trie_file(f, node_data.as_slice(), offsets.as_slice(), &self.parent)?;

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

pub struct TrieSqlCursor <'a> {
    db: &'a Connection,
    block_id: u32
}

pub struct TrieSqlHashMapCursor <'a> {
    db: &'a Connection,
    cache: &'a mut HashMap<u32, BlockHeaderHash>
}

impl NodeHashReader for TrieSqlCursor<'_> {
    fn read_node_hash_bytes<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), Error> {
        TrieSQL::read_node_hash_bytes(self.db, w, self.block_id, ptr)
    }
}

// disk-backed Trie.
// Keeps the last-extended Trie in-RAM and flushes it to disk on either a call to flush() or a call
// to extend_to_block() with a different block header hash.
pub struct TrieFileStorage {
    pub dir_path: String,

    last_extended: Option<(BlockHeaderHash, TrieRAM)>,

    db: Connection,
    cur_block: BlockHeaderHash,
    cur_block_id: Option<u32>,

    read_count: u64,
    read_backptr_count: u64,
    read_node_count: u64,
    read_leaf_count: u64,

    write_count: u64,
    write_node_count: u64,
    write_leaf_count: u64,

    pub trie_ancestor_hash_bytes_cache: Option<(BlockHeaderHash, Vec<TrieHash>)>,

    miner_tip: Option<BlockHeaderHash>,

    block_hash_cache: HashMap<u32, BlockHeaderHash>,

    // used in testing in order to short-circuit block-height lookups
    //   when the trie struct is tested outside of marf.rs usage
    #[cfg(test)]
    pub test_genesis_block: Option<BlockHeaderHash>,
}

impl TrieFileStorage {
    pub fn new(dir_path: &str) -> Result<TrieFileStorage, Error> {
        let mut db = Connection::open(dir_path)?;
        let dir_path = dir_path.to_string();

        TrieSQL::create_tables_if_needed(&mut db)?;

        test_debug!("Opened TrieFileStorage {};", dir_path);

        let ret = TrieFileStorage {
            dir_path,
            db,

            last_extended: None,
            cur_block: TrieFileStorage::block_sentinel(),
            cur_block_id: None,
            
            read_count: 0,
            read_backptr_count: 0,
            read_node_count: 0,
            read_leaf_count: 0,

            write_count: 0,
            write_node_count: 0,
            write_leaf_count: 0,

            trie_ancestor_hash_bytes_cache: None,
            block_hash_cache: HashMap::new(),
  
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
        TrieFileStorage::new(":memory:")
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

    /// Recover from partially-written state -- i.e. blow it away.
    /// Doesn't get called automatically.
    pub fn recover(dir_path: &String) -> Result<(), Error> {
        let conn = Connection::open(dir_path)?;
        TrieSQL::clear_lock_data(&conn)
    }

    /// Read the Trie root node's hash from the block table.
    #[cfg(test)]
    pub fn read_block_root_hash(&self, bhh: &BlockHeaderHash) -> Result<TrieHash, Error> {
        let root_hash_ptr =
            TriePtr::new(TrieNodeID::Node256, 0, TrieFileStorage::root_ptr_disk());
        TrieSQL::get_node_hash_bytes_by_bhh(&self.db, bhh, &root_hash_ptr)
    }

    /// Generate a mapping between Trie root hashes and the blocks that contain them
    #[cfg(test)]
    pub fn read_root_to_block_table(&mut self) -> Result<HashMap<TrieHash, BlockHeaderHash>, Error> {
        let mut ret = HashMap::from_iter(TrieSQL::read_all_block_hashes_and_roots(&self.db)?
                                         .into_iter());

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

        TrieSQL::remove_chain_tip_if_present(&self.db, &self.cur_block)?;

        // this *requires* that bhh hasn't been the parent of any prior
        //   extended blocks.
        // this is currently enforced if you use the "public" interfaces
        //   to marfs, but could definitely be violated via raw updates
        //   to trie structures.
        TrieSQL::add_chain_tip(&self.db, bhh)?;

        let trie_buf = TrieRAM::new(bhh, size_hint, &self.cur_block);

        // place a lock on this block, so we can't extend to it again
        if !TrieSQL::lock_bhh_for_extension(&mut self.db, bhh)? {
            warn!("Block already extended: {}", &bhh);
            return Err(Error::ExistsError);
        }

        trace!("Extended from {} to {}", &self.cur_block, bhh);

        // write the new file out and add its parent
        // TODO: I don't think this is necessary in the SQL impl,
        //   so I've commented out -- but if it turns out we need to write
        //   the parent block somewhere at this point, I've left this todo here so as not
        //   to forget.
        //  TrieRAM::write_trie_file(&mut fd, &[], &[], identifier, bhh)?;
        //  fd.write_all(self.cur_block.as_bytes())
        //    .map_err(|e| Error::IOError(e))?;

        // update internal structures
        self.cur_block = bhh.clone();
        self.cur_block_id = None;

        self.last_extended = Some((bhh.clone(), trie_buf));

        Ok(())
    }

    pub fn open_block(&mut self, bhh: &BlockHeaderHash) -> Result<(), Error> {
        if *bhh == self.cur_block && self.cur_block_id.is_some() {
            // no-op
            return Ok(())
        }

        let sentinel = TrieFileStorage::block_sentinel();
        if *bhh == sentinel {
            // just reset to newly opened state
            self.cur_block = sentinel;
            // did we write to the sentinel ?
            self.cur_block_id = TrieSQL::get_block_identifier(&self.db, bhh)
                .ok();
            return Ok(());
        }

        if let Some((ref last_extended, _)) = self.last_extended {
            if last_extended == bhh {
                // nothing to do -- we're already ready.
                // just clear out.
                self.cur_block_id = None;
                self.cur_block = bhh.clone();
                return Ok(());
            }
        }

        // opening a different Trie than the one we're extending
        self.cur_block_id = Some(TrieSQL::get_block_identifier(&self.db, bhh)?);
        self.cur_block = bhh.clone();

        Ok(())
    }

    pub fn get_cur_block_identifier(&mut self) -> Result<u32, Error> {
        if let Some((ref last_extended, _)) = self.last_extended {
            if &self.cur_block == last_extended {
                return Err(Error::RequestedIdentifierForExtensionTrie)
            }
        }

        self.cur_block_id.ok_or_else(|| {
            Error::NotOpenedError
        })
    }
    
    pub fn get_cur_block(&self) -> BlockHeaderHash {
        self.cur_block.clone()
    }

    pub fn get_block_from_local_id(&mut self, local_id: u32) -> Result<&BlockHeaderHash, Error> {
        self.get_block_hash_caching(local_id)
    }

    pub fn root_ptr(&self) -> u32 {
        if let Some((ref last_extended, _)) = self.last_extended {
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

        // blow away db
        TrieSQL::clear_tables(&mut self.db)?;

        match self.last_extended {
            Some((_, ref mut trie_storage)) => trie_storage.format()?,
            None => {}
        };

        self.cur_block = TrieFileStorage::block_sentinel();
        self.cur_block_id = None;
        self.last_extended = None;

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

        let mut map = TrieSqlHashMapCursor { db: &self.db,
                                             cache: &mut self.block_hash_cache };

        if let Some((ref last_extended, ref mut last_extended_trie)) = self.last_extended {
            if &self.cur_block == last_extended {
                let hash_reader = last_extended_trie;
                return TrieFileStorage::inner_write_children_hashes(hash_reader, &mut map, node, w)
            }
        }

        // otherwise, the current block is open as an FD
        let mut cursor = TrieSqlCursor { db: &self.db,
                                         block_id: self.cur_block_id.ok_or_else(|| {
                                             error!("Failed to get cur block as hash reader");
                                             Error::NotFoundError
                                         })? };

        TrieFileStorage::inner_write_children_hashes(&mut cursor, &mut map, node, w)
    }

    fn inner_write_children_hashes<W: Write, H: NodeHashReader, M: BlockMap>(
        hash_reader: &mut H, map: &mut M, node: &TrieNodeType, w: &mut W) -> Result<(), Error> {
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
                let block_hash = map.get_block_hash_caching(ptr.back_block())?;
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
        match self.cur_block_id {
            Some(block_id) => {
                TrieSQL::get_node_hash_bytes(&self.db, block_id, ptr)
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
        match self.cur_block_id {
            Some(id) => TrieSQL::read_node_type(&self.db, id, &clear_ptr),
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
        debug!("Retarget block {} to {}", cur_bhh, new_bhh);

        // switch over state
        // make it as if we had inserted this block the whole time
        TrieSQL::retarget_chain_tip_entry(&self.db, cur_bhh, new_bhh)?;

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
            let real_bhh = match final_bhh {
                Some(real_bhh) => {
                    if real_bhh != bhh {
                        self.block_retarget(bhh, real_bhh)?;
                    }
                    real_bhh
                }
                None => bhh
            };
            
            debug!("Flush: {} to {}", bhh, real_bhh);

            let mut buffer = Cursor::new(Vec::new());
            trie_ram.dump(&mut buffer, bhh)?;
            // consume the cursor, get the buffer
            let buffer = buffer.into_inner();
            trace!("Buffering finished.");

            let tx = self.db.transaction()?;
            let block_id = TrieSQL::write_trie_blob(&tx, real_bhh, &buffer)?;
            TrieSQL::drop_lock(&tx, bhh)?;
            tx.commit()?;

            debug!("Flush: identifier of {} is {}", real_bhh, block_id);
        }

        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        self.flush_to(None)
    }

    pub fn drop_extending_trie(&mut self) {
        if let Some((ref bhh, _)) = self.last_extended.take() {
            let tx = self.db.transaction()
                .expect("Corruption: Failed to obtain db transaction");
            TrieSQL::remove_chain_tip_if_present(&tx, bhh)
                .expect("Corruption: Failed to drop the extended trie from chain tips");
            TrieSQL::drop_lock(&tx, bhh)
                .expect("Corruption: Failed to drop the extended trie lock");
            tx.commit()
                .expect("Corruption: Failed to drop the extended trie");
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
        let result = if self.last_extended.is_some() {
            1
        } else {
            0
        };
        result + (TrieSQL::count_blocks(&self.db)
                  .expect("Corruption: SQL Error on a non-fallible query.") as usize)
    }
    
    pub fn chain_tips(&self) -> Vec<BlockHeaderHash> {
        TrieSQL::get_chain_tips(&self.db)
            .expect("Corruption: SQL Error on a non-fallible query.")
    }
}
