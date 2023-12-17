use std::{ops::{Deref, DerefMut}, rc::Rc};

use rusqlite::Connection;

use crate::{SqliteTrieDb, SqliteTrieDbTransaction};

use stacks_marf::{Result, MarfError, TrieDb, TrieDbTransaction};

pub struct InMemorySqliteTrieDb {
    inner: SqliteTrieDb
}

pub struct InMemorySqliteTrieDbTransaction<'a> {
    conn: Rc<InMemorySqliteTrieDb>,
    inner: SqliteTrieDbTransaction<'a>
}

impl InMemorySqliteTrieDb {
    pub fn new() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| MarfError::SQLError(e.to_string()))?;
        Ok(Self { 
            inner: SqliteTrieDb { conn: Rc::new(conn) } 
        })
    }
}

impl Deref for InMemorySqliteTrieDb {
    type Target = SqliteTrieDb;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for InMemorySqliteTrieDb {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl TrieDb for InMemorySqliteTrieDb {
    type TxType<'a> = InMemorySqliteTrieDbTransaction<'a>;

    fn transaction<'a>(
        &'a self
    ) -> Result<Self::TxType<'a>> {
        todo!()
    }

    fn is_memory(&self) -> bool {
        todo!()
    }

    fn db_path(&self) -> Result<String> {
        todo!()
    }

    fn is_readonly(&self) -> bool {
        todo!()
    }

    fn get_block_identifier<T: stacks_marf::MarfTrieId>(&self, bhh: &T) -> Result<u32> {
        todo!()
    }

    fn get_mined_block_identifier<T: stacks_marf::MarfTrieId>(&self, bhh: &T) -> Result<u32> {
        todo!()
    }

    fn get_confirmed_block_identifier<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
    ) -> Result<Option<u32>> {
        todo!()
    }

    fn get_unconfirmed_block_identifier<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
    ) -> Result<Option<u32>> {
        todo!()
    }

    fn get_block_hash<T: stacks_marf::MarfTrieId>(&self, local_id: u32) -> Result<T> {
        todo!()
    }

    fn write_trie_blob<T: stacks_marf::MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> Result<u32> {
        todo!()
    }

    fn update_external_trie_blob<T: stacks_marf::MarfTrieId>(
        &self,
        block_hash: &T,
        offset: u64,
        length: u64,
        block_id: u32,
    ) -> Result<u32> {
        todo!()
    }

    fn write_external_trie_blob<T: stacks_marf::MarfTrieId>(
        &self,
        block_hash: &T,
        offset: u64,
        length: u64,
    ) -> Result<u32> {
        todo!()
    }

    fn write_trie_blob_to_mined<T: stacks_marf::MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> Result<u32> {
        todo!()
    }

    fn write_trie_blob_to_unconfirmed<T: stacks_marf::MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> Result<u32> {
        todo!()
    }

    fn open_trie_blob<'a>(&self, block_id: u32) -> Result<Vec<u8>> {
        todo!()
    }

    fn open_trie_blob_readonly<'a>(&self, block_id: u32) -> Result<Vec<u8>> {
        todo!()
    }

    fn read_node_hash_bytes<W: std::io::prelude::Write>(
        &self,
        w: &mut W,
        block_id: u32,
        ptr: &stacks_marf::node::TriePtr,
    ) -> Result<(),> {
        todo!()
    }

    fn read_node_hash_bytes_by_bhh<W: std::io::prelude::Write, T: stacks_marf::MarfTrieId>(
        &self,
        w: &mut W,
        bhh: &T,
        ptr: &stacks_marf::node::TriePtr,
    ) -> Result<()> {
        todo!()
    }

    fn read_node_type(
        &self,
        block_id: u32,
        ptr: &stacks_marf::node::TriePtr,
    ) -> Result<(stacks_marf::node::TrieNodeType, stacks_common::types::chainstate::TrieHash)> {
        todo!()
    }

    fn read_node_type_nohash(
        &self,
        block_id: u32,
        ptr: &stacks_marf::node::TriePtr,
    ) -> Result<stacks_marf::node::TrieNodeType> {
        todo!()
    }

    fn get_external_trie_offset_length(
        &self,
        block_id: u32,
    ) -> Result<(u64, u64)> {
        todo!()
    }

    fn get_external_trie_offset_length_by_bhh<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
    ) -> Result<(u64, u64)> {
        todo!()
    }

    fn get_external_blobs_length(&self) -> Result<u64> {
        todo!()
    }

    fn set_migrated(&self) -> Result<()> {
        todo!()
    }

    fn get_node_hash_bytes(
        &self,
        block_id: u32,
        ptr: &stacks_marf::node::TriePtr,
    ) -> Result<stacks_common::types::chainstate::TrieHash> {
        todo!()
    }

    fn get_node_hash_bytes_by_bhh<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
        ptr: &stacks_marf::node::TriePtr,
    ) -> Result<stacks_common::types::chainstate::TrieHash> {
        todo!()
    }

    fn tx_lock_bhh_for_extension<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
        unconfirmed: bool,
    ) -> Result<bool> {
        todo!()
    }

    fn lock_bhh_for_extension<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
        unconfirmed: bool,
    ) -> Result<bool> {
        todo!()
    }

    fn count_blocks(&self) -> Result<u32> {
        todo!()
    }

    fn is_unconfirmed_block(&self, block_id: u32) -> Result<bool> {
        todo!()
    }

    fn drop_lock<T: stacks_marf::MarfTrieId>(&self, bhh: &T) -> Result<()> {
        todo!()
    }

    fn drop_unconfirmed_trie<T: stacks_marf::MarfTrieId>(&self, bhh: &T) -> Result<()> {
        todo!()
    }

    fn clear_lock_data(&self) -> Result<()> {
        todo!()
    }

    fn format(&self) -> Result<()> {
        todo!()
    }

    fn reopen_readonly(&self) -> Result<Self> {
        todo!()
    }
}

impl<'a> TrieDbTransaction<'a, InMemorySqliteTrieDb> for InMemorySqliteTrieDbTransaction<'a> {

}

impl Deref for InMemorySqliteTrieDbTransaction<'_> {
    type Target = InMemorySqliteTrieDb;

    fn deref(&self) -> &Self::Target {
        &*self.conn
    }
}