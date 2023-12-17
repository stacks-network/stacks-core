use std::{ops::{Deref, DerefMut}, rc::Rc, path::PathBuf};

use rusqlite::Connection;

use crate::{SqliteTrieDb, SqliteTrieDbTransaction};

use stacks_marf::{Result, MarfError, TrieDb, TrieDbTransaction};

pub struct InMemorySqliteTrieDb {
    inner: SqliteTrieDb
}

pub struct InMemorySqliteTrieDbTransaction<'a> {
    conn: &'a InMemorySqliteTrieDb,
    inner: SqliteTrieDbTransaction<'a>
}

impl InMemorySqliteTrieDb {
    pub fn new() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| MarfError::SQLError(e.to_string()))?;
        Ok(Self { 
            inner: SqliteTrieDb {
                conn: Rc::new(conn),
                is_readonly: false,
                db_path: Some(":memory:".to_string().into())
            } 
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
        Ok(Self::TxType {
            conn: self,
            inner: self.inner.transaction()?
        })
    }

    fn is_memory(&self) -> bool {
        true
    }

    fn db_path(&self) -> Result<Option<PathBuf>> {
        Ok(None)
    }

    fn is_readonly(&self) -> bool {
        self.inner.is_readonly()
    }

    fn get_block_identifier<T: stacks_marf::MarfTrieId>(&self, bhh: &T) -> Result<u32> {
        self.inner.get_block_identifier(bhh)
    }

    fn get_mined_block_identifier<T: stacks_marf::MarfTrieId>(&self, bhh: &T) -> Result<u32> {
        self.inner.get_mined_block_identifier(bhh)
    }

    fn get_confirmed_block_identifier<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
    ) -> Result<Option<u32>> {
        self.inner.get_confirmed_block_identifier(bhh)
    }

    fn get_unconfirmed_block_identifier<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
    ) -> Result<Option<u32>> {
        self.inner.get_unconfirmed_block_identifier(bhh)
    }

    fn get_block_hash<T: stacks_marf::MarfTrieId>(&self, local_id: u32) -> Result<T> {
        self.inner.get_block_hash(local_id)
    }

    fn write_trie_blob<T: stacks_marf::MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> Result<u32> {
        self.inner.write_trie_blob(block_hash, data)
    }

    fn update_external_trie_blob<T: stacks_marf::MarfTrieId>(
        &self,
        block_hash: &T,
        offset: u64,
        length: u64,
        block_id: u32,
    ) -> Result<u32> {
        self.inner.update_external_trie_blob(block_hash, offset, length, block_id)
    }

    fn write_external_trie_blob<T: stacks_marf::MarfTrieId>(
        &self,
        block_hash: &T,
        offset: u64,
        length: u64,
    ) -> Result<u32> {
        self.inner.write_external_trie_blob(block_hash, offset, length)
    }

    fn write_trie_blob_to_mined<T: stacks_marf::MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> Result<u32> {
        self.inner.write_trie_blob_to_mined(block_hash, data)
    }

    fn write_trie_blob_to_unconfirmed<T: stacks_marf::MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> Result<u32> {
        self.inner.write_trie_blob_to_unconfirmed(block_hash, data)
    }

    fn open_trie_blob<'a>(&self, block_id: u32) -> Result<Vec<u8>> {
        self.inner.open_trie_blob(block_id)
    }

    fn open_trie_blob_readonly<'a>(&self, block_id: u32) -> Result<Vec<u8>> {
        self.inner.open_trie_blob_readonly(block_id)
    }

    fn read_node_hash_bytes<W: std::io::prelude::Write>(
        &self,
        w: &mut W,
        block_id: u32,
        ptr: &stacks_marf::node::TriePtr,
    ) -> Result<(),> {
        self.inner.read_node_hash_bytes(w, block_id, ptr)
    }

    fn read_node_hash_bytes_by_bhh<W: std::io::prelude::Write, T: stacks_marf::MarfTrieId>(
        &self,
        w: &mut W,
        bhh: &T,
        ptr: &stacks_marf::node::TriePtr,
    ) -> Result<()> {
        self.inner.read_node_hash_bytes_by_bhh(w, bhh, ptr)
    }

    fn read_node_type(
        &self,
        block_id: u32,
        ptr: &stacks_marf::node::TriePtr,
    ) -> Result<(stacks_marf::node::TrieNodeType, stacks_common::types::chainstate::TrieHash)> {
        self.inner.read_node_type(block_id, ptr)
    }

    fn read_node_type_nohash(
        &self,
        block_id: u32,
        ptr: &stacks_marf::node::TriePtr,
    ) -> Result<stacks_marf::node::TrieNodeType> {
        self.inner.read_node_type_nohash(block_id, ptr)
    }

    fn get_external_trie_offset_length(
        &self,
        block_id: u32,
    ) -> Result<(u64, u64)> {
        self.inner.get_external_trie_offset_length(block_id)
    }

    fn get_external_trie_offset_length_by_bhh<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
    ) -> Result<(u64, u64)> {
        self.inner.get_external_trie_offset_length_by_bhh(bhh)
    }

    fn get_external_blobs_length(&self) -> Result<u64> {
        self.inner.get_external_blobs_length()
    }

    fn set_migrated(&self) -> Result<()> {
        self.inner.set_migrated()
    }

    fn get_node_hash_bytes(
        &self,
        block_id: u32,
        ptr: &stacks_marf::node::TriePtr,
    ) -> Result<stacks_common::types::chainstate::TrieHash> {
        self.inner.get_node_hash_bytes(block_id, ptr)
    }

    fn get_node_hash_bytes_by_bhh<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
        ptr: &stacks_marf::node::TriePtr,
    ) -> Result<stacks_common::types::chainstate::TrieHash> {
        self.inner.get_node_hash_bytes_by_bhh(bhh, ptr)
    }

    fn tx_lock_bhh_for_extension<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
        unconfirmed: bool,
    ) -> Result<bool> {
        self.inner.tx_lock_bhh_for_extension(bhh, unconfirmed)
    }

    fn lock_bhh_for_extension<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
        unconfirmed: bool,
    ) -> Result<bool> {
        self.inner.lock_bhh_for_extension(bhh, unconfirmed)
    }

    fn count_blocks(&self) -> Result<u32> {
        self.inner.count_blocks()
    }

    fn is_unconfirmed_block(&self, block_id: u32) -> Result<bool> {
        self.inner.is_unconfirmed_block(block_id)
    }

    fn drop_lock<T: stacks_marf::MarfTrieId>(&self, bhh: &T) -> Result<()> {
        self.inner.drop_lock(bhh)
    }

    fn drop_unconfirmed_trie<T: stacks_marf::MarfTrieId>(&self, bhh: &T) -> Result<()> {
        self.inner.drop_unconfirmed_trie(bhh)
    }

    fn clear_lock_data(&self) -> Result<()> {
        self.inner.clear_lock_data()
    }

    fn format(&self) -> Result<()> {
        self.inner.format()
    }

    fn reopen_readonly(&self) -> Result<Self> {
        let inner_reopened = self.inner.reopen_readonly()?;
        Ok(InMemorySqliteTrieDb {
            inner: inner_reopened
        })
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