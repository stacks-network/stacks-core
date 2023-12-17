use std::rc::Rc;

use stacks_marf::{Result, TrieDb};

use crate::{SqliteTrieDb, SqliteTrieDbTransaction};

impl TrieDb for SqliteTrieDb {
    type TxType<'a> = SqliteTrieDbTransaction<'a> where Self: 'a;

    fn transaction<'a>(
        &'a self
    ) -> Result<Self::TxType<'a>> {
        Ok(SqliteTrieDbTransaction { 
            db: self
        })
    }

    fn get_block_identifier<T: stacks_marf::MarfTrieId>(&self, bhh: &T) -> stacks_marf::Result<u32> {
        todo!()
    }

    fn get_mined_block_identifier<T: stacks_marf::MarfTrieId>(&self, bhh: &T) -> stacks_marf::Result<u32> {
        todo!()
    }

    fn get_confirmed_block_identifier<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
    ) -> stacks_marf::Result<Option<u32>> {
        todo!()
    }

    fn get_unconfirmed_block_identifier<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
    ) -> stacks_marf::Result<Option<u32>> {
        todo!()
    }

    fn get_block_hash<T: stacks_marf::MarfTrieId>(&self, local_id: u32) -> stacks_marf::Result<T> {
        todo!()
    }

    fn write_trie_blob<T: stacks_marf::MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> stacks_marf::Result<u32> {
        todo!()
    }

    fn update_external_trie_blob<T: stacks_marf::MarfTrieId>(
        &self,
        block_hash: &T,
        offset: u64,
        length: u64,
        block_id: u32,
    ) -> stacks_marf::Result<u32> {
        todo!()
    }

    fn write_external_trie_blob<T: stacks_marf::MarfTrieId>(
        &self,
        block_hash: &T,
        offset: u64,
        length: u64,
    ) -> stacks_marf::Result<u32> {
        todo!()
    }

    fn write_trie_blob_to_mined<T: stacks_marf::MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> stacks_marf::Result<u32> {
        todo!()
    }

    fn write_trie_blob_to_unconfirmed<T: stacks_marf::MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> stacks_marf::Result<u32> {
        todo!()
    }

    fn open_trie_blob<'a>(&self, block_id: u32) -> stacks_marf::Result<Vec<u8>> {
        todo!()
    }

    fn open_trie_blob_readonly<'a>(&self, block_id: u32) -> stacks_marf::Result<Vec<u8>> {
        todo!()
    }

    fn read_node_hash_bytes<W: std::io::prelude::Write>(
        &self,
        w: &mut W,
        block_id: u32,
        ptr: &stacks_marf::node::TriePtr,
    ) -> stacks_marf::Result<(),> {
        todo!()
    }

    fn read_node_hash_bytes_by_bhh<W: std::io::prelude::Write, T: stacks_marf::MarfTrieId>(
        &self,
        w: &mut W,
        bhh: &T,
        ptr: &stacks_marf::node::TriePtr,
    ) -> stacks_marf::Result<()> {
        todo!()
    }

    fn read_node_type(
        &self,
        block_id: u32,
        ptr: &stacks_marf::node::TriePtr,
    ) -> stacks_marf::Result<(stacks_marf::node::TrieNodeType, stacks_common::types::chainstate::TrieHash)> {
        todo!()
    }

    fn read_node_type_nohash(
        &self,
        block_id: u32,
        ptr: &stacks_marf::node::TriePtr,
    ) -> stacks_marf::Result<stacks_marf::node::TrieNodeType> {
        todo!()
    }

    fn get_external_trie_offset_length(
        &self,
        block_id: u32,
    ) -> stacks_marf::Result<(u64, u64)> {
        todo!()
    }

    fn get_external_trie_offset_length_by_bhh<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
    ) -> stacks_marf::Result<(u64, u64)> {
        todo!()
    }

    fn get_external_blobs_length(&self) -> stacks_marf::Result<u64> {
        todo!()
    }

    fn set_migrated(&self) -> stacks_marf::Result<()> {
        todo!()
    }

    fn get_node_hash_bytes(
        &self,
        block_id: u32,
        ptr: &stacks_marf::node::TriePtr,
    ) -> stacks_marf::Result<stacks_common::types::chainstate::TrieHash> {
        todo!()
    }

    fn get_node_hash_bytes_by_bhh<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
        ptr: &stacks_marf::node::TriePtr,
    ) -> stacks_marf::Result<stacks_common::types::chainstate::TrieHash> {
        todo!()
    }

    fn tx_lock_bhh_for_extension<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
        unconfirmed: bool,
    ) -> stacks_marf::Result<bool> {
        todo!()
    }

    fn lock_bhh_for_extension<T: stacks_marf::MarfTrieId>(
        &self,
        bhh: &T,
        unconfirmed: bool,
    ) -> stacks_marf::Result<bool> {
        todo!()
    }

    fn count_blocks(&self) -> stacks_marf::Result<u32> {
        todo!()
    }

    fn is_unconfirmed_block(&self, block_id: u32) -> stacks_marf::Result<bool> {
        todo!()
    }

    fn drop_lock<T: stacks_marf::MarfTrieId>(&self, bhh: &T) -> stacks_marf::Result<()> {
        todo!()
    }

    fn drop_unconfirmed_trie<T: stacks_marf::MarfTrieId>(&self, bhh: &T) -> stacks_marf::Result<()> {
        todo!()
    }

    fn clear_lock_data(&self) -> stacks_marf::Result<()> {
        todo!()
    }

    fn format(&self) -> stacks_marf::Result<()> {
        todo!()
    }

    fn reopen_readonly(&self) -> stacks_marf::Result<Self> {
        todo!()
    }

    fn is_memory(&self) -> bool {
        true
    }

    fn db_path(&self) -> Result<String> {
        Ok(":memory:".to_string())
    }

    fn is_readonly(&self) -> bool {
        false
    }

    
}