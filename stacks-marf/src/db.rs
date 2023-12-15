use std::{io::Write, ops::Deref};

use stacks_common::types::chainstate::TrieHash;

use super::{Result, node::{TriePtr, TrieNodeType}, MarfTrieId};

pub trait TrieDb 
where
    Self: Sized
{
    type TxType: TrieDbTransaction<Self> + Sized;

    fn transaction(
        &mut self
    ) -> Result<Self::TxType>;

    //fn create_tables_if_needed(&self) -> Result<()>;
    //fn migrate_tables_if_needed<T: MarfTrieId>(&self) -> Result<u64>;
    fn get_block_identifier<T: MarfTrieId>(&self, bhh: &T) -> Result<u32>;
    fn get_mined_block_identifier<T: MarfTrieId>(&self, bhh: &T) -> Result<u32>;
    fn get_confirmed_block_identifier<T: MarfTrieId>(
        &self,
        bhh: &T,
    ) -> Result<Option<u32>>;
    fn get_unconfirmed_block_identifier<T: MarfTrieId>(
        &self,
        bhh: &T,
    ) -> Result<Option<u32>>;
    fn get_block_hash<T: MarfTrieId>(&self, local_id: u32) -> Result<T>;
    fn write_trie_blob<T: MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> Result<u32>;
    fn update_external_trie_blob<T: MarfTrieId>(
        &self,
        block_hash: &T,
        offset: u64,
        length: u64,
        block_id: u32,
    ) -> Result<u32>;
    fn write_external_trie_blob<T: MarfTrieId>(
        &self,
        block_hash: &T,
        offset: u64,
        length: u64,
    ) -> Result<u32>;
    fn write_trie_blob_to_mined<T: MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> Result<u32>;
    fn write_trie_blob_to_unconfirmed<T: MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> Result<u32>;
    fn open_trie_blob<'a>(&self, block_id: u32) -> Result<Vec<u8>>;
    fn open_trie_blob_readonly<'a>(&self, block_id: u32) -> Result<Vec<u8>>;
    fn read_node_hash_bytes<W: Write>(
        &self,
        w: &mut W,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<(),>;
    fn read_node_hash_bytes_by_bhh<W: Write, T: MarfTrieId>(
        &self,
        w: &mut W,
        bhh: &T,
        ptr: &TriePtr,
    ) -> Result<()>;
    fn read_node_type(
        &self,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<(TrieNodeType, TrieHash)>;
    fn read_node_type_nohash(
        &self,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<TrieNodeType>;
    fn get_external_trie_offset_length(
        &self,
        block_id: u32,
    ) -> Result<(u64, u64)>;
    fn get_external_trie_offset_length_by_bhh<T: MarfTrieId>(
        &self,
        bhh: &T,
    ) -> Result<(u64, u64)>;
    fn get_external_blobs_length(&self) -> Result<u64>;
    //fn detect_partial_migration(&self) -> Result<bool, MarfError>;
    fn set_migrated(&self) -> Result<()>;
    fn get_node_hash_bytes(
        &self,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<TrieHash>;
    fn get_node_hash_bytes_by_bhh<T: MarfTrieId>(
        &self,
        bhh: &T,
        ptr: &TriePtr,
    ) -> Result<TrieHash>;
    fn tx_lock_bhh_for_extension<T: MarfTrieId>(
        &self,
        bhh: &T,
        unconfirmed: bool,
    ) -> Result<bool>;
    fn lock_bhh_for_extension<T: MarfTrieId>(
        &self,
        bhh: &T,
        unconfirmed: bool,
    ) -> Result<bool>;
    fn count_blocks(&self) -> Result<u32>;
    fn is_unconfirmed_block(&self, block_id: u32) -> Result<bool>;
    fn drop_lock<T: MarfTrieId>(&self, bhh: &T) -> Result<()>;
    fn drop_unconfirmed_trie<T: MarfTrieId>(&self, bhh: &T) -> Result<()>;
    fn clear_lock_data(&self) -> Result<()>;
    //fn clear_tables() -> Result<(), MarfError>;

    #[cfg(test)]
    fn read_all_block_hashes_and_roots<T: MarfTrieId>(
        &self,
    ) -> Result<Vec<(TrieHash, T)>>;

    fn format(&self) -> Result<()>;
    fn reopen_readonly(&self) -> Result<Self>;
}

pub trait TrieDbTransaction<TrieDB> 
where
    TrieDB: TrieDb,
    Self: Deref<Target = TrieDB>
{

}