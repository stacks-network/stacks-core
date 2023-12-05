use std::{io::Write, cell::{RefCell, Ref}, path::{PathBuf, Path}, marker::PhantomData};

use rusqlite::{Connection, Transaction, blob::Blob};
use stacks_common::types::chainstate::TrieHash;

use super::{Error, node::{TriePtr, TrieNodeType}, MarfTrieId};

pub trait TrieDb {
    fn create_tables_if_needed(&self) -> Result<(), Error>;
    fn migrate_tables_if_needed<T: MarfTrieId>(&self) -> Result<u64, Error>;
    fn get_block_identifier<T: MarfTrieId>(&self, bhh: &T) -> Result<u32, Error>;
    fn get_mined_block_identifier<T: MarfTrieId>(&self, bhh: &T) -> Result<u32, Error>;
    fn get_confirmed_block_identifier<T: MarfTrieId>(
        &self,
        bhh: &T,
    ) -> Result<Option<u32>, Error>;
    fn get_unconfirmed_block_identifier<T: MarfTrieId>(
        &self,
        bhh: &T,
    ) -> Result<Option<u32>, Error>;
    fn get_block_hash<T: MarfTrieId>(&self, local_id: u32) -> Result<T, Error>;
    fn write_trie_blob<T: MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> Result<u32, Error>;
    fn update_external_trie_blob<T: MarfTrieId>(
        &self,
        block_hash: &T,
        offset: u64,
        length: u64,
        block_id: u32,
    ) -> Result<u32, Error>;
    fn write_external_trie_blob<T: MarfTrieId>(
        &self,
        block_hash: &T,
        offset: u64,
        length: u64,
    ) -> Result<u32, Error>;
    fn write_trie_blob_to_mined<T: MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> Result<u32, Error>;
    fn write_trie_blob_to_unconfirmed<T: MarfTrieId>(
        &self,
        block_hash: &T,
        data: &[u8],
    ) -> Result<u32, Error>;
    fn open_trie_blob<'a>(conn: &'a Connection, block_id: u32) -> Result<Blob<'a>, Error>;
    fn open_trie_blob_readonly<'a>(conn: &'a Connection, block_id: u32) -> Result<Blob<'a>, Error>;
    fn read_node_hash_bytes<W: Write>(
        &self,
        w: &mut W,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<(), Error>;
    fn read_node_hash_bytes_by_bhh<W: Write, T: MarfTrieId>(
        &self,
        w: &mut W,
        bhh: &T,
        ptr: &TriePtr,
    ) -> Result<(), Error>;
    fn read_node_type(
        &self,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<(TrieNodeType, TrieHash), Error>;
    fn read_node_type_nohash(
        &self,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<TrieNodeType, Error>;
    fn get_external_trie_offset_length(
        &self,
        block_id: u32,
    ) -> Result<(u64, u64), Error>;
    fn get_external_trie_offset_length_by_bhh<T: MarfTrieId>(
        &self,
        bhh: &T,
    ) -> Result<(u64, u64), Error>;
    fn get_external_blobs_length(&self) -> Result<u64, Error>;
    fn detect_partial_migration(&self) -> Result<bool, Error>;
    fn set_migrated(&self) -> Result<(), Error>;
    fn get_node_hash_bytes(
        &self,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<TrieHash, Error>;
    fn get_node_hash_bytes_by_bhh<T: MarfTrieId>(
        &self,
        bhh: &T,
        ptr: &TriePtr,
    ) -> Result<TrieHash, Error>;
    fn tx_lock_bhh_for_extension<T: MarfTrieId>(
        tx: &Connection,
        bhh: &T,
        unconfirmed: bool,
    ) -> Result<bool, Error>;
    fn lock_bhh_for_extension<T: MarfTrieId>(
        tx: &Transaction,
        bhh: &T,
        unconfirmed: bool,
    ) -> Result<bool, Error>;
    fn count_blocks(&self) -> Result<u32, Error>;
    fn is_unconfirmed_block(&self, block_id: u32) -> Result<bool, Error>;
    fn drop_lock<T: MarfTrieId>(&self, bhh: &T) -> Result<(), Error>;
    fn drop_unconfirmed_trie<T: MarfTrieId>(&self, bhh: &T) -> Result<(), Error>;
    fn clear_lock_data(&self) -> Result<(), Error>;
    fn clear_tables(tx: &Transaction) -> Result<(), Error>;

    #[cfg(test)]
    fn read_all_block_hashes_and_roots<T: MarfTrieId>(
        &self,
    ) -> Result<Vec<(TrieHash, T)>, Error>;
}