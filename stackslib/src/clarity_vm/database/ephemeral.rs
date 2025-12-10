// Copyright (C) 2025 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::mem;

use clarity::util::hash::Sha512Trunc256Sum;
use clarity::vm::database::sqlite::{
    sqlite_get_contract_hash, sqlite_get_metadata, sqlite_get_metadata_manual,
    sqlite_insert_metadata,
};
use clarity::vm::database::{ClarityBackingStore, SpecialCaseHandler, SqliteConnection};
use clarity::vm::errors::{RuntimeError, VmExecutionError, VmInternalError};
use clarity::vm::types::QualifiedContractIdentifier;
use rusqlite;
use rusqlite::Connection;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId, TrieHash};
use stacks_common::types::sqlite::NO_PARAMS;

use crate::chainstate::stacks::index::marf::{MarfConnection, MarfTransaction, MARF};
use crate::chainstate::stacks::index::{Error, MARFValue};
use crate::clarity_vm::clarity::{
    ClarityMarfStore, ClarityMarfStoreTransaction, WritableMarfStore,
};
use crate::clarity_vm::database::marf::ReadOnlyMarfStore;
use crate::clarity_vm::special::handle_contract_call_special_cases;
use crate::core::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};

/// Ephemeral MARF store.
///
/// The implementation "chains" a read-only MARF and a RAM-backed MARF together, for the purposes
/// of giving the Clarity VM a backing store.  Writes will be stored to the ephemeral MARF, and
/// reads will be carried out against either the ephemeral MARF or the read-only MARF, depending on
/// whether or not the opened chain tip refers to a block in the former or the latter.
pub struct EphemeralMarfStore<'a> {
    /// The opened chain tip.  It may refer to either a block in the ephemeral MARF or the
    /// read-only MARF.
    open_tip: EphemeralTip,
    /// The tip upon which the ephemeral MARF is built
    base_tip: StacksBlockId,
    /// The height of the base tip in the disk-backed MARF
    base_tip_height: u32,
    /// Transaction on a RAM-backed MARF which will be discarded once this struct is dropped
    ephemeral_marf: MarfTransaction<'a, StacksBlockId>,
    /// Handle to on-disk MARF
    read_only_marf: ReadOnlyMarfStore<'a>,
}

impl ClarityMarfStore for EphemeralMarfStore<'_> {}

impl ClarityMarfStoreTransaction for EphemeralMarfStore<'_> {
    /// Commit metadata for a given `target` trie.  In this MARF store, this just renames all
    /// metadata rows with `self.chain_tip` as their block identifier to have `target` instead,
    /// but only within the ephemeral MARF.  None of the writes will hit disk, and they will
    /// disappear when this instance is dropped
    ///
    /// Returns Ok(()) on success
    /// Returns Err(VmInternalError(..)) on sqlite failure
    fn commit_metadata_for_trie(&mut self, target: &StacksBlockId) -> Result<(), VmExecutionError> {
        if let Some(tip) = self.ephemeral_marf.get_open_chain_tip() {
            self.teardown_views();
            let res =
                SqliteConnection::commit_metadata_to(self.ephemeral_marf.sqlite_tx(), tip, target);
            self.setup_views();
            res
        } else {
            Ok(())
        }
    }

    /// Drop metadata for the given `target` trie. This just drops the metadata rows with `target`
    /// as their block identifier.  None of the data is disk-backed, so this should always succeed
    /// unless the RAM-only sqlite DB is experiencing problems (which is probably not recoverable).
    ///
    /// Returns Ok(()) on success
    /// Returns Err(VmInternalError(..)) on sqlite failure
    fn drop_metadata_for_trie(&mut self, target: &StacksBlockId) -> Result<(), VmExecutionError> {
        self.teardown_views();
        let res = SqliteConnection::drop_metadata(self.ephemeral_marf.sqlite_tx(), target);
        self.setup_views();
        res
    }

    /// Seal the trie -- compute the root hash.
    /// NOTE: This is a one-time operation for this implementation -- a subsequent call will panic.
    fn seal_trie(&mut self) -> TrieHash {
        self.ephemeral_marf
            .seal()
            .expect("FATAL: failed to .seal() MARF")
    }

    /// Drop the trie being built. This just drops the data from RAM and aborts the underlying
    /// sqlite transaction.  This MARF store instance is consumed.
    fn drop_current_trie(self) {
        self.ephemeral_marf.drop_current()
    }

    /// Drop unconfirmed state being built.  All data lives in RAM in the ephemeral MARF
    /// transaction, so no disk I/O will be performed.
    ///
    /// Returns Ok(()) on success
    /// Returns Err(VmInternalError(..)) on sqlite failure
    fn drop_unconfirmed(mut self) -> Result<(), VmExecutionError> {
        if let Some(tip) = self.ephemeral_marf.get_open_chain_tip().cloned() {
            debug!("Drop unconfirmed MARF trie {}", tip);
            self.drop_metadata_for_trie(&tip)?;
            self.ephemeral_marf.drop_unconfirmed();
        }
        Ok(())
    }

    /// "Commit" the ephemeral MARF as if it were to be written to chainstate,
    /// and consume this instance.  This is effectively a no-op since
    /// nothing will hit disk, and all written data will be dropped.  However, we go through the
    /// motions just in case any errors would be reported.
    ///
    /// Returns Ok(()) on success
    /// Returns Err(VmInternalError(..)) on sqlite failure
    fn commit_to_processed_block(mut self, target: &StacksBlockId) -> Result<(), VmExecutionError> {
        if self.ephemeral_marf.get_open_chain_tip().is_some() {
            self.commit_metadata_for_trie(target)?;
            let _ = self.ephemeral_marf.commit_to(target).map_err(|e| {
                error!("Failed to commit to ephemeral MARF block {target}: {e:?}",);
                VmInternalError::Expect("Failed to commit to MARF block".into())
            })?;
        }
        Ok(())
    }

    /// "Commit" the ephemeral MARF as if it were to be written to the `mined_blocks` table,
    /// and consume this instance.  This is effectively a no-op since
    /// nothing will hit disk, and all written data will be dropped.  However, we go through the
    /// motions just in case any errors would be reported.
    ///
    /// Returns Ok(()) on success
    /// Returns Err(VmInternalError(..)) on sqlite failure
    fn commit_to_mined_block(mut self, target: &StacksBlockId) -> Result<(), VmExecutionError> {
        if let Some(tip) = self.ephemeral_marf.get_open_chain_tip().cloned() {
            // rollback the side_store
            //    the side_store shouldn't commit data for blocks that won't be
            //    included in the processed chainstate (like a block constructed during mining)
            //    _if_ for some reason, we do want to be able to access that mined chain state in the future,
            //    we should probably commit the data to a different table which does not have uniqueness constraints.
            self.drop_metadata_for_trie(&tip)?;
            let _ = self.ephemeral_marf.commit_mined(target).map_err(|e| {
                error!("Failed to commit to mined MARF block {target}: {e:?}",);
                VmInternalError::Expect("Failed to commit to MARF block".into())
            })?;
        }
        Ok(())
    }

    /// "Commit" unconfirmed data to the ephemeral MARF as if it were to be written to unconfiremd
    /// state, and consume this instance.  This is effectively a no-op since nothing will be
    /// written to disk, and all written data will be dropped.  However, we go through the motions
    /// just in case any errors would be reported.
    fn commit_unconfirmed(self) {
        // NOTE: Can omit commit_metadata_to, since the block header hash won't change
        self.ephemeral_marf
            .commit()
            .expect("ERROR: Failed to commit MARF block");
    }

    #[cfg(test)]
    fn test_commit(self) {
        self.do_test_commit()
    }
}

/// Enumeration of the possible types of open tips in an ephemeral MARF.
/// The tip can point to a block in the ephemeral RAM-backed MARF, or the on-disk MARF.
#[derive(Debug, PartialEq, Clone)]
enum EphemeralTip {
    RAM(StacksBlockId),
    Disk(StacksBlockId),
}

impl EphemeralTip {
    fn into_block_id(self) -> StacksBlockId {
        match self {
            Self::RAM(tip) => tip,
            Self::Disk(tip) => tip,
        }
    }
}

impl<'a> EphemeralMarfStore<'a> {
    /// Attach the sqlite DB of the given read-only MARF store to the ephemeral MARF, so that reads
    /// on the ephemeral MARF for non-ephemeral data will automatically fall back to the read-only
    /// MARF's database.
    ///
    /// Returns Ok(()) on success
    /// Returns Err(..) on sqlite error
    pub fn attach_read_only_marf(
        ephemeral_marf: &MARF<StacksBlockId>,
        read_only_marf: &ReadOnlyMarfStore<'a>,
    ) -> Result<(), Error> {
        let conn = ephemeral_marf.sqlite_conn();
        conn.execute(
            "ATTACH DATABASE ?1 AS read_only_marf",
            rusqlite::params![read_only_marf.get_db_path()],
        )?;
        Ok(())
    }

    /// Instantiate.
    /// The `base_tip` must be a valid tip in the given MARF.  New writes in the ephemeral MARF will
    /// descend from the block identified by `tip`.
    ///
    /// Returns Ok(Self) on success
    /// Returns Err(..) if the ephemeral MARF tx was not opened.
    pub fn new(
        mut read_only_marf: ReadOnlyMarfStore<'a>,
        ephemeral_marf_tx: MarfTransaction<'a, StacksBlockId>,
    ) -> Result<Self, Error> {
        let base_tip_height = read_only_marf.get_current_block_height();
        let ephemeral_tip = ephemeral_marf_tx
            .get_open_chain_tip()
            .ok_or(Error::NotFoundError)?
            .clone();
        let ephemeral_marf_store = Self {
            open_tip: EphemeralTip::RAM(ephemeral_tip),
            base_tip: read_only_marf.get_chain_tip().clone(),
            base_tip_height,
            ephemeral_marf: ephemeral_marf_tx,
            read_only_marf,
        };

        // setup views so that the ephemeral MARF's data and metadata tables show all MARF
        // key/value data
        ephemeral_marf_store.setup_views();

        Ok(ephemeral_marf_store)
    }

    /// Test to see if a given tip is in the ephemeral MARF
    fn is_ephemeral_tip(&mut self, tip: &StacksBlockId) -> Result<bool, VmInternalError> {
        match self.ephemeral_marf.get_root_hash_at(tip) {
            Ok(_) => Ok(true),
            Err(Error::NotFoundError) => Ok(false),
            Err(e) => Err(VmInternalError::MarfFailure(e.to_string())),
        }
    }

    /// Create a temporary view for `data_table` and `metadata_table` that merges the ephemeral
    /// MARF's data with the disk-backed MARF.  This must be done before reading anything out of
    /// the side store, and must be undone before writing anything to the ephemeral MARF.
    ///
    /// This is infallible. Sqlite errors will panic. This is fine because all sqlite operations
    /// are on the RAM-backed ephemeral MARF; if RAM exhaustion causes problems, then OOM failure
    /// is not far behind.
    fn setup_views(&self) {
        let conn = self.ephemeral_marf.sqlite_conn();
        conn.execute(
            "ALTER TABLE data_table RENAME TO ephemeral_data_table",
            NO_PARAMS,
        )
        .expect("FATAL: failed to rename data_table to ephemeral_data_table");
        conn.execute(
            "ALTER TABLE metadata_table RENAME TO ephemeral_metadata_table",
            NO_PARAMS,
        )
        .expect("FATAL: failed to rename metadata_table to ephemeral_metadata_table");
        conn.execute("CREATE TEMP VIEW data_table(key, value) AS SELECT * FROM main.ephemeral_data_table UNION SELECT * FROM read_only_marf.data_table", NO_PARAMS)
            .expect("FATAL: failed to setup temp view data_table on ephemeral MARF DB");
        conn.execute("CREATE TEMP VIEW metadata_table(key, blockhash, value) AS SELECT * FROM main.ephemeral_metadata_table UNION SELECT * FROM read_only_marf.metadata_table", NO_PARAMS)
            .expect("FATAL: failed to setup temp view metadata_table on ephemeral MARF DB");
    }

    /// Delete temporary views `data_table` and `metadata_table`, and restore
    /// `data_table` and `metadata_table` table names.  Do this prior to writing.
    ///
    /// This is infallible. Sqlite errors will panic. This is fine because all sqlite operations
    /// are on the RAM-backed ephemeral MARF; if RAM exhaustion causes problems, then OOM failure
    /// is not far behind.
    fn teardown_views(&self) {
        let conn = self.ephemeral_marf.sqlite_conn();
        conn.execute("DROP VIEW data_table", NO_PARAMS)
            .expect("FATAL: failed to drop data_table view");
        conn.execute("DROP VIEW metadata_table", NO_PARAMS)
            .expect("FATAL: failed to drop metadata_table view");
        conn.execute(
            "ALTER TABLE ephemeral_data_table RENAME TO data_table",
            NO_PARAMS,
        )
        .expect("FATAL: failed to restore data_table");
        conn.execute(
            "ALTER TABLE ephemeral_metadata_table RENAME TO metadata_table",
            NO_PARAMS,
        )
        .expect("FATAL: failed to restore metadata_table");
    }

    /// Test helper to commit ephemeral MARF block data using the open chain tip as the final
    /// identifier
    #[cfg(test)]
    fn do_test_commit(self) {
        if let Some(tip) = self.ephemeral_marf.get_open_chain_tip() {
            let bhh = tip.clone();
            self.commit_to_processed_block(&bhh).unwrap();
        }
    }

    /// Helper function to cast a Result<Option<T>, Error> into Result<Option<T>, VmExecutionError>
    fn handle_marf_result<T>(res: Result<Option<T>, Error>) -> Result<Option<T>, VmExecutionError> {
        match res {
            Ok(result_opt) => Ok(result_opt),
            Err(Error::NotFoundError) => {
                trace!("Ephemeral MarfedKV get not found",);
                Ok(None)
            }
            Err(e) => Err(VmInternalError::Expect(format!(
                "ERROR: Unexpected MARF failure: {e:?}"
            ))
            .into()),
        }
    }

    /// Helper function to implement a generic getter over the MARF for data that could be stored
    /// in the ephemeral MARF, but if not, could be stored in the read-only MARF.  `tx_getter`
    /// reads from the ephemeral MARF, and `marf_getter` reads from the read-only MARF.
    ///
    /// Returns Ok(Some(V)) if the key was mapped in eiher MARF
    /// Returns Ok(None) if the key was not mapped in either MARF
    /// Returns Err(VmInternalError(..)) on failure.
    fn get_with_fn<Key, V, TxGetter, MarfGetter>(
        &mut self,
        key: Key,
        tx_getter: TxGetter,
        marf_getter: MarfGetter,
    ) -> Result<Option<V>, VmExecutionError>
    where
        TxGetter: FnOnce(
            &mut MarfTransaction<StacksBlockId>,
            &StacksBlockId,
            Key,
        ) -> Result<Option<V>, VmExecutionError>,
        MarfGetter: FnOnce(&mut ReadOnlyMarfStore, Key) -> Result<Option<V>, VmExecutionError>,
        Key: std::fmt::Debug + Copy,
    {
        let value_opt = if let EphemeralTip::RAM(tip) = &self.open_tip {
            // try the ephemeral MARF first
            tx_getter(&mut self.ephemeral_marf, tip, key)?
        } else {
            None
        };

        if let Some(value) = value_opt {
            // found in ephemeral MARF
            return Ok(Some(value));
        }

        // Due to the way we implemented `.set_block_hash()`, the read-only
        // MARF's tip will be set to `base_tip` if the open tip was ephemeral.
        // Otherwise, it'll be set to the tip that was last opeend.  Either way,
        // the correct tip has been set in `self.read_only_marf` that `.get_data_from_path()`
        // will work as expected.
        marf_getter(&mut self.read_only_marf, key)
    }
}

impl ClarityBackingStore for EphemeralMarfStore<'_> {
    /// Seek to the given chain tip.  This given tip will become the new tip from which
    /// reads and writes will be indexed.
    ///
    /// Returns Ok(old-chain-tip) on success.
    /// Returns Err(..) if the given chain tip does not exist or is on a different fork (e.g. is
    /// not an ancestor of this struct's tip).
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId, VmExecutionError> {
        if self.is_ephemeral_tip(&bhh)? {
            // open the disk-backed MARF to the base tip, so we can carry out reads on disk-backed
            // data in the event that a read on a key is `None` for the ephemeral MARF.
            self.read_only_marf.set_block_hash(self.base_tip.clone())?;

            // update ephemeral MARF open tip
            let old_tip =
                mem::replace(&mut self.open_tip, EphemeralTip::RAM(bhh.clone())).into_block_id();
            self.open_tip = EphemeralTip::RAM(bhh);
            return Ok(old_tip);
        }

        // this bhh is not ephemeral, so it might be disk-backed.
        self.read_only_marf
            .check_ancestor_block_hash(&bhh)
            .map_err(|e| match e {
                Error::NotFoundError => {
                    test_debug!("No such block {:?} (NotFoundError)", &bhh);
                    RuntimeError::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0))
                }
                Error::NonMatchingForks(_bh1, _bh2) => {
                    test_debug!(
                        "No such block {:?} (NonMatchingForks({}, {}))",
                        &bhh,
                        BlockHeaderHash(_bh1),
                        BlockHeaderHash(_bh2)
                    );
                    RuntimeError::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0))
                }
                _ => panic!("ERROR: Unexpected MARF failure: {}", e),
            })?;

        let old_tip = mem::replace(&mut self.open_tip, EphemeralTip::Disk(bhh));
        Ok(old_tip.into_block_id())
    }

    /// Get the special-case contract-call handlers (e.g. for PoX and .costs-voting)
    fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        Some(&handle_contract_call_special_cases)
    }

    /// Load a value associated with the give key from the MARF and its side-store.
    /// The key can be any string; it will be translated into a MARF key.
    /// The caller must decode the resulting value.
    ///
    /// Returns Ok(Some(value)) if the key was mapped to the given value at the opened chain tip.
    /// Returns Ok(None) if the key was not mapped to the given value at the opened chain tip.
    /// Returns Err(..) on all other failures.
    fn get_data(&mut self, key: &str) -> Result<Option<String>, VmExecutionError> {
        trace!(
            "Ephemeral MarfedKV get_data: {key:?} tip={:?}",
            &self.open_tip
        );
        self.get_with_fn(
            key,
            |ephemeral_marf, tip, key| {
                let Some(marf_value) = Self::handle_marf_result(ephemeral_marf.get(tip, key))? else {
                    return Ok(None)
                };
                let side_key = marf_value.to_hex();
                let data = SqliteConnection::get(ephemeral_marf.sqlite_conn(), &side_key)?
                    .ok_or_else(|| {
                        VmInternalError::Expect(format!(
                            "ERROR: MARF contained value_hash not found in side storage: {side_key}",
                        ))
                    })?;
                Ok(Some(data))
            },
            |read_only_marf, key| read_only_marf.get_data(key)
        )
    }

    /// Get data from the MARF given a trie hash.
    /// Returns Ok(Some(value)) if the key was mapped to the given value at the opeend chain tip.
    /// Returns Ok(None) if the key was not mapped to the given value at the opened chain tip.
    /// Returns Err(..) on all other failures
    fn get_data_from_path(&mut self, hash: &TrieHash) -> Result<Option<String>, VmExecutionError> {
        trace!(
            "Ephemeral MarfedKV get_from_hash: {:?} tip={:?}",
            hash,
            &self.open_tip
        );
        self.get_with_fn(
            hash,
            |ephemeral_marf, tip, hash| {
                let Some(marf_value) =
                    Self::handle_marf_result(ephemeral_marf.get_from_hash(tip, hash))?
                else {
                    return Ok(None);
                };
                let side_key = marf_value.to_hex();
                trace!(
                    "Ephemeral MarfedKV get side-key for {:?}: {:?}",
                    hash,
                    &side_key
                );
                let data = SqliteConnection::get(ephemeral_marf.sqlite_conn(), &side_key)?
                    .ok_or_else(|| {
                        VmInternalError::Expect(format!(
                        "ERROR: Ephemeral MARF contained value_hash not found in side storage: {}",
                        side_key
                    ))
                    })?;
                Ok(Some(data))
            },
            |read_only_marf, path| read_only_marf.get_data_from_path(path),
        )
    }

    /// Get data from the MARF as well as a Merkle proof-of-inclusion.
    /// Returns Ok(Some(value)) if the key was mapped to the given value at the opened chain tip.
    /// Returns Ok(None) if the key was not mapped to the given value at the opened chain tip.
    /// Returns Err(..) on all other failures
    fn get_data_with_proof(
        &mut self,
        key: &str,
    ) -> Result<Option<(String, Vec<u8>)>, VmExecutionError> {
        trace!(
            "Ephemeral MarfedKV get_data_with_proof: '{}' tip={:?}",
            key,
            &self.open_tip
        );
        self.get_with_fn(
            key,
            |ephemeral_marf, tip, key| {
                let Some((marf_value, proof)) =
                    Self::handle_marf_result(ephemeral_marf.get_with_proof(tip, key))?
                else {
                    return Ok(None);
                };
                let side_key = marf_value.to_hex();
                let data = SqliteConnection::get(ephemeral_marf.sqlite_conn(), &side_key)?
                    .ok_or_else(|| {
                        VmInternalError::Expect(format!(
                            "ERROR: MARF contained value_hash not found in side storage: {}",
                            side_key
                        ))
                    })?;
                Ok(Some((data, proof.serialize_to_vec())))
            },
            |read_only_marf, key| read_only_marf.get_data_with_proof(key),
        )
    }

    /// Get data and a Merkle proof-of-inclusion for it from the MARF given a trie hash.
    /// Returns Ok(Some(value)) if the key was mapped to the given value at the opeend chain tip.
    /// Returns Ok(None) if the key was not mapped to the given value at the opened chain tip.
    /// Returns Err(..) on all other failures
    fn get_data_with_proof_from_path(
        &mut self,
        hash: &TrieHash,
    ) -> Result<Option<(String, Vec<u8>)>, VmExecutionError> {
        trace!(
            "Ephemeral MarfedKV get_data_with_proof_from_hash: {:?} tip={:?}",
            hash,
            &self.open_tip
        );
        self.get_with_fn(
            hash,
            |ephemeral_marf, tip, path| {
                let Some((marf_value, proof)) =
                    Self::handle_marf_result(ephemeral_marf.get_with_proof_from_hash(tip, path))?
                else {
                    return Ok(None);
                };
                let side_key = marf_value.to_hex();
                let data = SqliteConnection::get(ephemeral_marf.sqlite_conn(), &side_key)?
                    .ok_or_else(|| {
                        VmInternalError::Expect(format!(
                            "ERROR: MARF contained value_hash not found in side storage: {}",
                            side_key
                        ))
                    })?;
                Ok(Some((data, proof.serialize_to_vec())))
            },
            |read_only_marf, path| read_only_marf.get_data_with_proof_from_path(path),
        )
    }

    /// Get a sqlite connection to the MARF side-store.
    /// Note that due to `setup_views()` and `teardown_views()`, the MARF DB will show key/value
    /// pairs for both the ephemeral MARF and the disk-backed readonly MARF.
    fn get_side_store(&mut self) -> &Connection {
        self.ephemeral_marf.sqlite_conn()
    }

    /// Get an ancestor block's ID at a given absolute height, off of the open tip.
    /// Returns Some(block-id) if there is a block at the given height.
    /// Returns None otherwise.
    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId> {
        let block_id_opt = if let EphemeralTip::RAM(tip) = &self.open_tip {
            // careful -- the ephemeral MARF's height 0 corresponds to the base tip height
            if height > self.base_tip_height {
                self.ephemeral_marf
                    .get_block_at_height(height - self.base_tip_height, tip)
                    .unwrap_or_else(|_| {
                        panic!(
                            "Unexpected MARF failure: failed to get block at height {} off of {}.",
                            height, tip
                        )
                    })
            } else {
                None
            }
        } else {
            None
        };

        if let Some(block_id) = block_id_opt {
            return Some(block_id);
        }

        // Due to the way we implemented `.set_block_hash()`, the read-only
        // MARF's tip will be set to `base_tip` if the open tip was ephemeral.
        // Otherwise, it'll be set to the tip that was last opeend.  Either way,
        // the correct tip has been set in `self.read_only_marf` that `.get_block_at_height()`
        // will work as expected.
        self.read_only_marf.get_block_at_height(height)
    }

    /// Get the block ID of the inner MARF's open chain tip.
    /// If the tip points to the ephemeral MARF, then use that MARF.
    /// Otherwise, use the disk-backed one.
    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        if let EphemeralTip::RAM(..) = &self.open_tip {
            return self
                .ephemeral_marf
                .get_open_chain_tip()
                .expect("Attempted to get the open chain tip from an unopened context.")
                .clone();
        }

        self.read_only_marf.get_open_chain_tip()
    }

    /// Get the height of the inner MARF's open chain tip.
    /// If the tip points to the ephemeral MARF, then use that MARF.
    /// Otherwise, use the disk-backed one.
    fn get_open_chain_tip_height(&mut self) -> u32 {
        if let EphemeralTip::RAM(..) = &self.open_tip {
            return self
                .ephemeral_marf
                .get_open_chain_tip_height()
                .expect("Attempted to get the open chain tip from an unopened context.")
                + self.base_tip_height
                + 1;
        }

        self.read_only_marf.get_open_chain_tip_height()
    }

    /// Get the block height of the current open chain tip.
    /// If the tip points to the ephemeral MARF, then use that MARF.
    /// Otherwise, use the disk-backed one.
    fn get_current_block_height(&mut self) -> u32 {
        let height_opt = if let EphemeralTip::RAM(tip) = &self.open_tip {
            match self.ephemeral_marf.get_block_height_of(tip, tip) {
                Ok(Some(x)) => Some(x + self.base_tip_height + 1),
                Ok(None) => {
                    let first_tip = StacksBlockId::new(
                        &FIRST_BURNCHAIN_CONSENSUS_HASH,
                        &FIRST_STACKS_BLOCK_HASH,
                    );
                    if tip == &first_tip || tip == &StacksBlockId([0u8; 32]) {
                        // the current block height should always work, except if it's the first block
                        // height (in which case, the current chain tip should match the first-ever
                        // index block hash).
                        // In this case, this is the height of the base tip in the disk-backed MARF
                        return self.base_tip_height;
                    }

                    // should never happen
                    let msg = format!(
                        "Failed to obtain current block height of {:?} (got None)",
                        &self.open_tip
                    );
                    panic!("{}", &msg);
                }
                Err(e) => {
                    let msg = format!(
                        "Unexpected MARF failure: Failed to get current block height of {:?}: {:?}",
                        &self.open_tip, &e
                    );
                    panic!("{}", &msg);
                }
            }
        } else {
            None
        };

        if let Some(height) = height_opt {
            return height;
        }

        self.read_only_marf.get_current_block_height()
    }

    /// Write all (key, value) pairs to the ephemeral MARF.
    /// Returns Ok(()) on success
    /// Returns Err(..) on inner MARF errors.
    fn put_all_data(&mut self, items: Vec<(String, String)>) -> Result<(), VmExecutionError> {
        let mut keys = Vec::with_capacity(items.len());
        let mut values = Vec::with_capacity(items.len());

        // we're only writing, so get rid of the temporary views and restore the data and metadata
        // tables in the ephemeral MARF so this works.
        self.teardown_views();
        for (key, value) in items.into_iter() {
            let marf_value = MARFValue::from_value(&value);
            SqliteConnection::put(
                self.ephemeral_marf.sqlite_tx(),
                &marf_value.to_hex(),
                &value,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "FATAL: failed to insert side-store data {:?}: {:?}",
                    &value, &e
                )
            });

            keys.push(key);
            values.push(marf_value);
        }
        self.ephemeral_marf
            .insert_batch(&keys, values)
            .unwrap_or_else(|e| {
                panic!(
                    "FATAL: failed to insert ephemeral MARF key/value pairs: {:?}",
                    e
                )
            });

        // restore unified data and metadata views
        self.setup_views();
        Ok(())
    }

    /// Get the hash of a contract and the block it was mined in,
    /// given its fully-qualified identifier.
    /// Returns Ok((block-id, sha512/256)) on success.
    /// Returns Err(..) on DB error (including not-found)
    fn get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> Result<(StacksBlockId, Sha512Trunc256Sum), VmExecutionError> {
        sqlite_get_contract_hash(self, contract)
    }

    /// Write contract metadata into the metadata table.
    /// This method needs to tear down and restore the materialized view of the ephemeral marf's
    /// metadata table in order to work correctly, since the ephemeral MARF will store the data.
    ///
    /// Returns Ok(()) on success
    /// Returns Err(..) on failure.
    fn insert_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
        value: &str,
    ) -> Result<(), VmExecutionError> {
        self.teardown_views();
        let res = sqlite_insert_metadata(self, contract, key, value);
        self.setup_views();
        res
    }

    /// Load up metadata from the metadata table (materialized view) in the ephemeral MARF
    /// for a given contract and metadata key.
    /// Returns Ok(Some(value)) if the metadata exists
    /// Returns Ok(None) if the metadata does not exist
    /// Returns Err(..) on failure
    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>, VmExecutionError> {
        sqlite_get_metadata(self, contract, key)
    }

    /// Load up metadata at a specific block height from the metadata table (materialized view) in
    /// the ephemeral MARF for a given contract and metadata key.
    /// Returns Ok(Some(value)) if the metadata exists
    /// Returns Ok(None) if the metadata does not exist
    /// Returns Err(..) on failure
    fn get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>, VmExecutionError> {
        sqlite_get_metadata_manual(self, at_height, contract, key)
    }
}

impl WritableMarfStore for EphemeralMarfStore<'_> {}
