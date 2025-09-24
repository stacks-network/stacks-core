// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2025 Stacks Open Internet Foundation
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

use std::ops::DerefMut;
use std::path::PathBuf;
use std::str::FromStr;

use clarity::util::hash::Sha512Trunc256Sum;
use clarity::vm::database::sqlite::{
    sqlite_get_contract_hash, sqlite_get_metadata, sqlite_get_metadata_manual,
    sqlite_insert_metadata,
};
use clarity::vm::database::{ClarityBackingStore, SpecialCaseHandler, SqliteConnection};
use clarity::vm::errors::{IncomparableError, InterpreterResult, RuntimeError, VmInternalError};
use clarity::vm::types::QualifiedContractIdentifier;
use rusqlite;
use rusqlite::Connection;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId, TrieHash};

use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MarfTransaction, MARF};
use crate::chainstate::stacks::index::storage::{TrieFileStorage, TrieHashCalculationMode};
use crate::chainstate::stacks::index::{ClarityMarfTrieId, Error, MARFValue};
use crate::clarity_vm::clarity::{
    ClarityMarfStore, ClarityMarfStoreTransaction, WritableMarfStore,
};
use crate::clarity_vm::database::ephemeral::EphemeralMarfStore;
use crate::clarity_vm::special::handle_contract_call_special_cases;
use crate::core::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};
use crate::util_lib::db::{Error as DatabaseError, IndexDBConn};

/// The MarfedKV struct is used to wrap a MARF data structure and side-storage
///   for use as a K/V store for ClarityDB or the AnalysisDB.
/// The Clarity VM and type checker do not "know" to begin/commit the block they are currently processing:
///   each instantiation of the VM simply executes one transaction. So the block handling
///   loop will need to invoke these two methods (begin + commit) outside of the context of the VM.
///   NOTE: Clarity will panic if you try to execute it from a non-initialized MarfedKV context.
///   (See: vm::tests::with_marfed_environment())
pub struct MarfedKV {
    chain_tip: StacksBlockId,
    marf: MARF<StacksBlockId>,
    /// RAM-backed MARF that will be mutably referenced in an EphemeralMarfStore instance.
    /// Due to limits in Rust's type system, it is necessary for this to be instantiated in
    /// MarfedKV, since it must outlive EphemeralMarfStore, and MarfedKV is the "parent" of
    /// all data referenced by ClarityMarfStore implementations (including the read-only and
    /// persistent MARF stores).
    ephemeral_marf: Option<MARF<StacksBlockId>>,
}

impl MarfedKV {
    fn setup_db(
        path_str: &str,
        unconfirmed: bool,
        marf_opts: Option<MARFOpenOpts>,
    ) -> InterpreterResult<MARF<StacksBlockId>> {
        let mut path = PathBuf::from(path_str);

        std::fs::create_dir_all(&path).map_err(|_| VmInternalError::FailedToCreateDataDirectory)?;

        path.push("marf.sqlite");
        let marf_path = path
            .to_str()
            .ok_or_else(|| VmInternalError::BadFileName)?
            .to_string();

        let mut marf_opts = marf_opts.unwrap_or(MARFOpenOpts::default());
        marf_opts.external_blobs = true;

        let mut marf: MARF<StacksBlockId> = if unconfirmed {
            MARF::from_path_unconfirmed(&marf_path, marf_opts)
                .map_err(|err| VmInternalError::MarfFailure(err.to_string()))?
        } else {
            MARF::from_path(&marf_path, marf_opts)
                .map_err(|err| VmInternalError::MarfFailure(err.to_string()))?
        };

        if SqliteConnection::check_schema(marf.sqlite_conn()).is_ok() {
            // no need to initialize
            return Ok(marf);
        }

        let tx = marf
            .storage_tx()
            .map_err(|err| VmInternalError::DBError(err.to_string()))?;

        SqliteConnection::initialize_conn(&tx)?;
        tx.commit()
            .map_err(|err| VmInternalError::SqliteError(IncomparableError { err }))?;

        Ok(marf)
    }

    pub fn open(
        path_str: &str,
        miner_tip: Option<&StacksBlockId>,
        marf_opts: Option<MARFOpenOpts>,
    ) -> InterpreterResult<MarfedKV> {
        let marf = MarfedKV::setup_db(path_str, false, marf_opts)?;
        let chain_tip = match miner_tip {
            Some(miner_tip) => miner_tip.clone(),
            None => StacksBlockId::sentinel(),
        };

        Ok(MarfedKV {
            marf,
            chain_tip,
            ephemeral_marf: None,
        })
    }

    pub fn open_unconfirmed(
        path_str: &str,
        miner_tip: Option<&StacksBlockId>,
        marf_opts: Option<MARFOpenOpts>,
    ) -> InterpreterResult<MarfedKV> {
        let marf = MarfedKV::setup_db(path_str, true, marf_opts)?;
        let chain_tip = match miner_tip {
            Some(miner_tip) => miner_tip.clone(),
            None => StacksBlockId::sentinel(),
        };

        Ok(MarfedKV {
            marf,
            chain_tip,
            ephemeral_marf: None,
        })
    }

    // used by benchmarks
    pub fn temporary() -> MarfedKV {
        use rand::Rng;
        use stacks_common::util::hash::to_hex;

        let mut path = PathBuf::from_str("/tmp/stacks-node-tests/unit-tests-marf").unwrap();
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
        path.push(to_hex(&random_bytes));

        debug!(
            "Temporary MARF path at {}",
            &path
                .to_str()
                .expect("FATAL: non-UTF-8 character in filename")
        );

        let marf = MarfedKV::setup_db(
            path.to_str()
                .expect("Inexplicably non-UTF-8 character in filename"),
            false,
            None,
        )
        .unwrap();

        let chain_tip = StacksBlockId::sentinel();

        MarfedKV {
            marf,
            chain_tip,
            ephemeral_marf: None,
        }
    }

    pub fn begin_read_only<'a>(
        &'a mut self,
        at_block: Option<&StacksBlockId>,
    ) -> ReadOnlyMarfStore<'a> {
        let chain_tip = if let Some(at_block) = at_block {
            self.marf.open_block(at_block).unwrap_or_else(|e| {
                error!(
                    "Failed to open read only connection at {}: {:?}",
                    at_block, &e
                );
                panic!()
            });
            at_block.clone()
        } else {
            self.chain_tip.clone()
        };
        ReadOnlyMarfStore {
            chain_tip,
            marf: &mut self.marf,
        }
    }

    pub fn begin_read_only_checked<'a>(
        &'a mut self,
        at_block: Option<&StacksBlockId>,
    ) -> InterpreterResult<ReadOnlyMarfStore<'a>> {
        let chain_tip = if let Some(at_block) = at_block {
            self.marf.open_block(at_block).map_err(|e| {
                debug!(
                    "Failed to open read only connection at {}: {:?}",
                    at_block, &e
                );
                VmInternalError::MarfFailure(Error::NotFoundError.to_string())
            })?;
            at_block.clone()
        } else {
            self.chain_tip.clone()
        };
        Ok(ReadOnlyMarfStore {
            chain_tip,
            marf: &mut self.marf,
        })
    }

    /// begin, commit, rollback a save point identified by key
    ///    this is used to clean up any data from aborted blocks
    ///     (NOT aborted transactions that is handled by the clarity vm directly).
    /// The block header hash is used for identifying savepoints.
    ///     this _cannot_ be used to rollback to arbitrary prior block hash, because that
    ///     blockhash would already have committed and no longer exist in the save point stack.
    /// this is a "lower-level" rollback than the roll backs performed in
    ///   ClarityDatabase or AnalysisDatabase -- this is done at the backing store level.
    pub fn begin<'a>(
        &'a mut self,
        current: &StacksBlockId,
        next: &StacksBlockId,
    ) -> PersistentWritableMarfStore<'a> {
        let mut tx = self.marf.begin_tx().unwrap_or_else(|_| {
            panic!(
                "ERROR: Failed to begin new MARF block {} - {})",
                current, next
            )
        });
        tx.begin(current, next).unwrap_or_else(|_| {
            panic!(
                "ERROR: Failed to begin new MARF block {} - {})",
                current, next
            )
        });

        let chain_tip = tx
            .get_open_chain_tip()
            .expect("ERROR: Failed to get open MARF")
            .clone();

        PersistentWritableMarfStore {
            chain_tip,
            marf: tx,
        }
    }

    pub fn begin_unconfirmed<'a>(
        &'a mut self,
        current: &StacksBlockId,
    ) -> PersistentWritableMarfStore<'a> {
        let mut tx = self.marf.begin_tx().unwrap_or_else(|_| {
            panic!(
                "ERROR: Failed to begin new unconfirmed MARF block for {})",
                current
            )
        });
        tx.begin_unconfirmed(current).unwrap_or_else(|_| {
            panic!(
                "ERROR: Failed to begin new unconfirmed MARF block for {})",
                current
            )
        });

        let chain_tip = tx
            .get_open_chain_tip()
            .expect("ERROR: Failed to get open MARF")
            .clone();

        PersistentWritableMarfStore {
            chain_tip,
            marf: tx,
        }
    }

    /// Begin an ephemeral MARF block.
    /// The data will never hit disk.
    pub fn begin_ephemeral<'a>(
        &'a mut self,
        base_tip: &StacksBlockId,
        ephemeral_next: &StacksBlockId,
    ) -> InterpreterResult<EphemeralMarfStore<'a>> {
        // sanity check -- `base_tip` must be mapped
        self.marf.open_block(&base_tip).map_err(|e| {
            debug!(
                "Failed to open read only connection at {}: {:?}",
                &base_tip, &e
            );
            VmInternalError::MarfFailure(Error::NotFoundError.to_string())
        })?;

        // set up ephemeral MARF
        let ephemeral_marf_storage = TrieFileStorage::open(
            ":memory:",
            MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", false),
        )
        .map_err(|e| {
            VmInternalError::Expect(format!("Failed to instantiate ephemeral MARF: {:?}", &e))
        })?;

        let mut ephemeral_marf = MARF::from_storage(ephemeral_marf_storage);
        let tx = ephemeral_marf
            .storage_tx()
            .map_err(|err| VmInternalError::DBError(err.to_string()))?;

        SqliteConnection::initialize_conn(&tx)?;
        tx.commit()
            .map_err(|err| VmInternalError::SqliteError(IncomparableError { err }))?;

        self.ephemeral_marf = Some(ephemeral_marf);

        let read_only_marf = ReadOnlyMarfStore {
            chain_tip: base_tip.clone(),
            marf: &mut self.marf,
        };

        let Some(ephemeral_marf) = self.ephemeral_marf.as_mut() else {
            // unreachable since self.ephemeral_marf is already assigned
            unreachable!();
        };

        // attach the disk-backed MARF to the ephemeral MARF
        EphemeralMarfStore::attach_read_only_marf(&ephemeral_marf, &read_only_marf).map_err(
            |e| {
                VmInternalError::Expect(format!(
                    "Failed to attach read-only MARF to ephemeral MARF: {:?}",
                    &e
                ))
            },
        )?;

        let mut tx = ephemeral_marf.begin_tx().map_err(|e| {
            VmInternalError::Expect(format!("Failed to open ephemeral MARF tx: {:?}", &e))
        })?;

        tx.begin(&StacksBlockId::sentinel(), ephemeral_next)
            .map_err(|e| {
                VmInternalError::Expect(format!(
                    "Failed to begin first ephemeral MARF block: {:?}",
                    &e
                ))
            })?;

        let ephemeral_marf_store = EphemeralMarfStore::new(read_only_marf, tx).map_err(|e| {
            VmInternalError::Expect(format!(
                "Failed to instantiate ephemeral MARF store: {:?}",
                &e
            ))
        })?;

        Ok(ephemeral_marf_store)
    }

    pub fn get_chain_tip(&self) -> &StacksBlockId {
        &self.chain_tip
    }

    pub fn get_marf(&mut self) -> &mut MARF<StacksBlockId> {
        &mut self.marf
    }

    #[cfg(test)]
    pub fn sql_conn(&self) -> &Connection {
        self.marf.sqlite_conn()
    }

    pub fn index_conn<C>(&self, context: C) -> IndexDBConn<'_, C, StacksBlockId> {
        IndexDBConn::new(&self.marf, context)
    }
}

/// A wrapper around a MARF transaction which allows read/write access to the MARF's keys off of a
/// given chain tip.
pub struct PersistentWritableMarfStore<'a> {
    /// The chain tip from which reads and writes will be indexed.
    chain_tip: StacksBlockId,
    /// The transaction to the MARF instance
    marf: MarfTransaction<'a, StacksBlockId>,
}

/// A wrapper around a MARF handle which allows only read access to the MARF's keys off of a given
/// chain tip.
pub struct ReadOnlyMarfStore<'a> {
    /// The chain tip from which reads will be indexed.
    chain_tip: StacksBlockId,
    /// Handle to the MARF being read
    marf: &'a mut MARF<StacksBlockId>,
}

impl ClarityMarfStore for ReadOnlyMarfStore<'_> {}
impl ClarityMarfStore for PersistentWritableMarfStore<'_> {}

impl ClarityMarfStoreTransaction for PersistentWritableMarfStore<'_> {
    /// Commit metadata for a given `target` trie.  In this MARF store, this just renames all
    /// metadata rows with `self.chain_tip` as their block identifier to have `target` instead.
    ///
    /// Returns Ok(()) on success
    /// Returns Err(VmInternalError(..)) on sqlite failure
    fn commit_metadata_for_trie(&mut self, target: &StacksBlockId) -> InterpreterResult<()> {
        SqliteConnection::commit_metadata_to(self.marf.sqlite_tx(), &self.chain_tip, target)
    }

    /// Drop metadata for the given `target` trie. This just drops the metadata rows with `target`
    /// as their block identifier.
    ///
    /// Returns Ok(()) on success
    /// Returns Err(VmInternalError(..)) on sqlite failure
    fn drop_metadata_for_trie(&mut self, target: &StacksBlockId) -> InterpreterResult<()> {
        SqliteConnection::drop_metadata(self.marf.sqlite_tx(), target)
    }

    /// Seal the trie -- compute the root hash.
    /// NOTE: This is a one-time operation for this implementation -- a subsequent call will panic.
    fn seal_trie(&mut self) -> TrieHash {
        self.marf
            .seal()
            .expect("FATAL: failed to .seal() MARF transaction")
    }

    /// Drop the trie being built. This just drops the data from RAM and aborts the underlying
    /// sqlite transaction.  This instance is consumed.
    fn drop_current_trie(self) {
        self.marf.drop_current();
    }

    /// Drop unconfirmed state being built. This will not only drop unconfirmed state in RAM, but
    /// also any unconfirmed trie data from the sqlite DB as well as its associated metadata.
    ///
    /// Returns Ok(()) on success
    /// Returns Err(VmInternalError(..)) on sqlite failure
    fn drop_unconfirmed(mut self) -> InterpreterResult<()> {
        let chain_tip = self.chain_tip.clone();
        debug!("Drop unconfirmed MARF trie {}", &chain_tip);
        self.drop_metadata_for_trie(&chain_tip)?;
        self.marf.drop_unconfirmed();
        Ok(())
    }

    /// Commit the outstanding trie and metadata to the set of processed-block tries, and call it
    /// `target` in the DB.  Future tries can be built atop it.  This commits the transaction and
    /// drops this MARF store.
    ///
    /// Returns Ok(()) on success
    /// Returns Err(VmInternalError(..)) on sqlite failure
    fn commit_to_processed_block(mut self, target: &StacksBlockId) -> InterpreterResult<()> {
        debug!("commit_to({})", target);
        self.commit_metadata_for_trie(target)?;
        let _ = self.marf.commit_to(target).map_err(|e| {
            error!("Failed to commit to MARF block {target}: {e:?}");
            VmInternalError::Expect("Failed to commit to MARF block".into())
        })?;
        Ok(())
    }

    /// Commit the outstanding trie to the `mined_blocks` table in the underlying MARF.
    /// The metadata will be dropped, since this won't be added to the chainstate.  This commits
    /// the transaction and drops this MARF store.
    ///
    /// Returns Ok(()) on success
    /// Returns Err(VmInternalError(..)) on sqlite failure
    fn commit_to_mined_block(mut self, target: &StacksBlockId) -> InterpreterResult<()> {
        debug!("commit_mined_block: ({}->{})", &self.chain_tip, target);
        // rollback the side_store
        //    the side_store shouldn't commit data for blocks that won't be
        //    included in the processed chainstate (like a block constructed during mining)
        //    _if_ for some reason, we do want to be able to access that mined chain state in the future,
        //    we should probably commit the data to a different table which does not have uniqueness constraints.
        let chain_tip = self.chain_tip.clone();
        self.drop_metadata_for_trie(&chain_tip)?;
        let _ = self.marf.commit_mined(target).map_err(|e| {
            error!("Failed to commit to mined MARF block {target}: {e:?}",);
            VmInternalError::Expect("Failed to commit to MARF block".into())
        })?;
        Ok(())
    }

    /// Commit the outstanding trie to unconfirmed state, so subsequent read I/O can be performed
    /// on it (such as servicing RPC requests).  This commits this transaction and drops this MARF
    /// store
    fn commit_unconfirmed(self) {
        debug!("commit_unconfirmed()");
        // NOTE: Can omit commit_metadata_to, since the block header hash won't change
        self.marf
            .commit()
            .expect("ERROR: Failed to commit MARF block");
    }

    #[cfg(test)]
    fn test_commit(self) {
        self.do_test_commit()
    }
}

impl ReadOnlyMarfStore<'_> {
    /// Determine if there is a trie in the underlying MARF with the given ID `bhh`.
    ///
    /// Return Ok(true) if so
    /// Return Ok(false) if not
    /// Return Err(..) if we encounter a sqlite error
    pub fn trie_exists_for_block(&mut self, bhh: &StacksBlockId) -> Result<bool, DatabaseError> {
        self.marf
            .with_conn(|conn| conn.has_block(bhh).map_err(DatabaseError::IndexError))
    }

    /// Get the DB path on disk.
    /// If the DB is in RAM, this will be ":memory:"
    pub fn get_db_path(&self) -> &str {
        self.marf.get_db_path()
    }

    /// Get a reference to the chain tip
    pub fn get_chain_tip(&self) -> &StacksBlockId {
        &self.chain_tip
    }

    /// Helper wrapper around MARF::check_ancestor_block_hash(),
    pub fn check_ancestor_block_hash(&mut self, bhh: &StacksBlockId) -> Result<(), Error> {
        self.marf.check_ancestor_block_hash(bhh)
    }
}

impl ClarityBackingStore for ReadOnlyMarfStore<'_> {
    fn get_side_store(&mut self) -> &Connection {
        self.marf.sqlite_conn()
    }

    fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        Some(&handle_contract_call_special_cases)
    }

    /// Sets the chain tip at which queries will happen.  Used for `(at-block ..)`
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> InterpreterResult<StacksBlockId> {
        self.marf
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

        let result = Ok(self.chain_tip.clone());
        self.chain_tip = bhh;

        result
    }

    fn get_current_block_height(&mut self) -> u32 {
        match self
            .marf
            .get_block_height_of(&self.chain_tip, &self.chain_tip)
        {
            Ok(Some(x)) => x,
            Ok(None) => {
                let first_tip =
                    StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH);
                if self.chain_tip == first_tip || self.chain_tip == StacksBlockId([0u8; 32]) {
                    // the current block height should always work, except if it's the first block
                    // height (in which case, the current chain tip should match the first-ever
                    // index block hash).
                    return 0;
                }

                // should never happen
                let msg = format!(
                    "Failed to obtain current block height of {} (got None)",
                    &self.chain_tip
                );
                error!("{}", &msg);
                panic!("{}", &msg);
            }
            Err(e) => {
                let msg = format!(
                    "Unexpected MARF failure: Failed to get current block height of {}: {:?}",
                    &self.chain_tip, &e
                );
                error!("{}", &msg);
                panic!("{}", &msg);
            }
        }
    }

    fn get_block_at_height(&mut self, block_height: u32) -> Option<StacksBlockId> {
        self.marf
            .get_bhh_at_height(&self.chain_tip, block_height)
            .unwrap_or_else(|_| {
                panic!(
                    "Unexpected MARF failure: failed to get block at height {} off of {}.",
                    block_height, &self.chain_tip
                )
            })
            .map(|x| StacksBlockId(x.to_bytes()))
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        StacksBlockId(
            self.marf
                .get_open_chain_tip()
                .expect("Attempted to get the open chain tip from an unopened context.")
                .clone()
                .to_bytes(),
        )
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        self.marf
            .get_open_chain_tip_height()
            .expect("Attempted to get the open chain tip from an unopened context.")
    }

    fn get_data_with_proof(&mut self, key: &str) -> InterpreterResult<Option<(String, Vec<u8>)>> {
        self.marf
            .get_with_proof(&self.chain_tip, key)
            .or_else(|e| match e {
                Error::NotFoundError => Ok(None),
                _ => Err(e),
            })
            .map_err(|_| VmInternalError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|(marf_value, proof)| {
                let side_key = marf_value.to_hex();
                let data =
                    SqliteConnection::get(self.get_side_store(), &side_key)?.ok_or_else(|| {
                        VmInternalError::Expect(format!(
                            "ERROR: MARF contained value_hash not found in side storage: {}",
                            side_key
                        ))
                    })?;
                Ok((data, proof.serialize_to_vec()))
            })
            .transpose()
    }

    fn get_data_with_proof_from_path(
        &mut self,
        hash: &TrieHash,
    ) -> InterpreterResult<Option<(String, Vec<u8>)>> {
        self.marf
            .get_with_proof_from_hash(&self.chain_tip, hash)
            .or_else(|e| match e {
                Error::NotFoundError => Ok(None),
                _ => Err(e),
            })
            .map_err(|_| VmInternalError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|(marf_value, proof)| {
                let side_key = marf_value.to_hex();
                let data =
                    SqliteConnection::get(self.get_side_store(), &side_key)?.ok_or_else(|| {
                        VmInternalError::Expect(format!(
                            "ERROR: MARF contained value_hash not found in side storage: {}",
                            side_key
                        ))
                    })?;
                Ok((data, proof.serialize_to_vec()))
            })
            .transpose()
    }

    fn get_data(&mut self, key: &str) -> InterpreterResult<Option<String>> {
        self.marf
            .get(&self.chain_tip, key)
            .or_else(|e| match e {
                Error::NotFoundError => {
                    test_debug!(
                        "ReadOnly MarfedKV get {:?} off of {:?}: not found",
                        key,
                        &self.chain_tip
                    );
                    Ok(None)
                }
                _ => {
                    test_debug!(
                        "ReadOnly MarfedKV get {:?} off of {:?}: {:?}",
                        key,
                        &self.chain_tip,
                        &e
                    );
                    Err(e)
                }
            })
            .map_err(|_| VmInternalError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|marf_value| {
                let side_key = marf_value.to_hex();
                SqliteConnection::get(self.get_side_store(), &side_key)?.ok_or_else(|| {
                    VmInternalError::Expect(format!(
                        "ERROR: MARF contained value_hash not found in side storage: {}",
                        side_key
                    ))
                    .into()
                })
            })
            .transpose()
    }

    fn get_data_from_path(&mut self, hash: &TrieHash) -> InterpreterResult<Option<String>> {
        trace!("MarfedKV get_from_hash: {:?} tip={}", hash, &self.chain_tip);
        self.marf
            .get_from_hash(&self.chain_tip, hash)
            .or_else(|e| match e {
                Error::NotFoundError => {
                    trace!(
                        "MarfedKV get {:?} off of {:?}: not found",
                        hash,
                        &self.chain_tip
                    );
                    Ok(None)
                }
                _ => Err(e),
            })
            .map_err(|_| VmInternalError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|marf_value| {
                let side_key = marf_value.to_hex();
                trace!("MarfedKV get side-key for {:?}: {:?}", hash, &side_key);
                SqliteConnection::get(self.get_side_store(), &side_key)?.ok_or_else(|| {
                    VmInternalError::Expect(format!(
                        "ERROR: MARF contained value_hash not found in side storage: {}",
                        side_key
                    ))
                    .into()
                })
            })
            .transpose()
    }

    fn put_all_data(&mut self, _items: Vec<(String, String)>) -> InterpreterResult<()> {
        error!("Attempted to commit changes to read-only MARF");
        panic!("BUG: attempted commit to read-only MARF");
    }

    fn get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> InterpreterResult<(StacksBlockId, Sha512Trunc256Sum)> {
        sqlite_get_contract_hash(self, contract)
    }

    fn insert_metadata(
        &mut self,
        _contract: &QualifiedContractIdentifier,
        _key: &str,
        _value: &str,
    ) -> InterpreterResult<()> {
        error!("Attempted to commit metadata changes to read-only MARF");
        panic!("BUG: attempted metadata commit to read-only MARF");
    }

    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> InterpreterResult<Option<String>> {
        sqlite_get_metadata(self, contract, key)
    }

    fn get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> InterpreterResult<Option<String>> {
        sqlite_get_metadata_manual(self, at_height, contract, key)
    }
}

impl PersistentWritableMarfStore<'_> {
    #[cfg(test)]
    fn do_test_commit(self) {
        let bhh = self.chain_tip.clone();
        self.commit_to_processed_block(&bhh).unwrap();
    }
}

impl ClarityBackingStore for PersistentWritableMarfStore<'_> {
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> InterpreterResult<StacksBlockId> {
        self.marf
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

        let result = Ok(self.chain_tip.clone());
        self.chain_tip = bhh;

        result
    }

    fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        Some(&handle_contract_call_special_cases)
    }

    fn get_data(&mut self, key: &str) -> InterpreterResult<Option<String>> {
        trace!("MarfedKV get: {:?} tip={}", key, &self.chain_tip);
        self.marf
            .get(&self.chain_tip, key)
            .or_else(|e| match e {
                Error::NotFoundError => {
                    trace!(
                        "MarfedKV get {:?} off of {:?}: not found",
                        key,
                        &self.chain_tip
                    );
                    Ok(None)
                }
                _ => Err(e),
            })
            .map_err(|_| VmInternalError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|marf_value| {
                let side_key = marf_value.to_hex();
                trace!("MarfedKV get side-key for {:?}: {:?}", key, &side_key);
                SqliteConnection::get(self.marf.sqlite_tx(), &side_key)?.ok_or_else(|| {
                    VmInternalError::Expect(format!(
                        "ERROR: MARF contained value_hash not found in side storage: {}",
                        side_key
                    ))
                    .into()
                })
            })
            .transpose()
    }

    fn get_data_from_path(&mut self, hash: &TrieHash) -> InterpreterResult<Option<String>> {
        trace!("MarfedKV get_from_hash: {:?} tip={}", hash, &self.chain_tip);
        self.marf
            .get_from_hash(&self.chain_tip, hash)
            .or_else(|e| match e {
                Error::NotFoundError => {
                    trace!(
                        "MarfedKV get {:?} off of {:?}: not found",
                        hash,
                        &self.chain_tip
                    );
                    Ok(None)
                }
                _ => Err(e),
            })
            .map_err(|_| VmInternalError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|marf_value| {
                let side_key = marf_value.to_hex();
                trace!("MarfedKV get side-key for {:?}: {:?}", hash, &side_key);
                SqliteConnection::get(self.marf.sqlite_tx(), &side_key)?.ok_or_else(|| {
                    VmInternalError::Expect(format!(
                        "ERROR: MARF contained value_hash not found in side storage: {}",
                        side_key
                    ))
                    .into()
                })
            })
            .transpose()
    }

    fn get_data_with_proof(&mut self, key: &str) -> InterpreterResult<Option<(String, Vec<u8>)>> {
        self.marf
            .get_with_proof(&self.chain_tip, key)
            .or_else(|e| match e {
                Error::NotFoundError => Ok(None),
                _ => Err(e),
            })
            .map_err(|_| VmInternalError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|(marf_value, proof)| {
                let side_key = marf_value.to_hex();
                let data =
                    SqliteConnection::get(self.marf.sqlite_tx(), &side_key)?.ok_or_else(|| {
                        VmInternalError::Expect(format!(
                            "ERROR: MARF contained value_hash not found in side storage: {}",
                            side_key
                        ))
                    })?;
                Ok((data, proof.serialize_to_vec()))
            })
            .transpose()
    }

    fn get_data_with_proof_from_path(
        &mut self,
        hash: &TrieHash,
    ) -> InterpreterResult<Option<(String, Vec<u8>)>> {
        self.marf
            .get_with_proof_from_hash(&self.chain_tip, hash)
            .or_else(|e| match e {
                Error::NotFoundError => Ok(None),
                _ => Err(e),
            })
            .map_err(|_| VmInternalError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|(marf_value, proof)| {
                let side_key = marf_value.to_hex();
                let data =
                    SqliteConnection::get(self.marf.sqlite_tx(), &side_key)?.ok_or_else(|| {
                        VmInternalError::Expect(format!(
                            "ERROR: MARF contained value_hash not found in side storage: {}",
                            side_key
                        ))
                    })?;
                Ok((data, proof.serialize_to_vec()))
            })
            .transpose()
    }

    fn get_side_store(&mut self) -> &Connection {
        self.marf.sqlite_tx()
    }

    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId> {
        self.marf
            .get_block_at_height(height, &self.chain_tip)
            .unwrap_or_else(|_| {
                panic!(
                    "Unexpected MARF failure: failed to get block at height {} off of {}.",
                    height, &self.chain_tip
                )
            })
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        self.marf
            .get_open_chain_tip()
            .expect("Attempted to get the open chain tip from an unopened context.")
            .clone()
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        self.marf
            .get_open_chain_tip_height()
            .expect("Attempted to get the open chain tip from an unopened context.")
    }

    fn get_current_block_height(&mut self) -> u32 {
        match self
            .marf
            .get_block_height_of(&self.chain_tip, &self.chain_tip)
        {
            Ok(Some(x)) => x,
            Ok(None) => {
                let first_tip =
                    StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH);
                if self.chain_tip == first_tip || self.chain_tip == StacksBlockId([0u8; 32]) {
                    // the current block height should always work, except if it's the first block
                    // height (in which case, the current chain tip should match the first-ever
                    // index block hash).
                    return 0;
                }

                // should never happen
                let msg = format!(
                    "Failed to obtain current block height of {} (got None)",
                    &self.chain_tip
                );
                error!("{}", &msg);
                panic!("{}", &msg);
            }
            Err(e) => {
                let msg = format!(
                    "Unexpected MARF failure: Failed to get current block height of {}: {:?}",
                    &self.chain_tip, &e
                );
                error!("{}", &msg);
                panic!("{}", &msg);
            }
        }
    }

    fn put_all_data(&mut self, items: Vec<(String, String)>) -> InterpreterResult<()> {
        let mut keys = Vec::with_capacity(items.len());
        let mut values = Vec::with_capacity(items.len());
        for (key, value) in items.into_iter() {
            let marf_value = MARFValue::from_value(&value);
            SqliteConnection::put(self.marf.sqlite_tx(), &marf_value.to_hex(), &value)?;
            keys.push(key);
            values.push(marf_value);
        }
        self.marf
            .insert_batch(&keys, values)
            .map_err(|_| VmInternalError::Expect("ERROR: Unexpected MARF Failure".into()).into())
    }

    fn get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> InterpreterResult<(StacksBlockId, Sha512Trunc256Sum)> {
        sqlite_get_contract_hash(self, contract)
    }

    fn insert_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
        value: &str,
    ) -> InterpreterResult<()> {
        sqlite_insert_metadata(self, contract, key, value)
    }

    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> InterpreterResult<Option<String>> {
        sqlite_get_metadata(self, contract, key)
    }

    fn get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> InterpreterResult<Option<String>> {
        sqlite_get_metadata_manual(self, at_height, contract, key)
    }
}

impl WritableMarfStore for PersistentWritableMarfStore<'_> {}

/// This trait exists so we can implement `ClarityMarfStore`, `ClarityMarfStoreTransaction`, and
/// `WritableMarfStore` for `Box<dyn WritableMarfStore + '_>`.  We need
/// `Box<dyn WritableMarfStore + '_>` because `dyn WritableMarfStore` doesn't have a size known at
/// compile time (so it cannot be Sized).  But then we'd need it to implement `WritableMarfStore`,
/// which is tricky because some of `ClartyMarfStoreTransaction`'s functions take an instance
/// `self` instead of a reference.  Because we don't know the size of `self` at compile-time, we
/// have to employ a layer of indirection.
///
/// To work around this, `WritableMarfStore` is composed of `BoxedClarityMarfStoreTransaction`
/// below, and we have a blanket implementation of `BoxedClarityMarfStoreTransaction` for any
/// `T: ClarityMarfStoreTransaction`.  This in turn allows us to implement
/// `ClarityMarfStoreTransaction for `Box<dyn WritableMarfStore + 'a>` -- we cast to
/// `ClarityMarfStoreTransaction` to call functions that take a reference to `self`, and we cast to
/// `BoxedClarityMarfStoreTransaction` to call functions that take an instance of `self`.  In the
/// latter case, the instance will have a compile-time size since it will be a Box.  The
/// implementation of `BoxedClarityMarfStoreTransaction` just forwards the call to the
/// corresponding function in `ClarityMarfStoreTransaction` with a reference to the boxed instance.
pub trait BoxedClarityMarfStoreTransaction {
    fn boxed_drop_current_trie(self: Box<Self>);
    fn boxed_drop_unconfirmed(self: Box<Self>) -> InterpreterResult<()>;
    fn boxed_commit_to_processed_block(
        self: Box<Self>,
        target: &StacksBlockId,
    ) -> InterpreterResult<()>;
    fn boxed_commit_to_mined_block(
        self: Box<Self>,
        target: &StacksBlockId,
    ) -> InterpreterResult<()>;
    fn boxed_commit_unconfirmed(self: Box<Self>);

    #[cfg(test)]
    fn boxed_test_commit(self: Box<Self>);
}

impl<T: ClarityMarfStoreTransaction> BoxedClarityMarfStoreTransaction for T {
    fn boxed_drop_current_trie(self: Box<Self>) {
        <Self as ClarityMarfStoreTransaction>::drop_current_trie(*self)
    }

    fn boxed_drop_unconfirmed(self: Box<Self>) -> InterpreterResult<()> {
        <Self as ClarityMarfStoreTransaction>::drop_unconfirmed(*self)
    }

    fn boxed_commit_to_processed_block(
        self: Box<Self>,
        target: &StacksBlockId,
    ) -> InterpreterResult<()> {
        <Self as ClarityMarfStoreTransaction>::commit_to_processed_block(*self, target)
    }

    fn boxed_commit_to_mined_block(
        self: Box<Self>,
        target: &StacksBlockId,
    ) -> InterpreterResult<()> {
        <Self as ClarityMarfStoreTransaction>::commit_to_mined_block(*self, target)
    }

    fn boxed_commit_unconfirmed(self: Box<Self>) {
        <Self as ClarityMarfStoreTransaction>::commit_unconfirmed(*self)
    }

    #[cfg(test)]
    fn boxed_test_commit(self: Box<Self>) {
        <Self as ClarityMarfStoreTransaction>::test_commit(*self)
    }
}

impl<'a> ClarityMarfStoreTransaction for Box<dyn WritableMarfStore + 'a> {
    fn commit_metadata_for_trie(&mut self, target: &StacksBlockId) -> InterpreterResult<()> {
        ClarityMarfStoreTransaction::commit_metadata_for_trie(self.deref_mut(), target)
    }

    fn drop_metadata_for_trie(&mut self, target: &StacksBlockId) -> InterpreterResult<()> {
        ClarityMarfStoreTransaction::drop_metadata_for_trie(self.deref_mut(), target)
    }

    fn seal_trie(&mut self) -> TrieHash {
        ClarityMarfStoreTransaction::seal_trie(self.deref_mut())
    }

    fn drop_current_trie(self) {
        BoxedClarityMarfStoreTransaction::boxed_drop_current_trie(self)
    }

    fn drop_unconfirmed(self) -> InterpreterResult<()> {
        BoxedClarityMarfStoreTransaction::boxed_drop_unconfirmed(self)
    }
    fn commit_to_processed_block(self, target: &StacksBlockId) -> InterpreterResult<()> {
        BoxedClarityMarfStoreTransaction::boxed_commit_to_processed_block(self, target)
    }

    fn commit_to_mined_block(self, target: &StacksBlockId) -> InterpreterResult<()> {
        BoxedClarityMarfStoreTransaction::boxed_commit_to_mined_block(self, target)
    }

    fn commit_unconfirmed(self) {
        BoxedClarityMarfStoreTransaction::boxed_commit_unconfirmed(self)
    }

    #[cfg(test)]
    fn test_commit(self) {
        BoxedClarityMarfStoreTransaction::boxed_test_commit(self)
    }
}

impl<'a> ClarityBackingStore for Box<dyn WritableMarfStore + 'a> {
    fn put_all_data(&mut self, items: Vec<(String, String)>) -> InterpreterResult<()> {
        ClarityBackingStore::put_all_data(self.deref_mut(), items)
    }

    fn get_data(&mut self, key: &str) -> InterpreterResult<Option<String>> {
        ClarityBackingStore::get_data(self.deref_mut(), key)
    }

    fn get_data_from_path(&mut self, hash: &TrieHash) -> InterpreterResult<Option<String>> {
        ClarityBackingStore::get_data_from_path(self.deref_mut(), hash)
    }

    fn get_data_with_proof(&mut self, key: &str) -> InterpreterResult<Option<(String, Vec<u8>)>> {
        ClarityBackingStore::get_data_with_proof(self.deref_mut(), key)
    }

    fn get_data_with_proof_from_path(
        &mut self,
        hash: &TrieHash,
    ) -> InterpreterResult<Option<(String, Vec<u8>)>> {
        ClarityBackingStore::get_data_with_proof_from_path(self.deref_mut(), hash)
    }

    fn set_block_hash(&mut self, bhh: StacksBlockId) -> InterpreterResult<StacksBlockId> {
        ClarityBackingStore::set_block_hash(self.deref_mut(), bhh)
    }

    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId> {
        ClarityBackingStore::get_block_at_height(self.deref_mut(), height)
    }

    fn get_current_block_height(&mut self) -> u32 {
        ClarityBackingStore::get_current_block_height(self.deref_mut())
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        ClarityBackingStore::get_open_chain_tip_height(self.deref_mut())
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        ClarityBackingStore::get_open_chain_tip(self.deref_mut())
    }

    fn get_side_store(&mut self) -> &Connection {
        ClarityBackingStore::get_side_store(self.deref_mut())
    }

    fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        ClarityBackingStore::get_cc_special_cases_handler(&**self)
    }

    fn get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> InterpreterResult<(StacksBlockId, Sha512Trunc256Sum)> {
        ClarityBackingStore::get_contract_hash(self.deref_mut(), contract)
    }

    fn insert_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
        value: &str,
    ) -> InterpreterResult<()> {
        ClarityBackingStore::insert_metadata(self.deref_mut(), contract, key, value)
    }

    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> InterpreterResult<Option<String>> {
        ClarityBackingStore::get_metadata(self.deref_mut(), contract, key)
    }

    fn get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> InterpreterResult<Option<String>> {
        ClarityBackingStore::get_metadata_manual(self.deref_mut(), at_height, contract, key)
    }
}

impl<'a> ClarityMarfStore for Box<dyn WritableMarfStore + 'a> {}
impl<'a> WritableMarfStore for Box<dyn WritableMarfStore + 'a> {}
