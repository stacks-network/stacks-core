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

use std::mem;
use std::path::PathBuf;
use std::str::FromStr;

use clarity::util::hash::Sha512Trunc256Sum;
use clarity::vm::analysis::AnalysisDatabase;
use clarity::vm::database::sqlite::{
    sqlite_get_contract_hash, sqlite_get_metadata, sqlite_get_metadata_manual,
    sqlite_insert_metadata,
};
use clarity::vm::database::{
    BurnStateDB, ClarityBackingStore, ClarityDatabase, HeadersDB, SpecialCaseHandler,
    SqliteConnection,
};
use clarity::vm::errors::{
    IncomparableError, InterpreterError, InterpreterResult, RuntimeErrorType,
};
use clarity::vm::types::QualifiedContractIdentifier;
use rusqlite;
use rusqlite::Connection;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId, TrieHash};
use stacks_common::types::sqlite::NO_PARAMS;

use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MarfTransaction, MARF};
use crate::chainstate::stacks::index::storage::{TrieFileStorage, TrieHashCalculationMode};
use crate::chainstate::stacks::index::{ClarityMarfTrieId, Error, MARFValue};
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
    ephemeral_marf: Option<MARF<StacksBlockId>>,
}

impl MarfedKV {
    fn setup_db(
        path_str: &str,
        unconfirmed: bool,
        marf_opts: Option<MARFOpenOpts>,
    ) -> InterpreterResult<MARF<StacksBlockId>> {
        let mut path = PathBuf::from(path_str);

        std::fs::create_dir_all(&path)
            .map_err(|_| InterpreterError::FailedToCreateDataDirectory)?;

        path.push("marf.sqlite");
        let marf_path = path
            .to_str()
            .ok_or_else(|| InterpreterError::BadFileName)?
            .to_string();

        let mut marf_opts = marf_opts.unwrap_or(MARFOpenOpts::default());
        marf_opts.external_blobs = true;

        let mut marf: MARF<StacksBlockId> = if unconfirmed {
            MARF::from_path_unconfirmed(&marf_path, marf_opts)
                .map_err(|err| InterpreterError::MarfFailure(err.to_string()))?
        } else {
            MARF::from_path(&marf_path, marf_opts)
                .map_err(|err| InterpreterError::MarfFailure(err.to_string()))?
        };

        if SqliteConnection::check_schema(marf.sqlite_conn()).is_ok() {
            // no need to initialize
            return Ok(marf);
        }

        let tx = marf
            .storage_tx()
            .map_err(|err| InterpreterError::DBError(err.to_string()))?;

        SqliteConnection::initialize_conn(&tx)?;
        tx.commit()
            .map_err(|err| InterpreterError::SqliteError(IncomparableError { err }))?;

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
                InterpreterError::MarfFailure(Error::NotFoundError.to_string())
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
            InterpreterError::MarfFailure(Error::NotFoundError.to_string())
        })?;

        // set up ephemeral MARF
        let ephemeral_marf_storage = TrieFileStorage::open(
            ":memory:",
            MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", false),
        )
        .map_err(|e| {
            InterpreterError::Expect(format!("Failed to instantiate ephemeral MARF: {:?}", &e))
        })?;

        let mut ephemeral_marf = MARF::from_storage(ephemeral_marf_storage);
        let tx = ephemeral_marf
            .storage_tx()
            .map_err(|err| InterpreterError::DBError(err.to_string()))?;

        SqliteConnection::initialize_conn(&tx)?;
        tx.commit()
            .map_err(|err| InterpreterError::SqliteError(IncomparableError { err }))?;

        self.ephemeral_marf = Some(ephemeral_marf);

        let read_only_marf = ReadOnlyMarfStore {
            chain_tip: base_tip.clone(),
            marf: &mut self.marf,
        };

        let tx = if let Some(ephemeral_marf) = self.ephemeral_marf.as_mut() {
            // attach the disk-backed MARF to the ephemeral MARF
            EphemeralMarfStore::attach_read_only_marf(&ephemeral_marf, &read_only_marf).map_err(
                |e| {
                    InterpreterError::Expect(format!(
                        "Failed to attach read-only MARF to ephemeral MARF: {:?}",
                        &e
                    ))
                },
            )?;

            let mut tx = ephemeral_marf.begin_tx().map_err(|e| {
                InterpreterError::Expect(format!("Failed to open ephemeral MARF tx: {:?}", &e))
            })?;
            tx.begin(&StacksBlockId::sentinel(), ephemeral_next)
                .map_err(|e| {
                    InterpreterError::Expect(format!(
                        "Failed to begin first ephemeral MARF block: {:?}",
                        &e
                    ))
                })?;
            tx
        } else {
            // unreachable since self.ephemeral_marf is already assigned
            unreachable!();
        };

        let ephemeral_marf_store = EphemeralMarfStore::new(read_only_marf, tx).map_err(|e| {
            InterpreterError::Expect(format!(
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

/// A MARF store transaction for a chainstate block's trie.
/// This transaction instantiates a trie which builds atop an already-written trie in the
/// chainstate.  Once committed, it will persist -- it may be built upon, and a subsequent attempt
/// to build the same trie will fail.
///
/// The Stacks node commits tries for one of three purposes:
/// * It processed a block, and needs to persist its trie in the chainstate proper.
/// * It mined a block, and needs to persist its trie outside of the chainstate proper. The miner
/// may build on it later.
/// * It processed an unconfirmed microblock (Stacks 2.x only), and needs to persist the
/// unconfirmed chainstate outside of the chainstate proper so that the microblock miner can
/// continue to build on it and the network can service RPC requests on its state.
///
/// These needs are each captured in distinct methods for committing this transaction.
pub trait ClarityMarfStoreTransaction {
    /// Commit all inserted metadata and associate it with the block trie identified by `target`.
    /// It can later be deleted via `drop_metadata_for()` if given the same taret.
    /// Returns Ok(()) on success
    /// Returns Err(..) on error
    fn commit_metadata_for_trie(&mut self, target: &StacksBlockId) -> InterpreterResult<()>;

    /// Drop metadata for a particular block trie that was stored previously via `commit_metadata_to()`.
    /// This function is idempotent.
    ///
    /// Returns Ok(()) if the metadata for the trie identified by `target` was dropped.
    /// It will be possible to insert it again afterwards.
    /// Returns Err(..) if the metadata was not successfully dropped.
    fn drop_metadata_for_trie(&mut self, target: &StacksBlockId) -> InterpreterResult<()>;

    /// Compute the ID of the trie being built.
    /// In Stacks, this will only be called once all key/value pairs are inserted (and will only be
    /// called at most once in this transaction's lifetime).
    fn seal_trie(&mut self) -> TrieHash;

    /// Drop the block trie that this transaction was creating.
    /// Destroys the transaction.
    fn drop_current_trie(self);

    /// Drop the unconfirmed state trie that this transaction was creating.
    /// Destroys the transaction.
    ///
    /// Returns Ok(()) on successful deletion of the data
    /// Returns Err(..) if the deletion failed (this usually isn't recoverable, but recovery is up
    /// to the caller)
    fn drop_unconfirmed(self) -> InterpreterResult<()>;

    /// Store the processed block's trie that this transaction was creating.
    /// The trie's ID must be `target`, so that subsequent tries can be built on it (and so that
    /// subsequent queries can read from it).  `target` may not be known until it is time to write
    /// the trie out, which is why it is provided here.
    ///
    /// Returns Ok(()) if the block trie was successfully persisted.
    /// Returns Err(..) if there was an error in trying to persist this block trie.
    fn commit_to_processed_block(self, target: &StacksBlockId) -> InterpreterResult<()>;

    /// Store a mined block's trie that this transaction was creating.
    /// This function is distinct from `commit_to_processed_block()` in that the stored block will
    /// not be added to the chainstate. However, it must be persisted so that the node can later
    /// build on it.
    ///
    /// Returns Ok(()) if the block trie was successfully persisted.
    /// Returns Err(..) if there was an error trying to persist this MARF trie.
    fn commit_to_mined_block(self, target: &StacksBlockId) -> InterpreterResult<()>;

    /// Persist the unconfirmed state trie so that other parts of the Stacks node can read from it
    /// (such as to handle pending transactions or process RPC requests on it).
    fn commit_unconfirmed(self);

    /// Commit to the current chain tip.
    /// Used only for testing.
    #[cfg(test)]
    fn test_commit(self);
}

/// Unified API common to all MARF stores
pub trait ClarityMarfStore: ClarityBackingStore {
    /// Instantiate a `ClarityDatabase` out of this MARF store.
    /// Takes a `HeadersDB` and `BurnStateDB` implementation which are both used by
    /// `ClarityDatabase` to access Stacks's chainstate and sortition chainstate, respectively.
    fn as_clarity_db<'b>(
        &'b mut self,
        headers_db: &'b dyn HeadersDB,
        burn_state_db: &'b dyn BurnStateDB,
    ) -> ClarityDatabase<'b>
    where
        Self: Sized,
    {
        ClarityDatabase::new(self, headers_db, burn_state_db)
    }

    /// Instantiate an `AnalysisDatabase` out of this MARF store.
    fn as_analysis_db(&mut self) -> AnalysisDatabase<'_>
    where
        Self: Sized,
    {
        AnalysisDatabase::new(self)
    }
}

/// A MARF store which can be written to is both a ClarityMarfStore and a
/// ClarityMarfStoreTransaction (and thus also a ClarityBackingStore).
pub trait WritableMarfStore:
    ClarityMarfStore + ClarityMarfStoreTransaction + BoxedClarityMarfStoreTransaction
{
}

impl ClarityMarfStore for ReadOnlyMarfStore<'_> {}
impl ClarityMarfStore for PersistentWritableMarfStore<'_> {}
impl ClarityMarfStore for EphemeralMarfStore<'_> {}

impl ClarityMarfStoreTransaction for PersistentWritableMarfStore<'_> {
    /// Commit metadata for a given `target` trie.  In this MARF store, this just renames all
    /// metadata rows with `self.chain_tip` as their block identifier to have `target` instead.
    ///
    /// Returns Ok(()) on success
    /// Returns Err(InterpreterError(..)) on sqlite failure
    fn commit_metadata_for_trie(&mut self, target: &StacksBlockId) -> InterpreterResult<()> {
        SqliteConnection::commit_metadata_to(self.marf.sqlite_tx(), &self.chain_tip, target)
    }

    /// Drop metadata for the given `target` trie. This just drops the metadata rows with `target`
    /// as their block identifier.
    ///
    /// Returns Ok(()) on success
    /// Returns Err(InterpreterError(..)) on sqlite failure
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
    /// Returns Err(InterpreterError(..)) on sqlite failure
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
    /// Returns Err(InterpreterError(..)) on sqlite failure
    fn commit_to_processed_block(mut self, target: &StacksBlockId) -> InterpreterResult<()> {
        debug!("commit_to({})", target);
        self.commit_metadata_for_trie(target)?;
        let _ = self.marf.commit_to(target).map_err(|e| {
            error!("Failed to commit to MARF block {target}: {e:?}");
            InterpreterError::Expect("Failed to commit to MARF block".into())
        })?;
        Ok(())
    }

    /// Commit the outstanding trie to the `mined_blocks` table in the underlying MARF.
    /// The metadata will be dropped, since this won't be added to the chainstate.  This commits
    /// the transaction and drops this MARF store.
    ///
    /// Returns Ok(()) on success
    /// Returns Err(InterpreterError(..)) on sqlite failure
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
            InterpreterError::Expect("Failed to commit to MARF block".into())
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

impl ClarityMarfStoreTransaction for EphemeralMarfStore<'_> {
    /// Commit metadata for a given `target` trie.  In this MARF store, this just renames all
    /// metadata rows with `self.chain_tip` as their block identifier to have `target` instead,
    /// but only within the ephemeral MARF.  None of the writes will hit disk, and they will
    /// disappear when this instance is dropped
    ///
    /// Returns Ok(()) on success
    /// Returns Err(InterpreterError(..)) on sqlite failure
    fn commit_metadata_for_trie(&mut self, target: &StacksBlockId) -> InterpreterResult<()> {
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
    /// Returns Err(InterpreterError(..)) on sqlite failure
    fn drop_metadata_for_trie(&mut self, target: &StacksBlockId) -> InterpreterResult<()> {
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
    /// Returns Err(InterpreterError(..)) on sqlite failure
    fn drop_unconfirmed(mut self) -> InterpreterResult<()> {
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
    /// Returns Err(InterpreterError(..)) on sqlite failure
    fn commit_to_processed_block(mut self, target: &StacksBlockId) -> InterpreterResult<()> {
        if self.ephemeral_marf.get_open_chain_tip().is_some() {
            self.commit_metadata_for_trie(target)?;
            let _ = self.ephemeral_marf.commit_to(target).map_err(|e| {
                error!("Failed to commit to ephemeral MARF block {target}: {e:?}",);
                InterpreterError::Expect("Failed to commit to MARF block".into())
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
    /// Returns Err(InterpreterError(..)) on sqlite failure
    fn commit_to_mined_block(mut self, target: &StacksBlockId) -> InterpreterResult<()> {
        if let Some(tip) = self.ephemeral_marf.get_open_chain_tip().cloned() {
            // rollback the side_store
            //    the side_store shouldn't commit data for blocks that won't be
            //    included in the processed chainstate (like a block constructed during mining)
            //    _if_ for some reason, we do want to be able to access that mined chain state in the future,
            //    we should probably commit the data to a different table which does not have uniqueness constraints.
            self.drop_metadata_for_trie(&tip)?;
            let _ = self.ephemeral_marf.commit_mined(target).map_err(|e| {
                error!("Failed to commit to mined MARF block {target}: {e:?}",);
                InterpreterError::Expect("Failed to commit to MARF block".into())
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
                    RuntimeErrorType::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0))
                }
                Error::NonMatchingForks(_bh1, _bh2) => {
                    test_debug!(
                        "No such block {:?} (NonMatchingForks({}, {}))",
                        &bhh,
                        BlockHeaderHash(_bh1),
                        BlockHeaderHash(_bh2)
                    );
                    RuntimeErrorType::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0))
                }
                _ => panic!("ERROR: Unexpected MARF failure: {}", e),
            })?;

        let result = Ok(self.chain_tip);
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
            .map_err(|_| InterpreterError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|(marf_value, proof)| {
                let side_key = marf_value.to_hex();
                let data =
                    SqliteConnection::get(self.get_side_store(), &side_key)?.ok_or_else(|| {
                        InterpreterError::Expect(format!(
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
            .map_err(|_| InterpreterError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|(marf_value, proof)| {
                let side_key = marf_value.to_hex();
                let data =
                    SqliteConnection::get(self.get_side_store(), &side_key)?.ok_or_else(|| {
                        InterpreterError::Expect(format!(
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
            .map_err(|_| InterpreterError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|marf_value| {
                let side_key = marf_value.to_hex();
                SqliteConnection::get(self.get_side_store(), &side_key)?.ok_or_else(|| {
                    InterpreterError::Expect(format!(
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
            .map_err(|_| InterpreterError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|marf_value| {
                let side_key = marf_value.to_hex();
                trace!("MarfedKV get side-key for {:?}: {:?}", hash, &side_key);
                SqliteConnection::get(self.get_side_store(), &side_key)?.ok_or_else(|| {
                    InterpreterError::Expect(format!(
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
                    RuntimeErrorType::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0))
                }
                Error::NonMatchingForks(_bh1, _bh2) => {
                    test_debug!(
                        "No such block {:?} (NonMatchingForks({}, {}))",
                        &bhh,
                        BlockHeaderHash(_bh1),
                        BlockHeaderHash(_bh2)
                    );
                    RuntimeErrorType::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0))
                }
                _ => panic!("ERROR: Unexpected MARF failure: {}", e),
            })?;

        let result = Ok(self.chain_tip);
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
            .map_err(|_| InterpreterError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|marf_value| {
                let side_key = marf_value.to_hex();
                trace!("MarfedKV get side-key for {:?}: {:?}", key, &side_key);
                SqliteConnection::get(self.marf.sqlite_tx(), &side_key)?.ok_or_else(|| {
                    InterpreterError::Expect(format!(
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
            .map_err(|_| InterpreterError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|marf_value| {
                let side_key = marf_value.to_hex();
                trace!("MarfedKV get side-key for {:?}: {:?}", hash, &side_key);
                SqliteConnection::get(self.marf.sqlite_tx(), &side_key)?.ok_or_else(|| {
                    InterpreterError::Expect(format!(
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
            .map_err(|_| InterpreterError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|(marf_value, proof)| {
                let side_key = marf_value.to_hex();
                let data =
                    SqliteConnection::get(self.marf.sqlite_tx(), &side_key)?.ok_or_else(|| {
                        InterpreterError::Expect(format!(
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
            .map_err(|_| InterpreterError::Expect("ERROR: Unexpected MARF Failure on GET".into()))?
            .map(|(marf_value, proof)| {
                let side_key = marf_value.to_hex();
                let data =
                    SqliteConnection::get(self.marf.sqlite_tx(), &side_key)?.ok_or_else(|| {
                        InterpreterError::Expect(format!(
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
            .map_err(|_| InterpreterError::Expect("ERROR: Unexpected MARF Failure".into()).into())
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
            rusqlite::params![read_only_marf.marf.get_db_path()],
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
            base_tip: read_only_marf.chain_tip.clone(),
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
    fn is_ephemeral_tip(&mut self, tip: &StacksBlockId) -> Result<bool, InterpreterError> {
        match self.ephemeral_marf.get_root_hash_at(tip) {
            Ok(_) => Ok(true),
            Err(Error::NotFoundError) => Ok(false),
            Err(e) => Err(InterpreterError::MarfFailure(e.to_string())),
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
}

impl ClarityBackingStore for EphemeralMarfStore<'_> {
    /// Seek to the given chain tip.  This given tip will become the new tip from which
    /// reads and writes will be indexed.
    ///
    /// Returns Ok(old-chain-tip) on success.
    /// Returns Err(..) if the given chain tip does not exist or is on a different fork (e.g. is
    /// not an ancestor of this struct's tip).
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> InterpreterResult<StacksBlockId> {
        if self.is_ephemeral_tip(&bhh)? {
            // open the disk-backed MARF to the base tip, so we can carry out reads on disk-backed
            // data in the event that a read on a key is `None` for the ephemeral MARF.
            self.read_only_marf.set_block_hash(self.base_tip.clone())?;

            // update ephemeral MARF open tip
            let old_tip = mem::replace(&mut self.open_tip, EphemeralTip::RAM(bhh)).into_block_id();
            self.open_tip = EphemeralTip::RAM(bhh);
            return Ok(old_tip);
        }

        // this bhh is not ephemeral, so it might be disk-backed.
        self.read_only_marf
            .marf
            .check_ancestor_block_hash(&bhh)
            .map_err(|e| match e {
                Error::NotFoundError => {
                    test_debug!("No such block {:?} (NotFoundError)", &bhh);
                    RuntimeErrorType::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0))
                }
                Error::NonMatchingForks(_bh1, _bh2) => {
                    test_debug!(
                        "No such block {:?} (NonMatchingForks({}, {}))",
                        &bhh,
                        BlockHeaderHash(_bh1),
                        BlockHeaderHash(_bh2)
                    );
                    RuntimeErrorType::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0))
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
    fn get_data(&mut self, key: &str) -> InterpreterResult<Option<String>> {
        let value_res: InterpreterResult<Option<String>> = if let EphemeralTip::RAM(tip) =
            &self.open_tip
        {
            // try the ephemeral MARF first
            self.ephemeral_marf
                .get(tip, key)
                .or_else(|e| match e {
                    Error::NotFoundError => {
                        test_debug!(
                            "Ephemeral MarfedKV get {:?} off of {:?}: not found",
                            key,
                            tip
                        );
                        Ok(None)
                    }
                    _ => {
                        test_debug!(
                            "Ephemeral MarfedKV failed to get {:?} off of {:?}: {:?}",
                            key,
                            tip,
                            &e
                        );
                        Err(e)
                    }
                })
                .map_err(|_| InterpreterError::Expect("ERROR: Unexpected Ephemeral MARF Failure on GET".into()))?
                .map(|marf_value| {
                    let side_key = marf_value.to_hex();
                    SqliteConnection::get(self.ephemeral_marf.sqlite_conn(), &side_key)?.ok_or_else(|| {
                        InterpreterError::Expect(format!(
                            "ERROR: Ephemeral MARF contained value_hash not found in side storage: {}",
                            side_key
                        ))
                        .into()
                    })
                })
                .transpose()
        } else {
            Ok(None)
        };

        if let Some(value) = value_res? {
            // found in ephemeral MARF
            return Ok(Some(value));
        }

        // Due to the way we implemented `.set_block_hash()`, the read-only
        // MARF's tip will be set to `base_tip` if the open tip was ephemeral.
        // Otherwise, it'll be set to the tip that was last opeend.  Either way,
        // the correct tip has been set in `self.read_only_marf` that `.get_data()`
        // will work as expected.
        self.read_only_marf.get_data(key)
    }

    /// Get data from the MARF given a trie hash.
    /// Returns Ok(Some(value)) if the key was mapped to the given value at the opeend chain tip.
    /// Returns Ok(None) if the key was not mapped to the given value at the opened chain tip.
    /// Returns Err(..) on all other failures
    fn get_data_from_path(&mut self, hash: &TrieHash) -> InterpreterResult<Option<String>> {
        trace!(
            "Ephemeral MarfedKV get_from_hash: {:?} tip={:?}",
            hash,
            &self.open_tip
        );
        let value_res: InterpreterResult<Option<String>> = if let EphemeralTip::RAM(tip) =
            &self.open_tip
        {
            // try the ephemeral MARF first
            self.ephemeral_marf
                .get_from_hash(tip, hash)
                .or_else(|e| match e {
                    Error::NotFoundError => {
                        trace!(
                            "Ephemeral MarfedKV get {:?} off of {:?}: not found",
                            hash,
                            tip
                        );
                        Ok(None)
                    }
                    _ => Err(e),
                })
                .map_err(|_| InterpreterError::Expect("ERROR: Unexpected MARF Failure on get-by-path".into()))?
                .map(|marf_value| {
                    let side_key = marf_value.to_hex();
                    trace!("Ephemeral MarfedKV get side-key for {:?}: {:?}", hash, &side_key);
                    SqliteConnection::get(self.ephemeral_marf.sqlite_conn(), &side_key)?.ok_or_else(|| {
                        InterpreterError::Expect(format!(
                            "ERROR: Ephemeral MARF contained value_hash not found in side storage: {}",
                            side_key
                        ))
                        .into()
                    })
                })
                .transpose()
        } else {
            Ok(None)
        };

        if let Some(value) = value_res? {
            // found in ephemeral MARF
            return Ok(Some(value));
        }

        // Due to the way we implemented `.set_block_hash()`, the read-only
        // MARF's tip will be set to `base_tip` if the open tip was ephemeral.
        // Otherwise, it'll be set to the tip that was last opeend.  Either way,
        // the correct tip has been set in `self.read_only_marf` that `.get_data_from_path()`
        // will work as expected.
        self.read_only_marf.get_data_from_path(hash)
    }

    /// Get data from the MARF as well as a Merkle proof-of-inclusion.
    /// Returns Ok(Some(value)) if the key was mapped to the given value at the opened chain tip.
    /// Returns Ok(None) if the key was not mapped to the given value at the opened chain tip.
    /// Returns Err(..) on all other failures
    fn get_data_with_proof(&mut self, key: &str) -> InterpreterResult<Option<(String, Vec<u8>)>> {
        trace!(
            "Ephemeral MarfedKV get_data_with_proof: '{}' tip={:?}",
            key,
            &self.open_tip
        );
        let value_res: InterpreterResult<Option<(String, Vec<u8>)>> =
            if let EphemeralTip::RAM(tip) = &self.open_tip {
                // try the ephemeral MARF first
                self.ephemeral_marf
                    .get_with_proof(tip, key)
                    .or_else(|e| match e {
                        Error::NotFoundError => {
                            trace!(
                                "Ephemeral MarfedKV get-with-proof '{}' off of {:?}: not found",
                                key,
                                tip
                            );
                            Ok(None)
                        }
                        _ => Err(e),
                    })
                    .map_err(|_| {
                        InterpreterError::Expect(
                            "ERROR: Unexpected Ephemeral MARF Failure on get-with-proof".into(),
                        )
                    })?
                    .map(|(marf_value, proof)| {
                        let side_key = marf_value.to_hex();
                        let data =
                            SqliteConnection::get(self.ephemeral_marf.sqlite_conn(), &side_key)?
                                .ok_or_else(|| {
                                    InterpreterError::Expect(format!(
                                "ERROR: MARF contained value_hash not found in side storage: {}",
                                side_key
                            ))
                                })?;
                        Ok((data, proof.serialize_to_vec()))
                    })
                    .transpose()
            } else {
                Ok(None)
            };

        if let Some(value) = value_res? {
            // found in ephemeral MARF
            return Ok(Some(value));
        }

        // Due to the way we implemented `.set_block_hash()`, the read-only
        // MARF's tip will be set to `base_tip` if the open tip was ephemeral.
        // Otherwise, it'll be set to the tip that was last opeend.  Either way,
        // the correct tip has been set in `self.read_only_marf` that `.get_data_with_proof()`
        // will work as expected.
        self.read_only_marf.get_data_with_proof(key)
    }

    /// Get data and a Merkle proof-of-inclusion for it from the MARF given a trie hash.
    /// Returns Ok(Some(value)) if the key was mapped to the given value at the opeend chain tip.
    /// Returns Ok(None) if the key was not mapped to the given value at the opened chain tip.
    /// Returns Err(..) on all other failures
    fn get_data_with_proof_from_path(
        &mut self,
        hash: &TrieHash,
    ) -> InterpreterResult<Option<(String, Vec<u8>)>> {
        trace!(
            "Ephemeral MarfedKV get_data_with_proof_from_hash: {:?} tip={:?}",
            hash,
            &self.open_tip
        );
        let value_res: InterpreterResult<Option<(String, Vec<u8>)>> =
            if let EphemeralTip::RAM(tip) = &self.open_tip {
                self.ephemeral_marf
                    .get_with_proof_from_hash(tip, hash)
                    .or_else(|e| match e {
                        Error::NotFoundError => {
                            trace!(
                                "Ephemeral MarfedKV get-with-proof {:?} off of {:?}: not found",
                                hash,
                                tip
                            );
                            Ok(None)
                        }
                        _ => Err(e),
                    })
                    .map_err(|_| {
                        InterpreterError::Expect(
                            "ERROR: Unexpected ephemeral MARF Failure on get-data-with-proof"
                                .into(),
                        )
                    })?
                    .map(|(marf_value, proof)| {
                        let side_key = marf_value.to_hex();
                        let data =
                            SqliteConnection::get(self.ephemeral_marf.sqlite_conn(), &side_key)?
                                .ok_or_else(|| {
                                    InterpreterError::Expect(format!(
                                "ERROR: MARF contained value_hash not found in side storage: {}",
                                side_key
                            ))
                                })?;
                        Ok((data, proof.serialize_to_vec()))
                    })
                    .transpose()
            } else {
                Ok(None)
            };

        if let Some(value) = value_res? {
            // found in ephemeral MARF
            return Ok(Some(value));
        }

        // Due to the way we implemented `.set_block_hash()`, the read-only
        // MARF's tip will be set to `base_tip` if the open tip was ephemeral.
        // Otherwise, it'll be set to the tip that was last opeend.  Either way,
        // the correct tip has been set in `self.read_only_marf` that
        // `.get_data_with_proof_from_path()`
        // will work as expected.
        self.read_only_marf.get_data_with_proof_from_path(hash)
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
    fn put_all_data(&mut self, items: Vec<(String, String)>) -> InterpreterResult<()> {
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
    ) -> InterpreterResult<(StacksBlockId, Sha512Trunc256Sum)> {
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
    ) -> InterpreterResult<()> {
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
    ) -> InterpreterResult<Option<String>> {
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
    ) -> InterpreterResult<Option<String>> {
        sqlite_get_metadata_manual(self, at_height, contract, key)
    }
}

impl WritableMarfStore for PersistentWritableMarfStore<'_> {}
impl WritableMarfStore for EphemeralMarfStore<'_> {}

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
        <dyn WritableMarfStore as ClarityMarfStoreTransaction>::commit_metadata_for_trie(
            &mut **self,
            target,
        )
    }

    fn drop_metadata_for_trie(&mut self, target: &StacksBlockId) -> InterpreterResult<()> {
        <dyn WritableMarfStore as ClarityMarfStoreTransaction>::drop_metadata_for_trie(
            &mut **self,
            target,
        )
    }

    fn seal_trie(&mut self) -> TrieHash {
        <dyn WritableMarfStore as ClarityMarfStoreTransaction>::seal_trie(&mut **self)
    }

    fn drop_current_trie(self) {
        <dyn WritableMarfStore as BoxedClarityMarfStoreTransaction>::boxed_drop_current_trie(self)
    }

    fn drop_unconfirmed(self) -> InterpreterResult<()> {
        <dyn WritableMarfStore as BoxedClarityMarfStoreTransaction>::boxed_drop_unconfirmed(self)
    }
    fn commit_to_processed_block(self, target: &StacksBlockId) -> InterpreterResult<()> {
        <dyn WritableMarfStore as BoxedClarityMarfStoreTransaction>::boxed_commit_to_processed_block(
            self, target,
        )
    }

    fn commit_to_mined_block(self, target: &StacksBlockId) -> InterpreterResult<()> {
        <dyn WritableMarfStore as BoxedClarityMarfStoreTransaction>::boxed_commit_to_mined_block(
            self, target,
        )
    }

    fn commit_unconfirmed(self) {
        <dyn WritableMarfStore as BoxedClarityMarfStoreTransaction>::boxed_commit_unconfirmed(self)
    }

    #[cfg(test)]
    fn test_commit(self) {
        <dyn WritableMarfStore as BoxedClarityMarfStoreTransaction>::boxed_test_commit(self)
    }
}

impl<'a> ClarityBackingStore for Box<dyn WritableMarfStore + 'a> {
    fn put_all_data(&mut self, items: Vec<(String, String)>) -> InterpreterResult<()> {
        <dyn WritableMarfStore as ClarityBackingStore>::put_all_data(&mut **self, items)
    }

    fn get_data(&mut self, key: &str) -> InterpreterResult<Option<String>> {
        <dyn WritableMarfStore as ClarityBackingStore>::get_data(&mut **self, key)
    }

    fn get_data_from_path(&mut self, hash: &TrieHash) -> InterpreterResult<Option<String>> {
        <dyn WritableMarfStore as ClarityBackingStore>::get_data_from_path(&mut **self, hash)
    }

    fn get_data_with_proof(&mut self, key: &str) -> InterpreterResult<Option<(String, Vec<u8>)>> {
        <dyn WritableMarfStore as ClarityBackingStore>::get_data_with_proof(&mut **self, key)
    }

    fn get_data_with_proof_from_path(
        &mut self,
        hash: &TrieHash,
    ) -> InterpreterResult<Option<(String, Vec<u8>)>> {
        <dyn WritableMarfStore as ClarityBackingStore>::get_data_with_proof_from_path(
            &mut **self,
            hash,
        )
    }

    fn set_block_hash(&mut self, bhh: StacksBlockId) -> InterpreterResult<StacksBlockId> {
        <dyn WritableMarfStore as ClarityBackingStore>::set_block_hash(&mut **self, bhh)
    }

    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId> {
        <dyn WritableMarfStore as ClarityBackingStore>::get_block_at_height(&mut **self, height)
    }

    fn get_current_block_height(&mut self) -> u32 {
        <dyn WritableMarfStore as ClarityBackingStore>::get_current_block_height(&mut **self)
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        <dyn WritableMarfStore as ClarityBackingStore>::get_open_chain_tip_height(&mut **self)
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        <dyn WritableMarfStore as ClarityBackingStore>::get_open_chain_tip(&mut **self)
    }

    fn get_side_store(&mut self) -> &Connection {
        <dyn WritableMarfStore as ClarityBackingStore>::get_side_store(&mut **self)
    }

    fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        <dyn WritableMarfStore as ClarityBackingStore>::get_cc_special_cases_handler(&**self)
    }

    fn get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> InterpreterResult<(StacksBlockId, Sha512Trunc256Sum)> {
        <dyn WritableMarfStore as ClarityBackingStore>::get_contract_hash(&mut **self, contract)
    }

    fn insert_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
        value: &str,
    ) -> InterpreterResult<()> {
        <dyn WritableMarfStore as ClarityBackingStore>::insert_metadata(
            &mut **self,
            contract,
            key,
            value,
        )
    }

    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> InterpreterResult<Option<String>> {
        <dyn WritableMarfStore as ClarityBackingStore>::get_metadata(&mut **self, contract, key)
    }

    fn get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> InterpreterResult<Option<String>> {
        <dyn WritableMarfStore as ClarityBackingStore>::get_metadata_manual(
            &mut **self,
            at_height,
            contract,
            key,
        )
    }
}

impl<'a> ClarityMarfStore for Box<dyn WritableMarfStore + 'a> {}
impl<'a> WritableMarfStore for Box<dyn WritableMarfStore + 'a> {}
