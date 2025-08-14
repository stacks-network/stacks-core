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
    ) -> WritableMarfStore<'a> {
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

        WritableMarfStore::Persistent(PersistentWritableMarfStore {
            chain_tip,
            marf: tx,
        })
    }

    pub fn begin_unconfirmed<'a>(&'a mut self, current: &StacksBlockId) -> WritableMarfStore<'a> {
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

        WritableMarfStore::Persistent(PersistentWritableMarfStore {
            chain_tip,
            marf: tx,
        })
    }

    /// Begin an ephemeral MARF block.
    /// The data will never hit disk.
    pub fn begin_ephemeral<'a>(
        &'a mut self,
        base_tip: &StacksBlockId,
        ephemeral_next: &StacksBlockId,
    ) -> InterpreterResult<WritableMarfStore<'a>> {
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

        test_debug!(
            "Begin ephemeral WritableMarfStore {} --> {}",
            base_tip,
            ephemeral_next
        );
        Ok(WritableMarfStore::Ephemeral(ephemeral_marf_store))
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

/// Unified API for disk-only and ephemeral writable MARF stores
pub enum WritableMarfStore<'a> {
    Persistent(PersistentWritableMarfStore<'a>),
    Ephemeral(EphemeralMarfStore<'a>),
}

impl ReadOnlyMarfStore<'_> {
    pub fn as_clarity_db<'b>(
        &'b mut self,
        headers_db: &'b dyn HeadersDB,
        burn_state_db: &'b dyn BurnStateDB,
    ) -> ClarityDatabase<'b> {
        ClarityDatabase::new(self, headers_db, burn_state_db)
    }

    pub fn as_analysis_db(&mut self) -> AnalysisDatabase<'_> {
        AnalysisDatabase::new(self)
    }

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
        test_debug!("ReadOnly MarfedKV get: {:?} tip={}", key, &self.chain_tip);
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
                test_debug!(
                    "ReadOnly MarfedKV get side-key for {:?}: {:?}",
                    key,
                    &side_key
                );
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
        let res = sqlite_get_contract_hash(self, contract)?;
        test_debug!(
            "ReadOnly MarfedKV: get contract hash of {}: {:?}",
            contract,
            &res
        );
        Ok(res)
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
        let md = sqlite_get_metadata(self, contract, key)?;
        test_debug!(
            "ReadOnly MarfedKV: get metadata for {}: {} --> {:?}",
            contract,
            key,
            &md
        );
        Ok(md)
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
    pub fn as_clarity_db<'b>(
        &'b mut self,
        headers_db: &'b dyn HeadersDB,
        burn_state_db: &'b dyn BurnStateDB,
    ) -> ClarityDatabase<'b> {
        ClarityDatabase::new(self, headers_db, burn_state_db)
    }

    pub fn as_analysis_db(&mut self) -> AnalysisDatabase<'_> {
        AnalysisDatabase::new(self)
    }

    pub fn rollback_block(self) {
        self.marf.drop_current();
    }

    pub fn rollback_unconfirmed(self) -> InterpreterResult<()> {
        debug!("Drop unconfirmed MARF trie {}", &self.chain_tip);
        SqliteConnection::drop_metadata(self.marf.sqlite_tx(), &self.chain_tip)?;
        self.marf.drop_unconfirmed();
        Ok(())
    }

    pub fn commit_to(self, final_bhh: &StacksBlockId) -> InterpreterResult<()> {
        debug!("commit_to({})", final_bhh);
        SqliteConnection::commit_metadata_to(self.marf.sqlite_tx(), &self.chain_tip, final_bhh)?;

        let _ = self.marf.commit_to(final_bhh).map_err(|e| {
            error!("Failed to commit to MARF block {}: {:?}", &final_bhh, &e);
            InterpreterError::Expect("Failed to commit to MARF block".into())
        })?;
        Ok(())
    }

    #[cfg(test)]
    pub fn test_commit(self) {
        let bhh = self.chain_tip.clone();
        self.commit_to(&bhh).unwrap();
    }

    pub fn commit_unconfirmed(self) {
        debug!("commit_unconfirmed()");
        // NOTE: Can omit commit_metadata_to, since the block header hash won't change
        // commit_metadata_to(&self.chain_tip, final_bhh);
        self.marf
            .commit()
            .expect("ERROR: Failed to commit MARF block");
    }

    // This is used by miners
    //   so that the block validation and processing logic doesn't
    //   reprocess the same data as if it were already loaded
    pub fn commit_mined_block(self, will_move_to: &StacksBlockId) -> InterpreterResult<()> {
        debug!(
            "commit_mined_block: ({}->{})",
            &self.chain_tip, will_move_to
        );
        // rollback the side_store
        //    the side_store shouldn't commit data for blocks that won't be
        //    included in the processed chainstate (like a block constructed during mining)
        //    _if_ for some reason, we do want to be able to access that mined chain state in the future,
        //    we should probably commit the data to a different table which does not have uniqueness constraints.
        SqliteConnection::drop_metadata(self.marf.sqlite_tx(), &self.chain_tip)?;
        let _ = self.marf.commit_mined(will_move_to).map_err(|e| {
            error!(
                "Failed to commit to mined MARF block {}: {:?}",
                &will_move_to, &e
            );
            InterpreterError::Expect("Failed to commit to MARF block".into())
        })?;
        Ok(())
    }

    pub fn seal(&mut self) -> TrieHash {
        self.marf.seal().expect("FATAL: failed to .seal() MARF")
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
        let mut keys = Vec::new();
        let mut values = Vec::new();
        for (key, value) in items.into_iter() {
            trace!("MarfedKV put '{}' = '{}'", &key, &value);
            let marf_value = MARFValue::from_value(&value);
            SqliteConnection::put(self.get_side_store(), &marf_value.to_hex(), &value)?;
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
    pub fn new(
        read_only_marf: ReadOnlyMarfStore<'a>,
        ephemeral_marf_tx: MarfTransaction<'a, StacksBlockId>,
    ) -> Result<Self, Error> {
        let base_tip_height = read_only_marf
            .marf
            .get_block_height_of(&read_only_marf.chain_tip, &read_only_marf.chain_tip)?
            .ok_or(Error::NotOpenedError)?;
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

    /// Instantiate a handle to the ClarityDB from this ephemeral MARF, using the given HeadersDB
    /// and BurnStateDB
    pub fn as_clarity_db<'b>(
        &'b mut self,
        headers_db: &'b dyn HeadersDB,
        burn_state_db: &'b dyn BurnStateDB,
    ) -> ClarityDatabase<'b> {
        ClarityDatabase::new(self, headers_db, burn_state_db)
    }

    /// Instantiate a handle to the analysis DB from this ephemeral MARF
    pub fn as_analysis_db(&mut self) -> AnalysisDatabase<'_> {
        AnalysisDatabase::new(self)
    }

    /// Drop the block being built in the ephemeral MARF
    pub fn rollback_block(self) {
        self.ephemeral_marf.drop_current();
    }

    /// Drop any unconfirmed block being built in the ephemeral MARF.
    /// Returns Ok(()) on success
    /// Returns Err(..) on DB failure.
    pub fn rollback_unconfirmed(self) -> InterpreterResult<()> {
        if let Some(tip) = self.ephemeral_marf.get_open_chain_tip() {
            debug!("Drop unconfirmed MARF trie {}", tip);
            self.teardown_views();
            SqliteConnection::drop_metadata(self.ephemeral_marf.sqlite_tx(), tip)?;
            self.setup_views();
            self.ephemeral_marf.drop_unconfirmed();
        }
        Ok(())
    }

    /// Commit the ephemeral MARF block using the given identifier `final_bhh`.
    /// Returns Ok(()) on success
    /// Returns Err(InterpreterError::Expect) if the inner commit fails
    /// Returns Err(..) on DB error
    pub fn commit_to(self, final_bhh: &StacksBlockId) -> InterpreterResult<()> {
        if let Some(tip) = self.ephemeral_marf.get_open_chain_tip() {
            debug!("commit_to({})", final_bhh);
            self.teardown_views();
            SqliteConnection::commit_metadata_to(self.ephemeral_marf.sqlite_tx(), tip, final_bhh)?;
            self.setup_views();

            let _ = self.ephemeral_marf.commit_to(final_bhh).map_err(|e| {
                error!(
                    "Failed to commit to ephemeral MARF block {}: {:?}",
                    &final_bhh, &e
                );
                InterpreterError::Expect("Failed to commit to MARF block".into())
            })?;
        }
        Ok(())
    }

    /// Test helper to commit ephemeral MARF block data using the open chain tip as the final
    /// identifier
    #[cfg(test)]
    pub fn test_commit(self) {
        if let Some(tip) = self.ephemeral_marf.get_open_chain_tip() {
            let bhh = tip.clone();
            self.commit_to(&bhh).unwrap();
        }
    }

    /// Commit an unconfirmed block to the ephemeral MARF
    pub fn commit_unconfirmed(self) {
        debug!("commit_unconfirmed()");
        // NOTE: Can omit commit_metadata_to, since the block header hash won't change
        // commit_metadata_to(&self.chain_tip, final_bhh);
        self.ephemeral_marf
            .commit()
            .expect("ERROR: Failed to commit MARF block");
    }

    /// Commit a mined block with the given identifier `will_move_to`.
    /// This is used by miners so that the block validation and processing logic doesn't
    /// reprocess the same data as if it were already loaded.
    /// Returns Ok((()) on success
    /// Returns Err(InterpreterError::Expect) if the inner commit fails
    /// Returns Err(..) on DB error
    pub fn commit_mined_block(self, will_move_to: &StacksBlockId) -> InterpreterResult<()> {
        if let Some(tip) = self.ephemeral_marf.get_open_chain_tip() {
            debug!("commit_mined_block: ({}->{})", tip, will_move_to);
            // rollback the side_store
            //    the side_store shouldn't commit data for blocks that won't be
            //    included in the processed chainstate (like a block constructed during mining)
            //    _if_ for some reason, we do want to be able to access that mined chain state in the future,
            //    we should probably commit the data to a different table which does not have uniqueness constraints.
            self.teardown_views();
            SqliteConnection::drop_metadata(self.ephemeral_marf.sqlite_tx(), tip)?;
            self.setup_views();
            let _ = self
                .ephemeral_marf
                .commit_mined(will_move_to)
                .map_err(|e| {
                    error!(
                        "Failed to commit to mined MARF block {}: {:?}",
                        &will_move_to, &e
                    );
                    InterpreterError::Expect("Failed to commit to MARF block".into())
                })?;
        }
        Ok(())
    }

    /// Seal the block being built. Compute each MARF node hash and return the root hash.
    /// Do not call more than once; this will cause a runtime panic.
    pub fn seal(&mut self) -> TrieHash {
        self.ephemeral_marf
            .seal()
            .expect("FATAL: failed to .seal() MARF")
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
        test_debug!("Ephemeral MarfedKV get: {:?} tip={:?}", key, &self.open_tip);
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
                    test_debug!("Ephemeral MarfedKV get side-key for {:?}: {:?}", key, &side_key);
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

        test_debug!(
            "Ephemeral MarfedKV get: {:?} tip={:?} not mapped, falling back to read-only store",
            key,
            &self.open_tip
        );
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
                + self.base_tip_height;
        }

        self.read_only_marf.get_open_chain_tip_height()
    }

    /// Get the block height of the current open chain tip.
    /// If the tip points to the ephemeral MARF, then use that MARF.
    /// Otherwise, use the disk-backed one.
    fn get_current_block_height(&mut self) -> u32 {
        let height_opt = if let EphemeralTip::RAM(tip) = &self.open_tip {
            match self.ephemeral_marf.get_block_height_of(tip, tip) {
                Ok(Some(x)) => Some(x + self.base_tip_height),
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
            trace!("Ephemeral MarfedKV put '{}' = '{}'", &key, &value);
            let marf_value = MARFValue::from_value(&value);
            SqliteConnection::put(self.get_side_store(), &marf_value.to_hex(), &value)
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
        let res = sqlite_get_contract_hash(self, contract)?;
        test_debug!(
            "Ephemeral MarfedKV: get contract hash of {}: {:?}",
            contract,
            &res
        );
        Ok(res)
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
        let md = sqlite_get_metadata(self, contract, key)?;
        test_debug!(
            "Ephemeral MarfedKV: get metadata for {}: {} --> {:?}",
            contract,
            key,
            &md
        );
        Ok(md)
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

/// Unified API for writable MARF storage
impl<'a> WritableMarfStore<'a> {
    pub fn as_clarity_db<'b>(
        &'b mut self,
        headers_db: &'b dyn HeadersDB,
        burn_state_db: &'b dyn BurnStateDB,
    ) -> ClarityDatabase<'b> {
        match self {
            Self::Persistent(p) => p.as_clarity_db(headers_db, burn_state_db),
            Self::Ephemeral(e) => e.as_clarity_db(headers_db, burn_state_db),
        }
    }

    pub fn as_analysis_db(&mut self) -> AnalysisDatabase<'_> {
        match self {
            Self::Persistent(p) => p.as_analysis_db(),
            Self::Ephemeral(e) => e.as_analysis_db(),
        }
    }

    pub fn rollback_block(self) {
        match self {
            Self::Persistent(p) => p.rollback_block(),
            Self::Ephemeral(e) => e.rollback_block(),
        }
    }

    pub fn rollback_unconfirmed(self) -> InterpreterResult<()> {
        match self {
            Self::Persistent(p) => p.rollback_unconfirmed(),
            Self::Ephemeral(e) => e.rollback_unconfirmed(),
        }
    }

    pub fn commit_to(self, final_bhh: &StacksBlockId) -> InterpreterResult<()> {
        match self {
            Self::Persistent(p) => p.commit_to(final_bhh),
            Self::Ephemeral(e) => e.commit_to(final_bhh),
        }
    }

    #[cfg(test)]
    pub fn test_commit(self) {
        match self {
            Self::Persistent(p) => p.test_commit(),
            Self::Ephemeral(e) => e.test_commit(),
        }
    }

    pub fn commit_unconfirmed(self) {
        match self {
            Self::Persistent(p) => p.commit_unconfirmed(),
            Self::Ephemeral(e) => e.commit_unconfirmed(),
        }
    }

    pub fn commit_mined_block(self, will_move_to: &StacksBlockId) -> InterpreterResult<()> {
        match self {
            Self::Persistent(p) => p.commit_mined_block(will_move_to),
            Self::Ephemeral(e) => e.commit_mined_block(will_move_to),
        }
    }

    pub fn seal(&mut self) -> TrieHash {
        match self {
            Self::Persistent(p) => p.seal(),
            Self::Ephemeral(e) => e.seal(),
        }
    }
}

impl ClarityBackingStore for WritableMarfStore<'_> {
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> InterpreterResult<StacksBlockId> {
        match self {
            Self::Persistent(p) => p.set_block_hash(bhh),
            Self::Ephemeral(e) => e.set_block_hash(bhh),
        }
    }

    fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        match self {
            Self::Persistent(p) => p.get_cc_special_cases_handler(),
            Self::Ephemeral(e) => e.get_cc_special_cases_handler(),
        }
    }

    fn get_data(&mut self, key: &str) -> InterpreterResult<Option<String>> {
        match self {
            Self::Persistent(p) => p.get_data(key),
            Self::Ephemeral(e) => e.get_data(key),
        }
    }

    fn get_data_from_path(&mut self, hash: &TrieHash) -> InterpreterResult<Option<String>> {
        match self {
            Self::Persistent(p) => p.get_data_from_path(hash),
            Self::Ephemeral(e) => e.get_data_from_path(hash),
        }
    }

    fn get_data_with_proof(&mut self, key: &str) -> InterpreterResult<Option<(String, Vec<u8>)>> {
        match self {
            Self::Persistent(p) => p.get_data_with_proof(key),
            Self::Ephemeral(e) => e.get_data_with_proof(key),
        }
    }

    fn get_data_with_proof_from_path(
        &mut self,
        hash: &TrieHash,
    ) -> InterpreterResult<Option<(String, Vec<u8>)>> {
        match self {
            Self::Persistent(p) => p.get_data_with_proof_from_path(hash),
            Self::Ephemeral(e) => e.get_data_with_proof_from_path(hash),
        }
    }

    fn get_side_store(&mut self) -> &Connection {
        match self {
            Self::Persistent(p) => p.get_side_store(),
            Self::Ephemeral(e) => e.get_side_store(),
        }
    }

    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId> {
        match self {
            Self::Persistent(p) => p.get_block_at_height(height),
            Self::Ephemeral(e) => e.get_block_at_height(height),
        }
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        match self {
            Self::Persistent(p) => p.get_open_chain_tip(),
            Self::Ephemeral(e) => e.get_open_chain_tip(),
        }
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        match self {
            Self::Persistent(p) => p.get_open_chain_tip_height(),
            Self::Ephemeral(e) => e.get_open_chain_tip_height(),
        }
    }

    fn get_current_block_height(&mut self) -> u32 {
        match self {
            Self::Persistent(p) => p.get_current_block_height(),
            Self::Ephemeral(e) => e.get_current_block_height(),
        }
    }

    fn put_all_data(&mut self, items: Vec<(String, String)>) -> InterpreterResult<()> {
        match self {
            Self::Persistent(p) => p.put_all_data(items),
            Self::Ephemeral(e) => e.put_all_data(items),
        }
    }

    fn get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> InterpreterResult<(StacksBlockId, Sha512Trunc256Sum)> {
        match self {
            Self::Persistent(p) => p.get_contract_hash(contract),
            Self::Ephemeral(e) => e.get_contract_hash(contract),
        }
    }

    fn insert_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
        value: &str,
    ) -> InterpreterResult<()> {
        match self {
            Self::Persistent(p) => p.insert_metadata(contract, key, value),
            Self::Ephemeral(e) => e.insert_metadata(contract, key, value),
        }
    }

    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> InterpreterResult<Option<String>> {
        match self {
            Self::Persistent(p) => p.get_metadata(contract, key),
            Self::Ephemeral(e) => e.get_metadata(contract, key),
        }
    }

    fn get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> InterpreterResult<Option<String>> {
        match self {
            Self::Persistent(p) => p.get_metadata_manual(at_height, contract, key),
            Self::Ephemeral(e) => e.get_metadata_manual(at_height, contract, key),
        }
    }
}
