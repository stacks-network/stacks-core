// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::thread;

#[cfg(test)]
use clarity::consts::CHAIN_ID_TESTNET;
use clarity::vm::analysis::AnalysisDatabase;
use clarity::vm::clarity::TransactionConnection;
pub use clarity::vm::clarity::{ClarityConnection, ClarityError};
use clarity::vm::contexts::{AssetMap, OwnedEnvironment};
use clarity::vm::costs::{CostTracker, ExecutionCost, LimitedCostTracker};
use clarity::vm::database::{
    BurnStateDB, ClarityBackingStore, ClarityDatabase, HeadersDB, RollbackWrapper,
    RollbackWrapperPersistedLog, STXBalance, NULL_BURN_STATE_DB, NULL_HEADER_DB,
};
use clarity::vm::errors::VmExecutionError;
use clarity::vm::events::{STXEventType, STXMintEventData};
use clarity::vm::representations::SymbolicExpression;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, Value};
use clarity::vm::{ClarityVersion, ContractName};
use stacks_common::consts::SIGNER_SLOTS_PER_USER;
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};

use crate::burnchains::PoxConstants;
use crate::chainstate::nakamoto::signer_set::NakamotoSigners;
use crate::chainstate::stacks::boot::{
    make_sip_031_body, BOOT_CODE_COSTS, BOOT_CODE_COSTS_2, BOOT_CODE_COSTS_2_TESTNET,
    BOOT_CODE_COSTS_3, BOOT_CODE_COSTS_4, BOOT_CODE_COST_VOTING_TESTNET as BOOT_CODE_COST_VOTING,
    BOOT_CODE_POX_TESTNET, COSTS_2_NAME, COSTS_3_NAME, COSTS_4_NAME, POX_2_MAINNET_CODE,
    POX_2_NAME, POX_2_TESTNET_CODE, POX_3_MAINNET_CODE, POX_3_NAME, POX_3_TESTNET_CODE, POX_4_CODE,
    POX_4_NAME, SIGNERS_BODY, SIGNERS_DB_0_BODY, SIGNERS_DB_1_BODY, SIGNERS_NAME,
    SIGNERS_VOTING_BODY, SIGNERS_VOTING_NAME, SIP_031_NAME,
};
use crate::chainstate::stacks::db::{StacksAccount, StacksChainState};
use crate::chainstate::stacks::events::{StacksTransactionEvent, StacksTransactionReceipt};
use crate::chainstate::stacks::index::marf::MARF;
use crate::chainstate::stacks::{
    Error as ChainstateError, StacksMicroblockHeader, StacksTransaction, TransactionPayload,
    TransactionSmartContract, TransactionVersion,
};
use crate::clarity_vm::database::marf::{
    BoxedClarityMarfStoreTransaction, MarfedKV, ReadOnlyMarfStore,
};
use crate::core::{StacksEpoch, StacksEpochId, FIRST_STACKS_BLOCK_ID, GENESIS_EPOCH};
use crate::util_lib::boot::{boot_code_acc, boot_code_addr, boot_code_id, boot_code_tx_auth};
use crate::util_lib::db::Error as DatabaseError;
use crate::util_lib::strings::StacksString;

pub const SIP_031_INITIAL_MINT: u128 = 200_000_000_000_000;

///
/// A high-level interface for interacting with the Clarity VM.
///
/// ClarityInstance takes ownership of a MARF + Sqlite store used for
///   it's data operations.
/// The ClarityInstance defines a `begin_block(bhh, bhh, bhh) -> ClarityBlockConnection`
///    function.
/// ClarityBlockConnections are used for executing transactions within the context of
///    a single block.
/// Only one ClarityBlockConnection may be open at a time (enforced by the borrow checker)
///   and ClarityBlockConnections must be `commit_block`ed or `rollback_block`ed before discarding
///   begining the next connection (enforced by runtime panics).
///
/// Note on generics and abstracting the structs in `clarity_vm::clarity` into `libclarity`: while
///   multiple consumers of `libclarity` may need a high-level interface like
///   instance -> block -> transaction, their lifetime parameters make the use of rust traits very
///   difficult (in all likelihood, it would require higher-ordered traits, which is a
///   discussed-but-not-yet-implemented feature of rust). Instead, consumers of `libclarity` which
///   wish to benefit from some abstraction of high-level interfaces should implement the
///   `TransactionConnection` trait, which contains auto implementations for the typical transaction
///   types in a Clarity-based blockchain.
///
pub struct ClarityInstance {
    datastore: MarfedKV,
    mainnet: bool,
    chain_id: u32,
}

///
/// This struct represents a "sealed" or "finished" Clarity block that
/// has *not* yet been committed. This struct allows consumers of the
/// `clarity_vm` module's high level interface to separate the
/// completion of the Clarity operations in a Stacks block from the
/// final commit to the database.
///
/// This is necessary to allow callers complete other operations like
/// preparing a commitment to the chainstate headers MARF, and
/// issuring event dispatches, before the Clarity database commits.
///
pub struct PreCommitClarityBlock<'a> {
    datastore: Box<dyn WritableMarfStore + 'a>,
    commit_to: StacksBlockId,
}

///
/// A high-level interface for Clarity VM interactions within a single block.
///
pub struct ClarityBlockConnection<'a, 'b> {
    datastore: Box<dyn WritableMarfStore + 'a>,
    header_db: &'b dyn HeadersDB,
    burn_state_db: &'b dyn BurnStateDB,
    cost_track: Option<LimitedCostTracker>,
    mainnet: bool,
    chain_id: u32,
    epoch: StacksEpochId,
}

///
/// Interface for Clarity VM interactions within a given transaction.
///
///   commit the transaction to the block with .commit()
///   rollback the transaction by dropping this struct.
pub struct ClarityTransactionConnection<'a, 'b> {
    log: Option<RollbackWrapperPersistedLog>,
    store: &'b mut dyn ClarityBackingStore,
    header_db: &'a dyn HeadersDB,
    burn_state_db: &'a dyn BurnStateDB,
    cost_track: &'a mut Option<LimitedCostTracker>,
    mainnet: bool,
    chain_id: u32,
    epoch: StacksEpochId,
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
    fn commit_metadata_for_trie(&mut self, target: &StacksBlockId) -> Result<(), VmExecutionError>;

    /// Drop metadata for a particular block trie that was stored previously via `commit_metadata_to()`.
    /// This function is idempotent.
    ///
    /// Returns Ok(()) if the metadata for the trie identified by `target` was dropped.
    /// It will be possible to insert it again afterwards.
    /// Returns Err(..) if the metadata was not successfully dropped.
    fn drop_metadata_for_trie(&mut self, target: &StacksBlockId) -> Result<(), VmExecutionError>;

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
    fn drop_unconfirmed(self) -> Result<(), VmExecutionError>;

    /// Store the processed block's trie that this transaction was creating.
    /// The trie's ID must be `target`, so that subsequent tries can be built on it (and so that
    /// subsequent queries can read from it).  `target` may not be known until it is time to write
    /// the trie out, which is why it is provided here.
    ///
    /// Returns Ok(()) if the block trie was successfully persisted.
    /// Returns Err(..) if there was an error in trying to persist this block trie.
    fn commit_to_processed_block(self, target: &StacksBlockId) -> Result<(), VmExecutionError>;

    /// Store a mined block's trie that this transaction was creating.
    /// This function is distinct from `commit_to_processed_block()` in that the stored block will
    /// not be added to the chainstate. However, it must be persisted so that the node can later
    /// build on it.
    ///
    /// Returns Ok(()) if the block trie was successfully persisted.
    /// Returns Err(..) if there was an error trying to persist this MARF trie.
    fn commit_to_mined_block(self, target: &StacksBlockId) -> Result<(), VmExecutionError>;

    /// Persist the unconfirmed state trie so that other parts of the Stacks node can read from it
    /// (such as to handle pending transactions or process RPC requests on it).
    fn commit_unconfirmed(self);

    /// Commit to the current chain tip.
    /// Used only for testing.
    #[cfg(test)]
    fn test_commit(self);
}

impl<'a, 'b> ClarityTransactionConnection<'a, 'b> {
    pub fn new(
        store: &'b mut dyn ClarityBackingStore,
        header_db: &'a dyn HeadersDB,
        burn_state_db: &'a dyn BurnStateDB,
        cost_track: &'a mut Option<LimitedCostTracker>,
        mainnet: bool,
        chain_id: u32,
        epoch: StacksEpochId,
    ) -> ClarityTransactionConnection<'a, 'b> {
        let mut log = RollbackWrapperPersistedLog::new();
        log.nest();
        ClarityTransactionConnection {
            log: Some(log),
            store,
            header_db,
            burn_state_db,
            cost_track,
            mainnet,
            chain_id,
            epoch,
        }
    }
}

pub struct ClarityReadOnlyConnection<'a> {
    datastore: ReadOnlyMarfStore<'a>,
    header_db: &'a dyn HeadersDB,
    burn_state_db: &'a dyn BurnStateDB,
    epoch: StacksEpochId,
}

impl From<ChainstateError> for ClarityError {
    fn from(e: ChainstateError) -> Self {
        match e {
            ChainstateError::InvalidStacksTransaction(msg, _) => ClarityError::BadTransaction(msg),
            ChainstateError::CostOverflowError(_, after, budget) => {
                ClarityError::CostError(after, budget)
            }
            ChainstateError::ClarityError(x) => x,
            x => ClarityError::BadTransaction(x.to_string()),
        }
    }
}

/// A macro for doing take/replace on a closure.
///   macro is needed rather than a function definition because
///   otherwise, we end up breaking the borrow checker when
///   passing a mutable reference across a function boundary.
macro_rules! using {
    ($to_use: expr, $msg: expr, $exec: expr) => {{
        let object = $to_use.take().expect(&format!(
            "BUG: Transaction connection lost {} handle.",
            $msg
        ));
        let (object, result) = ($exec)(object);
        $to_use.replace(object);
        result
    }};
}

impl ClarityBlockConnection<'_, '_> {
    #[cfg(test)]
    pub fn new_test_conn<'a, 'b>(
        datastore: Box<dyn WritableMarfStore + 'a>,
        header_db: &'b dyn HeadersDB,
        burn_state_db: &'b dyn BurnStateDB,
        epoch: StacksEpochId,
    ) -> ClarityBlockConnection<'a, 'b> {
        ClarityBlockConnection {
            datastore,
            header_db,
            burn_state_db,
            cost_track: Some(LimitedCostTracker::new_free()),
            mainnet: false,
            chain_id: CHAIN_ID_TESTNET,
            epoch,
        }
    }

    /// Reset the block's total execution to the given cost, if there is a cost tracker at all.
    /// Used by the miner to "undo" applying a transaction that exceeded the budget.
    pub fn reset_block_cost(&mut self, cost: ExecutionCost) {
        if let Some(ref mut cost_tracker) = self.cost_track {
            cost_tracker.set_total(cost);
        }
    }

    pub fn set_cost_tracker(&mut self, tracker: LimitedCostTracker) -> LimitedCostTracker {
        let old = self
            .cost_track
            .take()
            .expect("BUG: Clarity block connection lost cost tracker instance");
        self.cost_track.replace(tracker);
        old
    }

    /// Get the current cost so far
    pub fn cost_so_far(&self) -> ExecutionCost {
        match self.cost_track {
            Some(ref track) => track.get_total(),
            None => ExecutionCost::ZERO,
        }
    }

    /// Returns the block limit for the block being created.
    pub fn block_limit(&self) -> Option<ExecutionCost> {
        match self.cost_track {
            Some(ref track) => Some(track.get_limit()),
            None => None,
        }
    }

    /// Load the epoch ID from the clarity DB.
    /// Used to sanity-check epoch transitions.
    pub fn get_clarity_db_epoch_version(
        &mut self,
        burn_state_db: &dyn BurnStateDB,
    ) -> Result<StacksEpochId, ClarityError> {
        let mut db = self.datastore.as_clarity_db(self.header_db, burn_state_db);
        // NOTE: the begin/roll_back shouldn't be necessary with how this gets used in practice,
        // but is put here defensively.
        db.begin();
        let result = db.get_clarity_epoch_version();
        db.roll_back()?;
        Ok(result?)
    }
}

impl ClarityInstance {
    pub fn new(mainnet: bool, chain_id: u32, datastore: MarfedKV) -> ClarityInstance {
        ClarityInstance {
            datastore,
            mainnet,
            chain_id,
        }
    }

    pub fn with_marf<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut MARF<StacksBlockId>) -> R,
    {
        f(self.datastore.get_marf())
    }

    pub fn is_mainnet(&self) -> bool {
        self.mainnet
    }

    /// Returns the Stacks epoch of the burn block that elected `stacks_block`
    fn get_epoch_of(
        stacks_block: &StacksBlockId,
        header_db: &dyn HeadersDB,
        burn_state_db: &dyn BurnStateDB,
    ) -> StacksEpoch {
        // Special case the first Stacks block -- it is not elected in any burn block
        //  so we specifically set its epoch to GENESIS_EPOCH.
        if stacks_block == &*FIRST_STACKS_BLOCK_ID {
            return burn_state_db
                .get_stacks_epoch_by_epoch_id(&GENESIS_EPOCH)
                .expect("Failed to obtain the Genesis StacksEpoch");
        }

        let burn_height = header_db
            .get_burn_block_height_for_block(stacks_block)
            .unwrap_or_else(|| panic!("Failed to get burn block height of {}", stacks_block));
        burn_state_db
            .get_stacks_epoch(burn_height)
            .unwrap_or_else(|| panic!("Failed to get Stacks epoch for height = {}", burn_height))
    }

    pub fn begin_block<'a, 'b>(
        &'a mut self,
        current: &StacksBlockId,
        next: &StacksBlockId,
        header_db: &'b dyn HeadersDB,
        burn_state_db: &'b dyn BurnStateDB,
    ) -> ClarityBlockConnection<'a, 'b> {
        let mut datastore = self.datastore.begin(current, next);

        let epoch = Self::get_epoch_of(current, header_db, burn_state_db);
        let cost_track = {
            let mut clarity_db = datastore.as_clarity_db(&NULL_HEADER_DB, &NULL_BURN_STATE_DB);
            Some(
                LimitedCostTracker::new(
                    self.mainnet,
                    self.chain_id,
                    epoch.block_limit.clone(),
                    &mut clarity_db,
                    epoch.epoch_id,
                )
                .expect("FAIL: problem instantiating cost tracking"),
            )
        };

        ClarityBlockConnection {
            datastore: Box::new(datastore),
            header_db,
            burn_state_db,
            cost_track,
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            epoch: epoch.epoch_id,
        }
    }

    pub fn begin_genesis_block<'a, 'b>(
        &'a mut self,
        current: &StacksBlockId,
        next: &StacksBlockId,
        header_db: &'b dyn HeadersDB,
        burn_state_db: &'b dyn BurnStateDB,
    ) -> ClarityBlockConnection<'a, 'b> {
        let datastore = self.datastore.begin(current, next);

        let epoch = GENESIS_EPOCH;

        let cost_track = Some(LimitedCostTracker::new_free());

        ClarityBlockConnection {
            datastore: Box::new(datastore),
            header_db,
            burn_state_db,
            cost_track,
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            epoch,
        }
    }

    /// begin a genesis block with the default cost contract
    ///  used in testing + benchmarking
    pub fn begin_test_genesis_block<'a, 'b>(
        &'a mut self,
        current: &StacksBlockId,
        next: &StacksBlockId,
        header_db: &'b dyn HeadersDB,
        burn_state_db: &'b dyn BurnStateDB,
    ) -> ClarityBlockConnection<'a, 'b> {
        let writable = self.datastore.begin(current, next);

        let epoch = GENESIS_EPOCH;

        let cost_track = Some(LimitedCostTracker::new_free());

        let mut conn = ClarityBlockConnection {
            datastore: Box::new(writable),
            header_db,
            burn_state_db,
            cost_track,
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            epoch,
        };

        let use_mainnet = self.mainnet;
        conn.as_transaction(|clarity_db| {
            let (ast, _analysis) = clarity_db
                .analyze_smart_contract(
                    &boot_code_id("costs", use_mainnet),
                    ClarityVersion::Clarity1,
                    BOOT_CODE_COSTS,
                )
                .unwrap();
            clarity_db
                .initialize_smart_contract(
                    &boot_code_id("costs", use_mainnet),
                    ClarityVersion::Clarity1,
                    &ast,
                    BOOT_CODE_COSTS,
                    None,
                    |_, _| None,
                    None,
                )
                .unwrap();
        });

        conn.as_transaction(|clarity_db| {
            let (ast, analysis) = clarity_db
                .analyze_smart_contract(
                    &boot_code_id("cost-voting", use_mainnet),
                    ClarityVersion::Clarity1,
                    &*BOOT_CODE_COST_VOTING,
                )
                .unwrap();
            clarity_db
                .initialize_smart_contract(
                    &boot_code_id("cost-voting", use_mainnet),
                    ClarityVersion::Clarity1,
                    &ast,
                    &*BOOT_CODE_COST_VOTING,
                    None,
                    |_, _| None,
                    None,
                )
                .unwrap();

            clarity_db
                .save_analysis(&boot_code_id("cost-voting", use_mainnet), &analysis)
                .unwrap();
        });

        conn.as_transaction(|clarity_db| {
            let (ast, _analysis) = clarity_db
                .analyze_smart_contract(
                    &boot_code_id("pox", use_mainnet),
                    ClarityVersion::Clarity1,
                    &*BOOT_CODE_POX_TESTNET,
                )
                .unwrap();
            clarity_db
                .initialize_smart_contract(
                    &boot_code_id("pox", use_mainnet),
                    ClarityVersion::Clarity1,
                    &ast,
                    &*BOOT_CODE_POX_TESTNET,
                    None,
                    |_, _| None,
                    None,
                )
                .unwrap();
        });

        conn
    }

    /// begin with a 2.1 genesis block with the default cost contract
    ///  used in testing + benchmarking
    pub fn begin_test_genesis_block_2_1<'a, 'b>(
        &'a mut self,
        current: &StacksBlockId,
        next: &StacksBlockId,
        header_db: &'b dyn HeadersDB,
        burn_state_db: &'b dyn BurnStateDB,
    ) -> ClarityBlockConnection<'a, 'b> {
        let writable = self.datastore.begin(current, next);

        let epoch = StacksEpochId::Epoch21;

        let cost_track = Some(LimitedCostTracker::new_free());

        let mut conn = ClarityBlockConnection {
            datastore: Box::new(writable),
            header_db,
            burn_state_db,
            cost_track,
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            epoch,
        };

        let use_mainnet = self.mainnet;

        conn.as_transaction(|clarity_db| {
            let (ast, _analysis) = clarity_db
                .analyze_smart_contract(
                    &boot_code_id("costs-2", use_mainnet),
                    ClarityVersion::Clarity1,
                    BOOT_CODE_COSTS_2,
                )
                .unwrap();
            clarity_db
                .initialize_smart_contract(
                    &boot_code_id("costs-2", use_mainnet),
                    ClarityVersion::Clarity1,
                    &ast,
                    BOOT_CODE_COSTS_2,
                    None,
                    |_, _| None,
                    None,
                )
                .unwrap();
        });

        conn.as_transaction(|clarity_db| {
            let (ast, _analysis) = clarity_db
                .analyze_smart_contract(
                    &boot_code_id("costs-3", use_mainnet),
                    ClarityVersion::Clarity2,
                    BOOT_CODE_COSTS_3,
                )
                .unwrap();
            clarity_db
                .initialize_smart_contract(
                    &boot_code_id("costs-3", use_mainnet),
                    ClarityVersion::Clarity2,
                    &ast,
                    BOOT_CODE_COSTS_3,
                    None,
                    |_, _| None,
                    None,
                )
                .unwrap();
        });

        conn.as_transaction(|clarity_db| {
            let (ast, _analysis) = clarity_db
                .analyze_smart_contract(
                    &boot_code_id("pox-2", use_mainnet),
                    ClarityVersion::Clarity2,
                    &*POX_2_TESTNET_CODE,
                )
                .unwrap();
            clarity_db
                .initialize_smart_contract(
                    &boot_code_id("pox-2", use_mainnet),
                    ClarityVersion::Clarity2,
                    &ast,
                    &*POX_2_TESTNET_CODE,
                    None,
                    |_, _| None,
                    None,
                )
                .unwrap();
        });

        conn
    }

    pub fn drop_unconfirmed_state(&mut self, block: &StacksBlockId) -> Result<(), ClarityError> {
        let datastore = self.datastore.begin_unconfirmed(block);
        datastore.drop_unconfirmed()?;
        Ok(())
    }

    pub fn begin_unconfirmed<'a, 'b>(
        &'a mut self,
        current: &StacksBlockId,
        header_db: &'b dyn HeadersDB,
        burn_state_db: &'b dyn BurnStateDB,
    ) -> ClarityBlockConnection<'a, 'b> {
        let mut datastore = self.datastore.begin_unconfirmed(current);

        let epoch = Self::get_epoch_of(current, header_db, burn_state_db);

        let cost_track = {
            let mut clarity_db = datastore.as_clarity_db(&NULL_HEADER_DB, &NULL_BURN_STATE_DB);
            Some(
                LimitedCostTracker::new(
                    self.mainnet,
                    self.chain_id,
                    epoch.block_limit.clone(),
                    &mut clarity_db,
                    epoch.epoch_id,
                )
                .expect("FAIL: problem instantiating cost tracking"),
            )
        };

        ClarityBlockConnection {
            datastore: Box::new(datastore),
            header_db,
            burn_state_db,
            cost_track,
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            epoch: epoch.epoch_id,
        }
    }

    /// Begin an ephemeral block, which will not be persisted and which may even already exist in
    /// the chainstate.
    pub fn begin_ephemeral<'a, 'b>(
        &'a mut self,
        base_tip: &StacksBlockId,
        ephemeral_next: &StacksBlockId,
        header_db: &'b dyn HeadersDB,
        burn_state_db: &'b dyn BurnStateDB,
    ) -> ClarityBlockConnection<'a, 'b> {
        let mut datastore = self
            .datastore
            .begin_ephemeral(base_tip, ephemeral_next)
            .expect("FATAL: failed to begin ephemeral block connection");

        let epoch = Self::get_epoch_of(base_tip, header_db, burn_state_db);
        let cost_track = {
            let mut clarity_db = datastore.as_clarity_db(&NULL_HEADER_DB, &NULL_BURN_STATE_DB);
            Some(
                LimitedCostTracker::new(
                    self.mainnet,
                    self.chain_id,
                    epoch.block_limit.clone(),
                    &mut clarity_db,
                    epoch.epoch_id,
                )
                .expect("FAIL: problem instantiating cost tracking"),
            )
        };

        ClarityBlockConnection {
            datastore: Box::new(datastore),
            header_db,
            burn_state_db,
            cost_track,
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            epoch: epoch.epoch_id,
        }
    }

    /// Open a read-only connection at `at_block`. This will be evaluated in the Stacks epoch that
    ///  was active *during* the evaluation of `at_block`
    pub fn read_only_connection<'a>(
        &'a mut self,
        at_block: &StacksBlockId,
        header_db: &'a dyn HeadersDB,
        burn_state_db: &'a dyn BurnStateDB,
    ) -> ClarityReadOnlyConnection<'a> {
        self.read_only_connection_checked(at_block, header_db, burn_state_db)
            .unwrap_or_else(|_| panic!("BUG: failed to open block {}", at_block))
    }

    /// Open a read-only connection at `at_block`. This will be evaluated in the Stacks epoch that
    ///  was active *during* the evaluation of `at_block`
    pub fn read_only_connection_checked<'a>(
        &'a mut self,
        at_block: &StacksBlockId,
        header_db: &'a dyn HeadersDB,
        burn_state_db: &'a dyn BurnStateDB,
    ) -> Result<ClarityReadOnlyConnection<'a>, ClarityError> {
        let mut datastore = self.datastore.begin_read_only_checked(Some(at_block))?;
        let epoch = {
            let mut db = datastore.as_clarity_db(header_db, burn_state_db);
            db.begin();
            let result = db.get_clarity_epoch_version();
            db.roll_back()?;
            result
        }?;

        Ok(ClarityReadOnlyConnection {
            datastore,
            header_db,
            burn_state_db,
            epoch,
        })
    }

    pub fn trie_exists_for_block(&mut self, bhh: &StacksBlockId) -> Result<bool, DatabaseError> {
        let mut datastore = self.datastore.begin_read_only(None);
        datastore.trie_exists_for_block(bhh)
    }

    /// Evaluate program read-only at `at_block`. This will be evaluated in the Stacks epoch that
    ///  was active *during* the evaluation of `at_block`
    pub fn eval_read_only(
        &mut self,
        at_block: &StacksBlockId,
        header_db: &dyn HeadersDB,
        burn_state_db: &dyn BurnStateDB,
        contract: &QualifiedContractIdentifier,
        program: &str,
    ) -> Result<Value, ClarityError> {
        let mut read_only_conn = self.datastore.begin_read_only(Some(at_block));
        let mut clarity_db = read_only_conn.as_clarity_db(header_db, burn_state_db);
        let epoch_id = {
            clarity_db.begin();
            let result = clarity_db.get_clarity_epoch_version();
            clarity_db.roll_back()?;
            result
        }?;

        let mut env = OwnedEnvironment::new_free(self.mainnet, self.chain_id, clarity_db, epoch_id);
        env.eval_read_only(contract, program)
            .map(|(x, _, _)| x)
            .map_err(ClarityError::from)
    }

    pub fn destroy(self) -> MarfedKV {
        self.datastore
    }
}

impl ClarityConnection for ClarityBlockConnection<'_, '_> {
    /// Do something with ownership of the underlying DB that involves only reading.
    fn with_clarity_db_readonly_owned<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(ClarityDatabase) -> (R, ClarityDatabase),
    {
        let mut db = ClarityDatabase::new(&mut self.datastore, self.header_db, self.burn_state_db);
        db.begin();
        let (result, mut db) = to_do(db);
        db.roll_back()
            .expect("FATAL: failed to roll back from read-only context");
        result
    }

    fn with_analysis_db_readonly<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(&mut AnalysisDatabase) -> R,
    {
        let mut db = AnalysisDatabase::new(&mut self.datastore);
        db.begin();
        let result = to_do(&mut db);
        db.roll_back()
            .expect("FATAL: failed to roll back from read-only context");
        result
    }

    fn get_epoch(&self) -> StacksEpochId {
        self.epoch
    }
}

impl ClarityConnection for ClarityReadOnlyConnection<'_> {
    /// Do something with ownership of the underlying DB that involves only reading.
    fn with_clarity_db_readonly_owned<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(ClarityDatabase) -> (R, ClarityDatabase),
    {
        let mut db = self
            .datastore
            .as_clarity_db(self.header_db, self.burn_state_db);
        db.begin();
        let (result, mut db) = to_do(db);
        db.roll_back()
            .expect("FATAL: failed to roll back changes in read-only context");
        result
    }

    fn with_analysis_db_readonly<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(&mut AnalysisDatabase) -> R,
    {
        let mut db = self.datastore.as_analysis_db();
        db.begin();
        let result = to_do(&mut db);
        db.roll_back()
            .expect("FATAL: failed to roll back changes in read-only context");
        result
    }

    fn get_epoch(&self) -> StacksEpochId {
        self.epoch
    }
}

impl PreCommitClarityBlock<'_> {
    pub fn commit(self) {
        debug!("Committing Clarity block connection"; "index_block" => %self.commit_to);
        self.datastore
            .commit_to_processed_block(&self.commit_to)
            .expect("FATAL: failed to commit block");
    }
}

impl<'a, 'b> ClarityBlockConnection<'a, 'b> {
    /// Rolls back all changes in the current block by
    /// (1) dropping all writes from the current MARF tip,
    /// (2) rolling back side-storage
    pub fn rollback_block(self) {
        // this is a "lower-level" rollback than the roll backs performed in
        //   ClarityDatabase or AnalysisDatabase -- this is done at the backing store level.
        debug!("Rollback Clarity datastore");
        self.datastore.drop_current_trie();
    }

    /// Rolls back all unconfirmed state in the current block by
    /// (1) dropping all writes from the current MARF tip,
    /// (2) rolling back side-storage
    pub fn rollback_unconfirmed(self) {
        // this is a "lower-level" rollback than the roll backs performed in
        //   ClarityDatabase or AnalysisDatabase -- this is done at the backing store level.
        debug!("Rollback unconfirmed Clarity datastore");
        self.datastore
            .drop_unconfirmed()
            .expect("FATAL: failed to rollback block");
    }

    /// Commits all changes in the current block by
    /// (1) committing the current MARF tip to storage,
    /// (2) committing side-storage.
    #[cfg(test)]
    pub fn commit_block(self) -> LimitedCostTracker {
        debug!("Commit Clarity datastore");
        self.datastore.test_commit();

        self.cost_track.unwrap()
    }

    pub fn precommit_to_block(self, final_bhh: StacksBlockId) -> PreCommitClarityBlock<'a> {
        self.cost_track
            .expect("Clarity block connection lost cost tracker before commitment");
        PreCommitClarityBlock {
            datastore: self.datastore,
            commit_to: final_bhh,
        }
    }

    /// Commits all changes in the current block by
    /// (1) committing the current MARF tip to storage,
    /// (2) committing side-storage.  Commits to a different
    /// block hash than the one opened (i.e. since the caller
    /// may not have known the "real" block hash at the
    /// time of opening).
    pub fn commit_to_block(self, final_bhh: &StacksBlockId) -> LimitedCostTracker {
        debug!("Commit Clarity datastore to {}", final_bhh);
        self.datastore
            .commit_to_processed_block(final_bhh)
            .expect("FATAL: failed to commit block");

        self.cost_track.unwrap()
    }

    /// Commits all changes in the current block by
    /// (1) committing the current MARF tip to storage,
    /// (2) committing side-storage.
    ///    before this saves, it updates the metadata headers in
    ///    the sidestore so that they don't get stepped on after
    ///    a miner re-executes a constructed block.
    pub fn commit_mined_block(
        self,
        bhh: &StacksBlockId,
    ) -> Result<LimitedCostTracker, ClarityError> {
        debug!("Commit mined Clarity datastore to {}", bhh);
        self.datastore.commit_to_mined_block(bhh)?;

        Ok(self.cost_track.unwrap())
    }

    /// Save all unconfirmed state by
    /// (1) committing the current unconfirmed MARF to storage,
    /// (2) committing side-storage
    /// Unconfirmed data has globally-unique block hashes that are cryptographically derived from a
    /// confirmed block hash, so they're exceedingly unlikely to conflict with existing blocks.
    pub fn commit_unconfirmed(self) -> LimitedCostTracker {
        debug!("Save unconfirmed Clarity datastore");
        self.datastore.commit_unconfirmed();

        self.cost_track.unwrap()
    }

    /// Get the boot code account
    fn get_boot_code_account(&mut self) -> Result<StacksAccount, ClarityError> {
        let boot_code_address = boot_code_addr(self.mainnet);
        let boot_code_nonce = self.with_clarity_db_readonly(|db| {
            db.get_account_nonce(&boot_code_address.clone().into())
        })?;

        let boot_code_account = boot_code_acc(boot_code_address, boot_code_nonce);
        Ok(boot_code_account)
    }

    pub fn initialize_epoch_2_05(&mut self) -> Result<StacksTransactionReceipt, ClarityError> {
        // use the `using!` statement to ensure that the old cost_tracker is placed
        //  back in all branches after initialization
        using!(self.cost_track, "cost tracker", |old_cost_tracker| {
            // epoch initialization is *free*
            self.cost_track.replace(LimitedCostTracker::new_free());

            let mainnet = self.mainnet;

            // get the boot code account information
            //  for processing the pox contract initialization
            let tx_version = if mainnet {
                TransactionVersion::Mainnet
            } else {
                TransactionVersion::Testnet
            };

            let boot_code_account = self
                .get_boot_code_account()
                .expect("FATAL: failed to get boot code account");

            // instantiate costs 2 contract...
            let cost_2_code = if mainnet {
                BOOT_CODE_COSTS_2
            } else {
                BOOT_CODE_COSTS_2_TESTNET
            };

            let payload = TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from(COSTS_2_NAME)
                        .expect("FATAL: invalid boot-code contract name"),
                    code_body: StacksString::from_str(cost_2_code)
                        .expect("FATAL: invalid boot code body"),
                },
                None,
            );

            let boot_code_address = boot_code_addr(self.mainnet);
            let boot_code_auth = boot_code_tx_auth(boot_code_address.clone());

            let costs_2_contract_tx = StacksTransaction::new(tx_version, boot_code_auth, payload);

            let initialization_receipt = self.as_transaction(|tx_conn| {
                // bump the epoch in the Clarity DB
                tx_conn
                    .with_clarity_db(|db| {
                        db.set_clarity_epoch_version(StacksEpochId::Epoch2_05)?;
                        Ok(())
                    })
                    .unwrap();

                // NOTE: we don't set tx_conn.epoch to Epoch2_05 here, even though we probably
                // should, because doing so risks a chain split.  Same for self.epoch.
                // C'est la vie.

                // initialize with a synthetic transaction
                debug!("Instantiate .costs-2 contract");
                StacksChainState::process_transaction_payload(
                    tx_conn,
                    &costs_2_contract_tx,
                    &boot_code_account,
                    None,
                )
                .expect("FATAL: Failed to process PoX 2 contract initialization")
            });

            if initialization_receipt.result != Value::okay_true()
                || initialization_receipt.post_condition_aborted
            {
                panic!(
                    "FATAL: Failure processing Costs 2 contract initialization: {initialization_receipt:#?}"
                );
            }

            // NOTE: we don't set self.epoch to Epoch2_05 here, even though we probably
            // should, because doing so risks a chain split.

            debug!("Epoch 2.05 initialized");
            (old_cost_tracker, Ok(initialization_receipt))
        })
    }

    pub fn initialize_epoch_2_1(&mut self) -> Result<Vec<StacksTransactionReceipt>, ClarityError> {
        // use the `using!` statement to ensure that the old cost_tracker is placed
        //  back in all branches after initialization
        using!(self.cost_track, "cost tracker", |old_cost_tracker| {
            // epoch initialization is *free*.
            // NOTE: this also means that cost functions won't be evaluated.
            // This is important because pox-2 is instantiated before costs-3.
            self.cost_track.replace(LimitedCostTracker::new_free());

            let mainnet = self.mainnet;
            let first_block_height = self.burn_state_db.get_burn_start_height();
            let pox_prepare_length = self.burn_state_db.get_pox_prepare_length();
            let pox_reward_cycle_length = self.burn_state_db.get_pox_reward_cycle_length();
            let pox_rejection_fraction = self.burn_state_db.get_pox_rejection_fraction();

            let v1_unlock_height = self.burn_state_db.get_v1_unlock_height();
            let pox_2_first_cycle = PoxConstants::static_block_height_to_reward_cycle(
                u64::from(v1_unlock_height),
                u64::from(first_block_height),
                u64::from(pox_reward_cycle_length),
            )
            .expect("PANIC: PoX-2 first reward cycle begins *before* first burn block height");

            // get the boot code account information
            //  for processing the pox contract initialization
            let tx_version = if mainnet {
                TransactionVersion::Mainnet
            } else {
                TransactionVersion::Testnet
            };

            let boot_code_address = boot_code_addr(mainnet);

            let boot_code_auth = boot_code_tx_auth(boot_code_address.clone());

            let boot_code_nonce = self.with_clarity_db_readonly(|db| {
                db.get_account_nonce(&boot_code_address.clone().into())
                    .expect("FATAL: Failed to boot account nonce")
            });

            let boot_code_account = StacksAccount {
                principal: PrincipalData::Standard(boot_code_address.into()),
                nonce: boot_code_nonce,
                stx_balance: STXBalance::zero(),
            };

            /////////////////// .pox-2 ////////////////////////
            let pox_2_code = if mainnet {
                &*POX_2_MAINNET_CODE
            } else {
                &*POX_2_TESTNET_CODE
            };

            let pox_2_contract_id = boot_code_id(POX_2_NAME, mainnet);

            let payload = TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from(POX_2_NAME)
                        .expect("FATAL: invalid boot-code contract name"),
                    code_body: StacksString::from_str(pox_2_code)
                        .expect("FATAL: invalid boot code body"),
                },
                Some(ClarityVersion::Clarity2),
            );

            let pox_2_contract_tx =
                StacksTransaction::new(tx_version, boot_code_auth.clone(), payload);

            // upgrade epoch before starting transaction-processing, since .pox-2 needs clarity2
            // features
            self.epoch = StacksEpochId::Epoch21;
            let pox_2_initialization_receipt = self.as_transaction(|tx_conn| {
                // bump the epoch in the Clarity DB
                tx_conn
                    .with_clarity_db(|db| {
                        db.set_clarity_epoch_version(StacksEpochId::Epoch21)?;
                        Ok(())
                    })
                    .unwrap();

                // require 2.1 rules henceforth in this connection as well
                tx_conn.epoch = StacksEpochId::Epoch21;

                // initialize with a synthetic transaction
                debug!("Instantiate {} contract", &pox_2_contract_id);
                let receipt = StacksChainState::process_transaction_payload(
                    tx_conn,
                    &pox_2_contract_tx,
                    &boot_code_account,
                    None,
                )
                .expect("FATAL: Failed to process PoX 2 contract initialization");

                // set burnchain params
                let consts_setter = PrincipalData::from(pox_2_contract_id.clone());
                let params = vec![
                    Value::UInt(u128::from(first_block_height)),
                    Value::UInt(u128::from(pox_prepare_length)),
                    Value::UInt(u128::from(pox_reward_cycle_length)),
                    Value::UInt(u128::from(pox_rejection_fraction)),
                    Value::UInt(u128::from(pox_2_first_cycle)),
                ];

                let (_, _, _burnchain_params_events) = tx_conn
                    .run_contract_call(
                        &consts_setter,
                        None,
                        &pox_2_contract_id,
                        "set-burnchain-parameters",
                        &params,
                        |_, _| None,
                        None,
                    )
                    .expect("Failed to set burnchain parameters in PoX-2 contract");

                receipt
            });

            if pox_2_initialization_receipt.result != Value::okay_true()
                || pox_2_initialization_receipt.post_condition_aborted
            {
                panic!(
                    "FATAL: Failure processing PoX 2 contract initialization: {:#?}",
                    &pox_2_initialization_receipt
                );
            }

            /////////////////// .costs-3 ////////////////////////
            let cost_3_code = BOOT_CODE_COSTS_3;

            let payload = TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from(COSTS_3_NAME)
                        .expect("FATAL: invalid boot-code contract name"),
                    code_body: StacksString::from_str(cost_3_code)
                        .expect("FATAL: invalid boot code body"),
                },
                None,
            );

            let costs_3_contract_tx = StacksTransaction::new(tx_version, boot_code_auth, payload);

            let costs_3_initialization_receipt = self.as_transaction(|tx_conn| {
                // bump the epoch in the Clarity DB
                tx_conn
                    .with_clarity_db(|db| {
                        db.set_clarity_epoch_version(StacksEpochId::Epoch21)?;
                        Ok(())
                    })
                    .unwrap();

                // require 2.1 rules henceforth in this connection as well
                tx_conn.epoch = StacksEpochId::Epoch21;

                // initialize with a synthetic transaction
                debug!("Instantiate .costs-3 contract");
                let receipt = StacksChainState::process_transaction_payload(
                    tx_conn,
                    &costs_3_contract_tx,
                    &boot_code_account,
                    None,
                )
                .expect("FATAL: Failed to process costs-3 contract initialization");

                receipt
            });

            if costs_3_initialization_receipt.result != Value::okay_true()
                || costs_3_initialization_receipt.post_condition_aborted
            {
                panic!(
                    "FATAL: Failure processing Costs 3 contract initialization: {costs_3_initialization_receipt:#?}"
                );
            }

            debug!("Epoch 2.1 initialized");
            (
                old_cost_tracker,
                Ok(vec![
                    pox_2_initialization_receipt,
                    costs_3_initialization_receipt,
                ]),
            )
        })
    }

    pub fn initialize_epoch_2_2(&mut self) -> Result<Vec<StacksTransactionReceipt>, ClarityError> {
        // use the `using!` statement to ensure that the old cost_tracker is placed
        //  back in all branches after initialization
        using!(self.cost_track, "cost tracker", |old_cost_tracker| {
            // epoch initialization is *free*.
            // NOTE: this also means that cost functions won't be evaluated.
            self.cost_track.replace(LimitedCostTracker::new_free());
            self.epoch = StacksEpochId::Epoch22;
            self.as_transaction(|tx_conn| {
                // bump the epoch in the Clarity DB
                tx_conn
                    .with_clarity_db(|db| {
                        db.set_clarity_epoch_version(StacksEpochId::Epoch22)?;
                        Ok(())
                    })
                    .unwrap();

                // require 2.2 rules henceforth in this connection as well
                tx_conn.epoch = StacksEpochId::Epoch22;
            });

            debug!("Epoch 2.2 initialized");

            (old_cost_tracker, Ok(vec![]))
        })
    }

    pub fn initialize_epoch_2_3(&mut self) -> Result<Vec<StacksTransactionReceipt>, ClarityError> {
        // use the `using!` statement to ensure that the old cost_tracker is placed
        //  back in all branches after initialization
        using!(self.cost_track, "cost tracker", |old_cost_tracker| {
            // epoch initialization is *free*.
            // NOTE: this also means that cost functions won't be evaluated.
            self.cost_track.replace(LimitedCostTracker::new_free());

            // first, upgrade the epoch
            self.epoch = StacksEpochId::Epoch23;
            self.as_transaction(|tx_conn| {
                // bump the epoch in the Clarity DB
                tx_conn
                    .with_clarity_db(|db| {
                        db.set_clarity_epoch_version(StacksEpochId::Epoch23)?;
                        Ok(())
                    })
                    .unwrap();

                // require 2.3 rules henceforth in this connection as well
                tx_conn.epoch = StacksEpochId::Epoch23;
            });

            debug!("Epoch 2.3 initialized");

            (old_cost_tracker, Ok(vec![]))
        })
    }

    pub fn initialize_epoch_2_4(&mut self) -> Result<Vec<StacksTransactionReceipt>, ClarityError> {
        // use the `using!` statement to ensure that the old cost_tracker is placed
        //  back in all branches after initialization
        using!(self.cost_track, "cost tracker", |old_cost_tracker| {
            // epoch initialization is *free*.
            // NOTE: this also means that cost functions won't be evaluated.
            self.cost_track.replace(LimitedCostTracker::new_free());
            self.epoch = StacksEpochId::Epoch24;
            self.as_transaction(|tx_conn| {
                // bump the epoch in the Clarity DB
                tx_conn
                    .with_clarity_db(|db| {
                        db.set_clarity_epoch_version(StacksEpochId::Epoch24)?;
                        Ok(())
                    })
                    .unwrap();

                // require 2.4 rules henceforth in this connection as well
                tx_conn.epoch = StacksEpochId::Epoch24;
            });

            /////////////////// .pox-3 ////////////////////////
            let mainnet = self.mainnet;
            let first_block_height = self.burn_state_db.get_burn_start_height();
            let pox_prepare_length = self.burn_state_db.get_pox_prepare_length();
            let pox_reward_cycle_length = self.burn_state_db.get_pox_reward_cycle_length();
            let pox_rejection_fraction = self.burn_state_db.get_pox_rejection_fraction();
            let pox_3_activation_height = self.burn_state_db.get_pox_3_activation_height();

            let pox_3_first_cycle = PoxConstants::static_block_height_to_reward_cycle(
                u64::from(pox_3_activation_height),
                u64::from(first_block_height),
                u64::from(pox_reward_cycle_length),
            )
            .expect("PANIC: PoX-3 first reward cycle begins *before* first burn block height")
                + 1;

            // get tx_version & boot code account information for pox-3 contract init
            let tx_version = if mainnet {
                TransactionVersion::Mainnet
            } else {
                TransactionVersion::Testnet
            };

            let boot_code_address = boot_code_addr(mainnet);

            let boot_code_auth = boot_code_tx_auth(boot_code_address.clone());

            let boot_code_nonce = self.with_clarity_db_readonly(|db| {
                db.get_account_nonce(&boot_code_address.clone().into())
                    .expect("FATAL: Failed to boot account nonce")
            });

            let boot_code_account = StacksAccount {
                principal: PrincipalData::Standard(boot_code_address.into()),
                nonce: boot_code_nonce,
                stx_balance: STXBalance::zero(),
            };

            let pox_3_code = if mainnet {
                &*POX_3_MAINNET_CODE
            } else {
                &*POX_3_TESTNET_CODE
            };

            let pox_3_contract_id = boot_code_id(POX_3_NAME, mainnet);

            let payload = TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from(POX_3_NAME)
                        .expect("FATAL: invalid boot-code contract name"),
                    code_body: StacksString::from_str(pox_3_code)
                        .expect("FATAL: invalid boot code body"),
                },
                Some(ClarityVersion::Clarity2),
            );

            let pox_3_contract_tx = StacksTransaction::new(tx_version, boot_code_auth, payload);

            let pox_3_initialization_receipt = self.as_transaction(|tx_conn| {
                // initialize with a synthetic transaction
                debug!("Instantiate {} contract", &pox_3_contract_id);
                let receipt = StacksChainState::process_transaction_payload(
                    tx_conn,
                    &pox_3_contract_tx,
                    &boot_code_account,
                    None,
                )
                .expect("FATAL: Failed to process PoX 3 contract initialization");

                // set burnchain params
                let consts_setter = PrincipalData::from(pox_3_contract_id.clone());
                let params = vec![
                    Value::UInt(u128::from(first_block_height)),
                    Value::UInt(u128::from(pox_prepare_length)),
                    Value::UInt(u128::from(pox_reward_cycle_length)),
                    Value::UInt(u128::from(pox_rejection_fraction)),
                    Value::UInt(u128::from(pox_3_first_cycle)),
                ];

                let (_, _, _burnchain_params_events) = tx_conn
                    .run_contract_call(
                        &consts_setter,
                        None,
                        &pox_3_contract_id,
                        "set-burnchain-parameters",
                        &params,
                        |_, _| None,
                        None,
                    )
                    .expect("Failed to set burnchain parameters in PoX-3 contract");

                receipt
            });

            if pox_3_initialization_receipt.result != Value::okay_true()
                || pox_3_initialization_receipt.post_condition_aborted
            {
                panic!(
                    "FATAL: Failure processing PoX 3 contract initialization: {:#?}",
                    &pox_3_initialization_receipt
                );
            }

            debug!("Epoch 2.4 initialized");

            (old_cost_tracker, Ok(vec![pox_3_initialization_receipt]))
        })
    }

    pub fn initialize_epoch_2_5(&mut self) -> Result<Vec<StacksTransactionReceipt>, ClarityError> {
        // use the `using!` statement to ensure that the old cost_tracker is placed
        //  back in all branches after initialization
        using!(self.cost_track, "cost tracker", |old_cost_tracker| {
            // epoch initialization is *free*.
            // NOTE: this also means that cost functions won't be evaluated.
            self.cost_track.replace(LimitedCostTracker::new_free());
            self.epoch = StacksEpochId::Epoch25;
            self.as_transaction(|tx_conn| {
                // bump the epoch in the Clarity DB
                tx_conn
                    .with_clarity_db(|db| {
                        db.set_clarity_epoch_version(StacksEpochId::Epoch25)?;
                        Ok(())
                    })
                    .unwrap();

                // require 3.0 rules henceforth in this connection as well
                tx_conn.epoch = StacksEpochId::Epoch25;
            });

            /////////////////// .pox-4 ////////////////////////
            let first_block_height = self.burn_state_db.get_burn_start_height();
            let pox_prepare_length = self.burn_state_db.get_pox_prepare_length();
            let pox_reward_cycle_length = self.burn_state_db.get_pox_reward_cycle_length();
            let pox_4_activation_height = self.burn_state_db.get_pox_4_activation_height();

            let pox_4_first_cycle = PoxConstants::static_block_height_to_reward_cycle(
                u64::from(pox_4_activation_height),
                u64::from(first_block_height),
                u64::from(pox_reward_cycle_length),
            )
            .expect("PANIC: PoX-4 first reward cycle begins *before* first burn block height")
                + 1;
            // get tx_version & boot code account information for pox-3 contract init
            let mainnet = self.mainnet;
            let tx_version = if mainnet {
                TransactionVersion::Mainnet
            } else {
                TransactionVersion::Testnet
            };

            let mut receipts = vec![];

            let boot_code_account = self
                .get_boot_code_account()
                .expect("FATAL: did not get boot account");

            let pox_4_code = &*POX_4_CODE;
            let pox_4_contract_id = boot_code_id(POX_4_NAME, mainnet);

            let payload = TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from(POX_4_NAME)
                        .expect("FATAL: invalid boot-code contract name"),
                    code_body: StacksString::from_str(pox_4_code)
                        .expect("FATAL: invalid boot code body"),
                },
                Some(ClarityVersion::Clarity2),
            );

            let boot_code_address = boot_code_addr(mainnet);
            let boot_code_auth = boot_code_tx_auth(boot_code_address.clone());

            let pox_4_contract_tx =
                StacksTransaction::new(tx_version, boot_code_auth.clone(), payload);

            let pox_4_initialization_receipt = self.as_transaction(|tx_conn| {
                // initialize with a synthetic transaction
                debug!("Instantiate {} contract", &pox_4_contract_id);
                let receipt = StacksChainState::process_transaction_payload(
                    tx_conn,
                    &pox_4_contract_tx,
                    &boot_code_account,
                    None,
                )
                .expect("FATAL: Failed to process PoX 4 contract initialization");

                // set burnchain params
                let consts_setter = PrincipalData::from(pox_4_contract_id.clone());
                let params = vec![
                    Value::UInt(u128::from(first_block_height)),
                    Value::UInt(u128::from(pox_prepare_length)),
                    Value::UInt(u128::from(pox_reward_cycle_length)),
                    Value::UInt(u128::from(pox_4_first_cycle)),
                ];

                let (_, _, _burnchain_params_events) = tx_conn
                    .run_contract_call(
                        &consts_setter,
                        None,
                        &pox_4_contract_id,
                        "set-burnchain-parameters",
                        &params,
                        |_, _| None,
                        None,
                    )
                    .expect("Failed to set burnchain parameters in PoX-3 contract");

                receipt
            });

            if pox_4_initialization_receipt.result != Value::okay_true()
                || pox_4_initialization_receipt.post_condition_aborted
            {
                panic!(
                    "FATAL: Failure processing PoX 4 contract initialization: {:#?}",
                    &pox_4_initialization_receipt
                );
            }
            receipts.push(pox_4_initialization_receipt);

            let signers_contract_id = boot_code_id(SIGNERS_NAME, mainnet);
            let payload = TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from(SIGNERS_NAME)
                        .expect("FATAL: invalid boot-code contract name"),
                    code_body: StacksString::from_str(SIGNERS_BODY)
                        .expect("FATAL: invalid boot code body"),
                },
                Some(ClarityVersion::Clarity2),
            );

            let signers_contract_tx =
                StacksTransaction::new(tx_version, boot_code_auth.clone(), payload);

            let signers_initialization_receipt = self.as_transaction(|tx_conn| {
                // initialize with a synthetic transaction
                debug!("Instantiate {} contract", &signers_contract_id);
                let receipt = StacksChainState::process_transaction_payload(
                    tx_conn,
                    &signers_contract_tx,
                    &boot_code_account,
                    None,
                )
                .expect("FATAL: Failed to process .signers contract initialization");
                receipt
            });

            if signers_initialization_receipt.result != Value::okay_true()
                || signers_initialization_receipt.post_condition_aborted
            {
                panic!(
                    "FATAL: Failure processing signers contract initialization: {:#?}",
                    &signers_initialization_receipt
                );
            }
            receipts.push(signers_initialization_receipt);

            // stackerdb contracts for each message type
            for signer_set in 0..2 {
                for message_id in 0..SIGNER_SLOTS_PER_USER {
                    let signers_name =
                        NakamotoSigners::make_signers_db_name(signer_set, message_id);
                    let body = if signer_set == 0 {
                        SIGNERS_DB_0_BODY
                    } else {
                        SIGNERS_DB_1_BODY
                    };
                    let payload = TransactionPayload::SmartContract(
                        TransactionSmartContract {
                            name: ContractName::try_from(signers_name.clone())
                                .expect("FATAL: invalid boot-code contract name"),
                            code_body: StacksString::from_str(body)
                                .expect("FATAL: invalid boot code body"),
                        },
                        Some(ClarityVersion::Clarity2),
                    );

                    let signers_contract_tx =
                        StacksTransaction::new(tx_version, boot_code_auth.clone(), payload);

                    let signers_db_receipt = self.as_transaction(|tx_conn| {
                        // initialize with a synthetic transaction
                        debug!("Instantiate .{} contract", &signers_name);
                        let receipt = StacksChainState::process_transaction_payload(
                            tx_conn,
                            &signers_contract_tx,
                            &boot_code_account,
                            None,
                        )
                        .expect("FATAL: Failed to process .signers DB contract initialization");
                        receipt
                    });

                    if signers_db_receipt.result != Value::okay_true()
                        || signers_db_receipt.post_condition_aborted
                    {
                        panic!(
                            "FATAL: Failure processing signers DB contract initialization: {:#?}",
                            &signers_db_receipt
                        );
                    }

                    receipts.push(signers_db_receipt);
                }
            }

            let signers_voting_contract_id = boot_code_id(SIGNERS_VOTING_NAME, mainnet);
            let payload = TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from(SIGNERS_VOTING_NAME)
                        .expect("FATAL: invalid boot-code contract name"),
                    code_body: StacksString::from_str(SIGNERS_VOTING_BODY)
                        .expect("FATAL: invalid boot code body"),
                },
                Some(ClarityVersion::Clarity2),
            );

            let signers_contract_tx = StacksTransaction::new(tx_version, boot_code_auth, payload);

            let signers_voting_initialization_receipt = self.as_transaction(|tx_conn| {
                // initialize with a synthetic transaction
                debug!("Instantiate {} contract", &signers_voting_contract_id);
                let receipt = StacksChainState::process_transaction_payload(
                    tx_conn,
                    &signers_contract_tx,
                    &boot_code_account,
                    None,
                )
                .expect("FATAL: Failed to process .signers-voting contract initialization");
                receipt
            });

            if signers_voting_initialization_receipt.result != Value::okay_true()
                || signers_voting_initialization_receipt.post_condition_aborted
            {
                panic!(
                    "FATAL: Failure processing signers-voting contract initialization: {:#?}",
                    &signers_voting_initialization_receipt
                );
            }
            receipts.push(signers_voting_initialization_receipt);

            debug!("Epoch 2.5 initialized");
            (old_cost_tracker, Ok(receipts))
        })
    }

    pub fn initialize_epoch_3_0(&mut self) -> Result<Vec<StacksTransactionReceipt>, ClarityError> {
        // use the `using!` statement to ensure that the old cost_tracker is placed
        //  back in all branches after initialization
        using!(self.cost_track, "cost tracker", |old_cost_tracker| {
            // epoch initialization is *free*.
            // NOTE: this also means that cost functions won't be evaluated.
            self.cost_track.replace(LimitedCostTracker::new_free());
            self.epoch = StacksEpochId::Epoch30;
            self.as_transaction(|tx_conn| {
                // bump the epoch in the Clarity DB
                tx_conn
                    .with_clarity_db(|db| {
                        db.set_clarity_epoch_version(StacksEpochId::Epoch30)?;
                        Ok(())
                    })
                    .unwrap();

                // require 3.0 rules henceforth in this connection as well
                tx_conn.epoch = StacksEpochId::Epoch30;
            });

            debug!("Epoch 3.0 initialized");
            (old_cost_tracker, Ok(vec![]))
        })
    }

    pub fn initialize_epoch_3_1(&mut self) -> Result<Vec<StacksTransactionReceipt>, ClarityError> {
        // use the `using!` statement to ensure that the old cost_tracker is placed
        //  back in all branches after initialization
        using!(self.cost_track, "cost tracker", |old_cost_tracker| {
            // epoch initialization is *free*.
            // NOTE: this also means that cost functions won't be evaluated.
            self.cost_track.replace(LimitedCostTracker::new_free());
            self.epoch = StacksEpochId::Epoch31;
            self.as_transaction(|tx_conn| {
                // bump the epoch in the Clarity DB
                tx_conn
                    .with_clarity_db(|db| {
                        db.set_clarity_epoch_version(StacksEpochId::Epoch31)?;
                        Ok(())
                    })
                    .unwrap();

                // require 3.1 rules henceforth in this connection as well
                tx_conn.epoch = StacksEpochId::Epoch31;
            });

            debug!("Epoch 3.1 initialized");
            (old_cost_tracker, Ok(vec![]))
        })
    }

    pub fn initialize_epoch_3_2(&mut self) -> Result<Vec<StacksTransactionReceipt>, ClarityError> {
        // use the `using!` statement to ensure that the old cost_tracker is placed
        //  back in all branches after initialization
        using!(self.cost_track, "cost tracker", |old_cost_tracker| {
            // epoch initialization is *free*.
            // NOTE: this also means that cost functions won't be evaluated.
            self.cost_track.replace(LimitedCostTracker::new_free());
            self.epoch = StacksEpochId::Epoch32;
            self.as_transaction(|tx_conn| {
                // bump the epoch in the Clarity DB
                tx_conn
                    .with_clarity_db(|db| {
                        db.set_clarity_epoch_version(StacksEpochId::Epoch32)?;
                        Ok(())
                    })
                    .unwrap();

                // require 3.2 rules henceforth in this connection as well
                tx_conn.epoch = StacksEpochId::Epoch32;
            });

            let mut receipts = vec![];

            let boot_code_account = self
                .get_boot_code_account()
                .expect("FATAL: did not get boot account");

            let mainnet = self.mainnet;
            let tx_version = if mainnet {
                TransactionVersion::Mainnet
            } else {
                TransactionVersion::Testnet
            };

            let boot_code_address = boot_code_addr(mainnet);
            let boot_code_auth = boot_code_tx_auth(boot_code_address);

            // SIP-031 setup (deploy of the boot contract, minting and transfer to the boot contract)
            let sip_031_contract_id = boot_code_id(SIP_031_NAME, mainnet);
            let payload = TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from(SIP_031_NAME)
                        .expect("FATAL: invalid boot-code contract name"),
                    code_body: StacksString::from_str(&make_sip_031_body(mainnet))
                        .expect("FATAL: invalid boot code body"),
                },
                Some(ClarityVersion::Clarity3),
            );

            let sip_031_contract_tx = StacksTransaction::new(tx_version, boot_code_auth, payload);

            let mut sip_031_initialization_receipt = self.as_transaction(|tx_conn| {
                // initialize with a synthetic transaction
                info!("Instantiate {} contract", &sip_031_contract_id);
                let receipt = StacksChainState::process_transaction_payload(
                    tx_conn,
                    &sip_031_contract_tx,
                    &boot_code_account,
                    None,
                )
                .expect("FATAL: Failed to process .sip-031 contract initialization");
                receipt
            });

            if sip_031_initialization_receipt.result != Value::okay_true()
                || sip_031_initialization_receipt.post_condition_aborted
            {
                panic!(
                    "FATAL: Failure processing sip-031 contract initialization: {:#?}",
                    &sip_031_initialization_receipt
                );
            }

            let recipient = PrincipalData::Contract(sip_031_contract_id);

            self.as_transaction(|tx_conn| {
                tx_conn
                    .with_clarity_db(|db| {
                        db.increment_ustx_liquid_supply(SIP_031_INITIAL_MINT)
                            .map_err(|e| e.into())
                    })
                    .expect("FATAL: `SIP-031 initial mint` overflowed");
                StacksChainState::account_credit(
                    tx_conn,
                    &recipient,
                    u64::try_from(SIP_031_INITIAL_MINT)
                        .expect("FATAL: transferred more STX than exist"),
                );
            });

            let event = STXEventType::STXMintEvent(STXMintEventData {
                recipient,
                amount: SIP_031_INITIAL_MINT,
            });
            sip_031_initialization_receipt
                .events
                .push(StacksTransactionEvent::STXEvent(event));

            receipts.push(sip_031_initialization_receipt);

            debug!("Epoch 3.2 initialized");
            (old_cost_tracker, Ok(receipts))
        })
    }

    pub fn initialize_epoch_3_3(&mut self) -> Result<Vec<StacksTransactionReceipt>, ClarityError> {
        // use the `using!` statement to ensure that the old cost_tracker is placed
        //  back in all branches after initialization
        using!(self.cost_track, "cost tracker", |old_cost_tracker| {
            // epoch initialization is *free*.
            // NOTE: this also means that cost functions won't be evaluated.
            self.cost_track.replace(LimitedCostTracker::new_free());

            let mainnet = self.mainnet;
            self.epoch = StacksEpochId::Epoch33;

            /////////////////// .costs-4 ////////////////////////
            let cost_4_code = BOOT_CODE_COSTS_4;

            let payload = TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from(COSTS_4_NAME)
                        .expect("FATAL: invalid boot-code contract name"),
                    code_body: StacksString::from_str(cost_4_code)
                        .expect("FATAL: invalid boot code body"),
                },
                None,
            );

            // get the boot code account information
            //  for processing the costs-4 contract initialization
            let tx_version = if mainnet {
                TransactionVersion::Mainnet
            } else {
                TransactionVersion::Testnet
            };

            let boot_code_address = boot_code_addr(mainnet);

            let boot_code_auth = boot_code_tx_auth(boot_code_address.clone());

            let boot_code_nonce = self.with_clarity_db_readonly(|db| {
                db.get_account_nonce(&boot_code_address.clone().into())
                    .expect("FATAL: Failed to boot account nonce")
            });

            let boot_code_account = StacksAccount {
                principal: PrincipalData::Standard(boot_code_address.into()),
                nonce: boot_code_nonce,
                stx_balance: STXBalance::zero(),
            };

            let costs_4_contract_tx = StacksTransaction::new(tx_version, boot_code_auth, payload);

            let costs_4_initialization_receipt = self.as_transaction(|tx_conn| {
                // bump the epoch in the Clarity DB
                tx_conn
                    .with_clarity_db(|db| {
                        db.set_clarity_epoch_version(StacksEpochId::Epoch33)?;
                        Ok(())
                    })
                    .unwrap();

                // require 3.3 rules henceforth in this connection as well
                tx_conn.epoch = StacksEpochId::Epoch33;

                // initialize with a synthetic transaction
                info!("Instantiate .costs-4 contract");
                let receipt = StacksChainState::process_transaction_payload(
                    tx_conn,
                    &costs_4_contract_tx,
                    &boot_code_account,
                    None,
                )
                .expect("FATAL: Failed to process costs-4 contract initialization");

                receipt
            });

            if costs_4_initialization_receipt.result != Value::okay_true()
                || costs_4_initialization_receipt.post_condition_aborted
            {
                panic!(
                    "FATAL: Failure processing Costs 4 contract initialization: {:#?}",
                    &costs_4_initialization_receipt
                );
            }

            info!("Epoch 3.3 initialized");
            (old_cost_tracker, Ok(vec![costs_4_initialization_receipt]))
        })
    }

    pub fn start_transaction_processing(&mut self) -> ClarityTransactionConnection<'_, '_> {
        ClarityTransactionConnection::new(
            &mut self.datastore,
            self.header_db,
            self.burn_state_db,
            &mut self.cost_track,
            self.mainnet,
            self.chain_id,
            self.epoch,
        )
    }

    /// Execute `todo` as a transaction in this block. The execution
    /// will use the "free" cost tracker.
    /// This will unconditionally commit the edit log from the
    /// transaction to the block, so any changes that should be
    /// rolled back must be rolled back by `todo`.
    pub fn as_free_transaction<F, R>(&mut self, todo: F) -> R
    where
        F: FnOnce(&mut ClarityTransactionConnection) -> R,
    {
        // use the `using!` statement to ensure that the old cost_tracker is placed
        //  back in all branches after initialization
        using!(self.cost_track, "cost tracker", |old_cost_tracker| {
            // epoch initialization is *free*
            self.cost_track.replace(LimitedCostTracker::new_free());

            let mut tx = self.start_transaction_processing();
            let r = todo(&mut tx);
            tx.commit()
                .expect("FATAL: failed to commit unconditional free transaction");
            (old_cost_tracker, r)
        })
    }

    /// Execute `todo` as a transaction in this block.
    /// This will unconditionally commit the edit log from the
    /// transaction to the block, so any changes that should be
    /// rolled back must be rolled back by `todo`.
    pub fn as_transaction<F, R>(&mut self, todo: F) -> R
    where
        F: FnOnce(&mut ClarityTransactionConnection) -> R,
    {
        let mut tx = self.start_transaction_processing();
        let r = todo(&mut tx);
        tx.commit()
            .expect("FATAL: failed to commit unconditional transaction");
        r
    }

    pub fn seal(&mut self) -> TrieHash {
        self.datastore.seal_trie()
    }

    pub fn destruct(self) -> Box<dyn WritableMarfStore + 'a> {
        self.datastore
    }

    #[cfg(test)]
    pub fn set_epoch(&mut self, epoch_id: StacksEpochId) {
        self.epoch = epoch_id;
    }
}

impl ClarityConnection for ClarityTransactionConnection<'_, '_> {
    /// Do something with ownership of the underlying DB that involves only reading.
    fn with_clarity_db_readonly_owned<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(ClarityDatabase) -> (R, ClarityDatabase),
    {
        using!(self.log, "log", |log| {
            let rollback_wrapper = RollbackWrapper::from_persisted_log(self.store, log);
            let mut db = ClarityDatabase::new_with_rollback_wrapper(
                rollback_wrapper,
                self.header_db,
                self.burn_state_db,
            );
            db.begin();
            let (r, mut db) = to_do(db);
            db.roll_back()
                .expect("FATAL: failed to rollback changes during read-only connection");
            (db.destroy().into(), r)
        })
    }

    fn with_analysis_db_readonly<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(&mut AnalysisDatabase) -> R,
    {
        self.with_analysis_db(|db, cost_tracker| {
            db.begin();
            let result = to_do(db);
            db.roll_back()
                .expect("FATAL: failed to rollback changes during read-only connection");
            (cost_tracker, result)
        })
    }

    fn get_epoch(&self) -> StacksEpochId {
        self.epoch
    }
}

impl Drop for ClarityTransactionConnection<'_, '_> {
    fn drop(&mut self) {
        if thread::panicking() {
            // if the thread is panicking, we've likely lost our cost_tracker handle,
            //  so don't expect() one, or we'll end up panicking while panicking.
            match self.cost_track.as_mut() {
                Some(t) => t.reset_memory(),
                None => {
                    error!("Failed to reset the memory of the Clarity transaction's cost_track handle while thread panicking");
                }
            }
        } else {
            self.cost_track
                .as_mut()
                .expect("BUG: Transaction connection lost cost_tracker handle.")
                .reset_memory();
        }
    }
}

impl TransactionConnection for ClarityTransactionConnection<'_, '_> {
    fn with_abort_callback<F, A, R, E>(
        &mut self,
        to_do: F,
        abort_call_back: A,
    ) -> Result<(R, AssetMap, Vec<StacksTransactionEvent>, Option<String>), E>
    where
        A: FnOnce(&AssetMap, &mut ClarityDatabase) -> Option<String>,
        F: FnOnce(&mut OwnedEnvironment) -> Result<(R, AssetMap, Vec<StacksTransactionEvent>), E>,
        E: From<VmExecutionError>,
    {
        using!(self.log, "log", |log| {
            using!(self.cost_track, "cost tracker", |cost_track| {
                let rollback_wrapper = RollbackWrapper::from_persisted_log(self.store, log);
                let mut db = ClarityDatabase::new_with_rollback_wrapper(
                    rollback_wrapper,
                    self.header_db,
                    self.burn_state_db,
                );

                // wrap the whole contract-call in a claritydb transaction,
                //   so we can abort on call_back's boolean retun
                db.begin();
                let mut vm_env = OwnedEnvironment::new_cost_limited(
                    self.mainnet,
                    self.chain_id,
                    db,
                    cost_track,
                    self.epoch,
                );
                let result = to_do(&mut vm_env);
                let (mut db, cost_track) = vm_env
                    .destruct()
                    .expect("Failed to recover database reference after executing transaction");
                // DO NOT reset memory usage yet -- that should happen only when the TX commits.

                let result = match result {
                    Ok((value, asset_map, events)) => {
                        let aborted = abort_call_back(&asset_map, &mut db);
                        let db_result = if aborted.is_some() {
                            db.roll_back()
                        } else {
                            db.commit()
                        };
                        match db_result {
                            Ok(_) => Ok((value, asset_map, events, aborted)),
                            Err(e) => Err(e.into()),
                        }
                    }
                    Err(e) => {
                        let db_result = db.roll_back();
                        match db_result {
                            Ok(_) => Err(e),
                            Err(db_err) => Err(db_err.into()),
                        }
                    }
                };

                (cost_track, (db.destroy().into(), result))
            })
        })
    }

    fn with_analysis_db<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(&mut AnalysisDatabase, LimitedCostTracker) -> (LimitedCostTracker, R),
    {
        using!(self.cost_track, "cost tracker", |cost_track| {
            using!(self.log, "log", |log| {
                let rollback_wrapper = RollbackWrapper::from_persisted_log(self.store, log);
                let mut db = AnalysisDatabase::new_with_rollback_wrapper(rollback_wrapper);
                let r = to_do(&mut db, cost_track);
                (db.destroy().into(), r)
            })
        })
    }
}

impl ClarityTransactionConnection<'_, '_> {
    /// Do something to the underlying DB that involves writing.
    pub fn with_clarity_db<F, R>(&mut self, to_do: F) -> Result<R, ClarityError>
    where
        F: FnOnce(&mut ClarityDatabase) -> Result<R, ClarityError>,
    {
        using!(self.log, "log", |log| {
            let rollback_wrapper = RollbackWrapper::from_persisted_log(self.store, log);
            let mut db = ClarityDatabase::new_with_rollback_wrapper(
                rollback_wrapper,
                self.header_db,
                self.burn_state_db,
            );

            db.begin();
            let result = to_do(&mut db);
            let db_result = if result.is_ok() {
                db.commit()
            } else {
                db.roll_back()
            };

            let result = match db_result {
                Ok(_) => result,
                Err(e) => Err(e.into()),
            };

            (db.destroy().into(), result)
        })
    }

    /// What's our total (block-wide) resource use so far?
    pub fn cost_so_far(&self) -> ExecutionCost {
        match self.cost_track {
            Some(ref track) => track.get_total(),
            None => ExecutionCost::ZERO,
        }
    }

    /// Evaluate a poison-microblock transaction
    pub fn run_poison_microblock(
        &mut self,
        sender: &PrincipalData,
        mblock_header_1: &StacksMicroblockHeader,
        mblock_header_2: &StacksMicroblockHeader,
    ) -> Result<Value, ClarityError> {
        self.with_abort_callback(
            |vm_env| {
                vm_env
                    .execute_in_env(sender.clone(), None, None, |env| {
                        env.run_as_transaction(|env| {
                            StacksChainState::handle_poison_microblock(
                                env,
                                mblock_header_1,
                                mblock_header_2,
                            )
                        })
                    })
                    .map_err(ClarityError::from)
            },
            |_, _| None,
        )
        .map(|(value, ..)| value)
    }

    pub fn is_mainnet(&self) -> bool {
        return self.mainnet;
    }

    /// Commit the changes from the edit log.
    /// panics if there is more than one open savepoint
    pub fn commit(mut self) -> Result<(), ClarityError> {
        let log = self
            .log
            .take()
            .expect("BUG: Transaction Connection lost db log connection.");
        let mut rollback_wrapper = RollbackWrapper::from_persisted_log(self.store, log);
        if rollback_wrapper.depth() != 1 {
            panic!(
                "Attempted to commit transaction with {} != 1 rollbacks",
                rollback_wrapper.depth()
            );
        }
        rollback_wrapper.commit().map_err(VmExecutionError::from)?;
        // now we can reset the memory usage for the edit-log
        self.cost_track
            .as_mut()
            .expect("BUG: Transaction connection lost cost tracker connection.")
            .reset_memory();
        Ok(())
    }

    /// Evaluate a method of a clarity contract in a read-only environment.
    /// This does not check if the method itself attempted to write,
    ///  but will always rollback any changes.
    ///
    /// The method is invoked as if the contract itself is the tx-sender.
    ///
    /// This method *is not* free: it will update the cost-tracker of
    /// the transaction connection. If the transaction connection is a
    /// free transaction, then these costs will be free, but
    /// otherwise, the cost tracker will be invoked like normal.
    pub fn eval_method_read_only(
        &mut self,
        contract: &QualifiedContractIdentifier,
        method: &str,
        args: &[SymbolicExpression],
    ) -> Result<Value, ClarityError> {
        let (result, _, _, _) = self.with_abort_callback(
            |vm_env| {
                vm_env
                    .execute_transaction(
                        PrincipalData::Contract(contract.clone()),
                        None,
                        contract.clone(),
                        method,
                        args,
                    )
                    .map_err(ClarityError::from)
            },
            |_, _| Some("read-only".to_string()),
        )?;
        Ok(result)
    }

    /// Evaluate a raw Clarity snippit
    #[cfg(test)]
    pub fn clarity_eval_raw(&mut self, code: &str) -> Result<Value, ClarityError> {
        let (result, _, _, _) = self.with_abort_callback(
            |vm_env| vm_env.eval_raw(code).map_err(ClarityError::from),
            |_, _| None,
        )?;
        Ok(result)
    }

    #[cfg(test)]
    pub fn eval_read_only(
        &mut self,
        contract: &QualifiedContractIdentifier,
        code: &str,
    ) -> Result<Value, ClarityError> {
        let (result, _, _, _) = self.with_abort_callback(
            |vm_env| {
                vm_env
                    .eval_read_only(contract, code)
                    .map_err(ClarityError::from)
            },
            |_, _| None,
        )?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use clarity::types::chainstate::{BurnchainHeaderHash, SortitionId, StacksAddress};
    use clarity::vm::analysis::errors::RuntimeAnalysisError;
    use clarity::vm::database::{ClarityBackingStore, STXBalance, SqliteConnection};
    use clarity::vm::test_util::{TEST_BURN_STATE_DB, TEST_HEADER_DB};
    use clarity::vm::types::{StandardPrincipalData, TupleData, Value};
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use stacks_common::types::chainstate::ConsensusHash;
    use stacks_common::types::sqlite::NO_PARAMS;

    use super::*;
    use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection as _};
    use crate::chainstate::stacks::index::ClarityMarfTrieId;
    use crate::clarity_vm::database::marf::MarfedKV;
    use crate::core::PEER_VERSION_EPOCH_2_0;

    #[test]
    pub fn create_md_index() {
        let path_db = "/tmp/stacks-node-tests/creat_md_index";
        let _ = std::fs::remove_dir_all(path_db);
        let mut path = PathBuf::from(path_db);

        std::fs::create_dir_all(&path).unwrap();

        path.push("marf.sqlite");
        let marf_path = path.to_str().unwrap().to_string();

        let mut marf_opts = MARFOpenOpts::default();
        marf_opts.external_blobs = true;

        let mut marf: MARF<StacksBlockId> = MARF::from_path(&marf_path, marf_opts).unwrap();

        let tx = marf.storage_tx().unwrap();

        tx.query_row("PRAGMA journal_mode = WAL;", NO_PARAMS, |_row| Ok(()))
            .unwrap();

        tx.execute(
            "CREATE TABLE IF NOT EXISTS data_table
                      (key TEXT PRIMARY KEY, value TEXT)",
            NO_PARAMS,
        )
        .unwrap();

        tx.execute(
            "CREATE TABLE IF NOT EXISTS metadata_table
                      (key TEXT NOT NULL, blockhash TEXT, value TEXT,
                       UNIQUE (key, blockhash))",
            NO_PARAMS,
        )
        .unwrap();

        tx.commit().unwrap();

        assert!(SqliteConnection::check_schema(marf.sqlite_conn()).is_err());

        MarfedKV::open(path_db, None, None).unwrap();

        // schema should be good now
        assert!(SqliteConnection::check_schema(marf.sqlite_conn()).is_ok());
    }

    #[test]
    pub fn bad_syntax_test() {
        let marf = MarfedKV::temporary();
        let mut clarity_instance = ClarityInstance::new(false, CHAIN_ID_TESTNET, marf);

        let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

        clarity_instance
            .begin_test_genesis_block(
                &StacksBlockId::sentinel(),
                &StacksBlockId([0; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            )
            .commit_block();

        {
            let mut conn = clarity_instance.begin_block(
                &StacksBlockId([0; 32]),
                &StacksBlockId([1; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            );

            let contract = "(define-public (foo (x int) (y uint)) (ok (+ x y)))";

            let _e = conn
                .as_transaction(|tx| {
                    tx.analyze_smart_contract(
                        &contract_identifier,
                        ClarityVersion::Clarity1,
                        contract,
                    )
                })
                .unwrap_err();

            // okay, let's try it again:

            let _e = conn
                .as_transaction(|tx| {
                    tx.analyze_smart_contract(
                        &contract_identifier,
                        ClarityVersion::Clarity1,
                        contract,
                    )
                })
                .unwrap_err();

            conn.commit_block();
        }
    }

    #[test]
    pub fn test_initialize_contract_tx_sender_contract_caller() {
        let marf = MarfedKV::temporary();
        let mut clarity_instance = ClarityInstance::new(false, CHAIN_ID_TESTNET, marf);
        let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

        clarity_instance
            .begin_test_genesis_block(
                &StacksBlockId::sentinel(),
                &StacksBlockId([0; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            )
            .commit_block();

        {
            let mut conn = clarity_instance.begin_block(
                &StacksBlockId([0; 32]),
                &StacksBlockId([1; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            );

            // S1G2081040G2081040G2081040G208105NK8PE5 is the transient address
            let contract = "
                (begin
                    (asserts! (is-eq tx-sender 'S1G2081040G2081040G2081040G208105NK8PE5)
                        (err tx-sender))

                    (asserts! (is-eq contract-caller 'S1G2081040G2081040G2081040G208105NK8PE5)
                        (err contract-caller))
                )";

            conn.as_transaction(|conn| {
                let (ct_ast, ct_analysis) = conn
                    .analyze_smart_contract(
                        &contract_identifier,
                        ClarityVersion::Clarity1,
                        contract,
                    )
                    .unwrap();
                conn.initialize_smart_contract(
                    &contract_identifier,
                    ClarityVersion::Clarity1,
                    &ct_ast,
                    contract,
                    None,
                    |_, _| None,
                    None,
                )
                .unwrap();
                conn.save_analysis(&contract_identifier, &ct_analysis)
                    .unwrap();
            });

            conn.commit_block();
        }
    }

    #[test]
    pub fn tx_rollback() {
        let marf = MarfedKV::temporary();
        let mut clarity_instance = ClarityInstance::new(false, CHAIN_ID_TESTNET, marf);

        let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();
        let contract = "(define-public (foo (x int) (y int)) (ok (+ x y)))";

        clarity_instance
            .begin_test_genesis_block(
                &StacksBlockId::sentinel(),
                &StacksBlockId([0; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            )
            .commit_block();

        {
            let mut conn = clarity_instance.begin_block(
                &StacksBlockId([0; 32]),
                &StacksBlockId([1; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            );

            {
                let mut tx = conn.start_transaction_processing();

                let (ct_ast, ct_analysis) = tx
                    .analyze_smart_contract(
                        &contract_identifier,
                        ClarityVersion::Clarity1,
                        contract,
                    )
                    .unwrap();
                tx.initialize_smart_contract(
                    &contract_identifier,
                    ClarityVersion::Clarity1,
                    &ct_ast,
                    contract,
                    None,
                    |_, _| None,
                    None,
                )
                .unwrap();
                tx.save_analysis(&contract_identifier, &ct_analysis)
                    .unwrap();
            }

            // okay, let's try it again -- should pass since the prior contract
            //   publish was unwound
            {
                let mut tx = conn.start_transaction_processing();

                let contract = "(define-public (foo (x int) (y int)) (ok (+ x y)))";

                let (ct_ast, ct_analysis) = tx
                    .analyze_smart_contract(
                        &contract_identifier,
                        ClarityVersion::Clarity1,
                        contract,
                    )
                    .unwrap();
                tx.initialize_smart_contract(
                    &contract_identifier,
                    ClarityVersion::Clarity1,
                    &ct_ast,
                    contract,
                    None,
                    |_, _| None,
                    None,
                )
                .unwrap();
                tx.save_analysis(&contract_identifier, &ct_analysis)
                    .unwrap();

                tx.commit().unwrap();
            }

            // should fail since the prior contract
            //   publish committed to the block
            {
                let mut tx = conn.start_transaction_processing();

                let contract = "(define-public (foo (x int) (y int)) (ok (+ x y)))";

                let (ct_ast, _ct_analysis) = tx
                    .analyze_smart_contract(
                        &contract_identifier,
                        ClarityVersion::Clarity1,
                        contract,
                    )
                    .unwrap();
                assert!(format!(
                    "{}",
                    tx.initialize_smart_contract(
                        &contract_identifier,
                        ClarityVersion::Clarity1,
                        &ct_ast,
                        contract,
                        None,
                        |_, _| None,
                        None
                    )
                    .unwrap_err()
                )
                .contains("ContractAlreadyExists"));

                tx.commit().unwrap();
            }
        }
    }

    #[test]
    pub fn simple_test() {
        let marf = MarfedKV::temporary();
        let mut clarity_instance = ClarityInstance::new(false, CHAIN_ID_TESTNET, marf);

        let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

        clarity_instance
            .begin_test_genesis_block(
                &StacksBlockId::sentinel(),
                &StacksBlockId([0; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            )
            .commit_block();

        {
            let mut conn = clarity_instance.begin_block(
                &StacksBlockId([0; 32]),
                &StacksBlockId([1; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            );

            let contract = "(define-public (foo (x int)) (ok (+ x x)))";

            conn.as_transaction(|conn| {
                let (ct_ast, ct_analysis) = conn
                    .analyze_smart_contract(
                        &contract_identifier,
                        ClarityVersion::Clarity1,
                        contract,
                    )
                    .unwrap();
                conn.initialize_smart_contract(
                    &contract_identifier,
                    ClarityVersion::Clarity1,
                    &ct_ast,
                    contract,
                    None,
                    |_, _| None,
                    None,
                )
                .unwrap();
                conn.save_analysis(&contract_identifier, &ct_analysis)
                    .unwrap();
            });

            assert_eq!(
                conn.as_transaction(|tx| tx.run_contract_call(
                    &StandardPrincipalData::transient().into(),
                    None,
                    &contract_identifier,
                    "foo",
                    &[Value::Int(1)],
                    |_, _| None,
                    None
                ))
                .unwrap()
                .0,
                Value::okay(Value::Int(2)).unwrap()
            );

            conn.commit_block();
        }

        let mut marf = clarity_instance.destroy();
        let mut conn = marf.begin_read_only(Some(&StacksBlockId([1; 32])));
        assert!(conn.get_contract_hash(&contract_identifier).is_ok());
    }

    #[test]
    pub fn test_block_roll_back() {
        let marf = MarfedKV::temporary();
        let mut clarity_instance = ClarityInstance::new(false, CHAIN_ID_TESTNET, marf);
        let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

        {
            let mut conn = clarity_instance.begin_test_genesis_block(
                &StacksBlockId::sentinel(),
                &StacksBlockId([0; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            );

            let contract = "(define-public (foo (x int)) (ok (+ x x)))";

            conn.as_transaction(|conn| {
                let (ct_ast, ct_analysis) = conn
                    .analyze_smart_contract(
                        &contract_identifier,
                        ClarityVersion::Clarity1,
                        contract,
                    )
                    .unwrap();
                conn.initialize_smart_contract(
                    &contract_identifier,
                    ClarityVersion::Clarity1,
                    &ct_ast,
                    contract,
                    None,
                    |_, _| None,
                    None,
                )
                .unwrap();
                conn.save_analysis(&contract_identifier, &ct_analysis)
                    .unwrap();
            });

            conn.rollback_block();
        }

        let mut marf = clarity_instance.destroy();

        let mut conn = marf.begin(&StacksBlockId::sentinel(), &StacksBlockId([0; 32]));
        // should not be in the marf.
        assert_eq!(
            conn.get_contract_hash(&contract_identifier).unwrap_err(),
            RuntimeAnalysisError::NoSuchContract(contract_identifier.to_string()).into()
        );
        let sql = conn.get_side_store();
        // sqlite only have entries
        assert_eq!(
            0,
            sql.query_row::<u32, _, _>("SELECT COUNT(value) FROM data_table", NO_PARAMS, |row| row
                .get(0))
                .unwrap()
        );
    }

    #[test]
    fn test_unconfirmed() {
        let test_name = "/tmp/clarity_test_unconfirmed";
        if fs::metadata(test_name).is_ok() {
            fs::remove_dir_all(test_name).unwrap();
        }

        let confirmed_marf = MarfedKV::open(test_name, None, None).unwrap();
        let mut confirmed_clarity_instance =
            ClarityInstance::new(false, CHAIN_ID_TESTNET, confirmed_marf);
        let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

        let contract = "
        (define-data-var bar int 0)
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

        // make an empty but confirmed block
        confirmed_clarity_instance
            .begin_test_genesis_block(
                &StacksBlockId::sentinel(),
                &StacksBlockId([0; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            )
            .commit_block();

        let marf = MarfedKV::open_unconfirmed(test_name, None, None).unwrap();

        let genesis_metadata_entries = marf
            .sql_conn()
            .query_row::<u32, _, _>(
                "SELECT COUNT(value) FROM metadata_table",
                NO_PARAMS,
                |row| row.get(0),
            )
            .unwrap();

        let mut clarity_instance = ClarityInstance::new(false, CHAIN_ID_TESTNET, marf);

        // make an unconfirmed block off of the confirmed block
        {
            let mut conn = clarity_instance.begin_unconfirmed(
                &StacksBlockId([0; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            );

            conn.as_transaction(|conn| {
                let (ct_ast, ct_analysis) = conn
                    .analyze_smart_contract(
                        &contract_identifier,
                        ClarityVersion::Clarity1,
                        contract,
                    )
                    .unwrap();
                conn.initialize_smart_contract(
                    &contract_identifier,
                    ClarityVersion::Clarity1,
                    &ct_ast,
                    contract,
                    None,
                    |_, _| None,
                    None,
                )
                .unwrap();
                conn.save_analysis(&contract_identifier, &ct_analysis)
                    .unwrap();
            });

            conn.commit_unconfirmed();
        }

        // contract is still there, in unconfirmed status
        {
            let mut conn = clarity_instance.begin_unconfirmed(
                &StacksBlockId([0; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            );

            conn.as_transaction(|conn| {
                conn.with_clarity_db_readonly(|ref mut tx| {
                    let src = tx.get_contract_src(&contract_identifier).unwrap();
                    assert_eq!(src, contract);
                });
            });

            conn.rollback_block();
        }

        // contract is still there, in unconfirmed status, even though the conn got explicitly
        // rolled back (but that should only drop the current TrieRAM)
        {
            let mut conn = clarity_instance.begin_unconfirmed(
                &StacksBlockId([0; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            );

            conn.as_transaction(|conn| {
                conn.with_clarity_db_readonly(|ref mut tx| {
                    let src = tx.get_contract_src(&contract_identifier).unwrap();
                    assert_eq!(src, contract);
                });
            });

            conn.rollback_unconfirmed();
        }

        // contract is now absent, now that we did a rollback of unconfirmed state
        {
            let mut conn = clarity_instance.begin_unconfirmed(
                &StacksBlockId([0; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            );

            conn.as_transaction(|conn| {
                conn.with_clarity_db_readonly(|ref mut tx| {
                    assert!(tx.get_contract_src(&contract_identifier).is_none());
                });
            });

            conn.commit_unconfirmed();
        }

        let mut marf = clarity_instance.destroy();
        let mut conn = marf.begin_unconfirmed(&StacksBlockId([0; 32]));

        // should not be in the marf.
        assert_eq!(
            conn.get_contract_hash(&contract_identifier).unwrap_err(),
            RuntimeAnalysisError::NoSuchContract(contract_identifier.to_string()).into()
        );

        let sql = conn.get_side_store();
        // sqlite only have any metadata entries from the genesis block
        assert_eq!(
            genesis_metadata_entries,
            sql.query_row::<u32, _, _>(
                "SELECT COUNT(value) FROM metadata_table",
                NO_PARAMS,
                |row| row.get(0)
            )
            .unwrap()
        );
    }

    #[test]
    pub fn test_tx_roll_backs() {
        let marf = MarfedKV::temporary();
        let mut clarity_instance = ClarityInstance::new(false, CHAIN_ID_TESTNET, marf);
        let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();
        let sender = StandardPrincipalData::transient().into();

        clarity_instance
            .begin_test_genesis_block(
                &StacksBlockId::sentinel(),
                &StacksBlockId([0; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            )
            .commit_block();

        {
            let mut conn = clarity_instance.begin_block(
                &StacksBlockId([0; 32]),
                &StacksBlockId([1; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            );

            let contract = "
            (define-data-var bar int 0)
            (define-public (get-bar) (ok (var-get bar)))
            (define-public (set-bar (x int) (y int))
              (begin (var-set bar (/ x y)) (ok (var-get bar))))";

            conn.as_transaction(|conn| {
                let (ct_ast, ct_analysis) = conn
                    .analyze_smart_contract(
                        &contract_identifier,
                        ClarityVersion::Clarity1,
                        contract,
                    )
                    .unwrap();
                conn.initialize_smart_contract(
                    &contract_identifier,
                    ClarityVersion::Clarity1,
                    &ct_ast,
                    contract,
                    None,
                    |_, _| None,
                    None,
                )
                .unwrap();
                conn.save_analysis(&contract_identifier, &ct_analysis)
                    .unwrap();
            });

            assert_eq!(
                conn.as_transaction(|tx| tx.run_contract_call(
                    &sender,
                    None,
                    &contract_identifier,
                    "get-bar",
                    &[],
                    |_, _| None,
                    None
                ))
                .unwrap()
                .0,
                Value::okay(Value::Int(0)).unwrap()
            );

            assert_eq!(
                conn.as_transaction(|tx| tx.run_contract_call(
                    &sender,
                    None,
                    &contract_identifier,
                    "set-bar",
                    &[Value::Int(1), Value::Int(1)],
                    |_, _| None,
                    None
                ))
                .unwrap()
                .0,
                Value::okay(Value::Int(1)).unwrap()
            );

            let e = conn
                .as_transaction(|tx| {
                    tx.run_contract_call(
                        &sender,
                        None,
                        &contract_identifier,
                        "set-bar",
                        &[Value::Int(10), Value::Int(1)],
                        |_, _| Some("testing rollback".to_string()),
                        None,
                    )
                })
                .unwrap_err();
            let result_value = if let ClarityError::AbortedByCallback { output, .. } = e {
                output.unwrap()
            } else {
                panic!("Expects a AbortedByCallback error")
            };

            assert_eq!(*result_value, Value::okay(Value::Int(10)).unwrap());

            // prior transaction should have rolled back due to abort call back!
            assert_eq!(
                conn.as_transaction(|tx| tx.run_contract_call(
                    &sender,
                    None,
                    &contract_identifier,
                    "get-bar",
                    &[],
                    |_, _| None,
                    None
                ))
                .unwrap()
                .0,
                Value::okay(Value::Int(1)).unwrap()
            );

            assert!(format!(
                "{:?}",
                conn.as_transaction(|tx| tx.run_contract_call(
                    &sender,
                    None,
                    &contract_identifier,
                    "set-bar",
                    &[Value::Int(10), Value::Int(0)],
                    |_, _| Some("testing rollback".to_string()),
                    None
                ))
                .unwrap_err()
            )
            .contains("DivisionByZero"));

            // prior transaction should have rolled back due to runtime error
            assert_eq!(
                conn.as_transaction(|tx| tx.run_contract_call(
                    &StandardPrincipalData::transient().into(),
                    None,
                    &contract_identifier,
                    "get-bar",
                    &[],
                    |_, _| None,
                    None
                ))
                .unwrap()
                .0,
                Value::okay(Value::Int(1)).unwrap()
            );

            conn.commit_block();
        }
    }

    #[test]
    pub fn test_post_condition_failure_contract_publish() {
        use stacks_common::util::hash::Hash160;
        use stacks_common::util::secp256k1::MessageSignature;

        use crate::chainstate::stacks::db::*;
        use crate::chainstate::stacks::*;
        use crate::util_lib::strings::StacksString;

        let marf = MarfedKV::temporary();
        let mut clarity_instance = ClarityInstance::new(false, CHAIN_ID_TESTNET, marf);
        let sender: StacksAddress = StandardPrincipalData::transient().into();

        let spending_cond = TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
            signer: Hash160([0x11u8; 20]),
            hash_mode: SinglesigHashMode::P2PKH,
            key_encoding: TransactionPublicKeyEncoding::Compressed,
            nonce: 0,
            tx_fee: 1,
            signature: MessageSignature::from_raw(&[0xfe; 65]),
        });

        let contract = "(define-public (foo) (ok 1))";

        let mut tx1 = StacksTransaction::new(
            TransactionVersion::Mainnet,
            TransactionAuth::Standard(spending_cond.clone()),
            TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: "hello-world".into(),
                    code_body: StacksString::from_str(contract).unwrap(),
                },
                None,
            ),
        );

        let tx2 = StacksTransaction::new(
            TransactionVersion::Mainnet,
            TransactionAuth::Standard(spending_cond.clone()),
            TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: "hello-world".into(),
                    code_body: StacksString::from_str(contract).unwrap(),
                },
                None,
            ),
        );

        tx1.post_conditions.push(TransactionPostCondition::STX(
            PostConditionPrincipal::Origin,
            FungibleConditionCode::SentEq,
            100,
        ));

        let mut tx3 = StacksTransaction::new(
            TransactionVersion::Mainnet,
            TransactionAuth::Standard(spending_cond),
            TransactionPayload::ContractCall(TransactionContractCall {
                address: sender.clone(),
                contract_name: "hello-world".into(),
                function_name: "foo".into(),
                function_args: vec![],
            }),
        );

        tx3.post_conditions.push(TransactionPostCondition::STX(
            PostConditionPrincipal::Origin,
            FungibleConditionCode::SentEq,
            100,
        ));
        let stx_balance = STXBalance::initial(5000);
        let account = StacksAccount {
            principal: sender.into(),
            nonce: 0,
            stx_balance,
        };

        clarity_instance
            .begin_test_genesis_block(
                &StacksBlockId::sentinel(),
                &StacksBlockId([0; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            )
            .commit_block();

        {
            let mut conn = clarity_instance.begin_block(
                &StacksBlockId([0; 32]),
                &StacksBlockId([1; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            );

            conn.as_transaction(|clarity_tx| {
                let receipt =
                    StacksChainState::process_transaction_payload(clarity_tx, &tx1, &account, None)
                        .unwrap();
                assert!(receipt.post_condition_aborted);
            });
            conn.as_transaction(|clarity_tx| {
                StacksChainState::process_transaction_payload(clarity_tx, &tx2, &account, None)
                    .unwrap();
            });

            conn.as_transaction(|clarity_tx| {
                let receipt =
                    StacksChainState::process_transaction_payload(clarity_tx, &tx3, &account, None)
                        .unwrap();

                assert!(receipt.post_condition_aborted);
            });

            conn.commit_block();
        }
    }

    #[test]
    pub fn test_block_limit() {
        let marf = MarfedKV::temporary();
        let mut clarity_instance = ClarityInstance::new(false, CHAIN_ID_TESTNET, marf);
        let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();
        let sender = StandardPrincipalData::transient().into();

        pub struct BlockLimitBurnStateDB {}
        impl BurnStateDB for BlockLimitBurnStateDB {
            fn get_tip_burn_block_height(&self) -> Option<u32> {
                None
            }

            fn get_tip_sortition_id(&self) -> Option<SortitionId> {
                None
            }

            fn get_burn_block_height(&self, _sortition_id: &SortitionId) -> Option<u32> {
                None
            }

            fn get_burn_header_hash(
                &self,
                _height: u32,
                _sortition_id: &SortitionId,
            ) -> Option<BurnchainHeaderHash> {
                None
            }

            fn get_sortition_id_from_consensus_hash(
                &self,
                consensus_hash: &ConsensusHash,
            ) -> Option<SortitionId> {
                None
            }

            fn get_stacks_epoch(&self, _height: u32) -> Option<StacksEpoch> {
                // Note: We return this StacksEpoch for every input, because this test is not exercising
                // this method.
                Some(StacksEpoch {
                    epoch_id: StacksEpochId::Epoch20,
                    start_height: 0,
                    end_height: u64::MAX,
                    block_limit: ExecutionCost {
                        write_length: u64::MAX,
                        write_count: u64::MAX,
                        read_count: u64::MAX,
                        read_length: u64::MAX,
                        runtime: 100,
                    },
                    network_epoch: PEER_VERSION_EPOCH_2_0,
                })
            }

            fn get_stacks_epoch_by_epoch_id(
                &self,
                _epoch_id: &StacksEpochId,
            ) -> Option<StacksEpoch> {
                self.get_stacks_epoch(0)
            }

            fn get_v1_unlock_height(&self) -> u32 {
                u32::MAX
            }

            fn get_v2_unlock_height(&self) -> u32 {
                u32::MAX
            }

            fn get_v3_unlock_height(&self) -> u32 {
                u32::MAX
            }

            fn get_pox_3_activation_height(&self) -> u32 {
                u32::MAX
            }

            fn get_pox_4_activation_height(&self) -> u32 {
                u32::MAX
            }

            fn get_pox_prepare_length(&self) -> u32 {
                panic!("BlockLimitBurnStateDB should not return PoX info");
            }

            fn get_pox_reward_cycle_length(&self) -> u32 {
                panic!("BlockLimitBurnStateDB should not return PoX info");
            }

            fn get_pox_rejection_fraction(&self) -> u64 {
                panic!("BlockLimitBurnStateDB should not return PoX info");
            }
            fn get_burn_start_height(&self) -> u32 {
                0
            }
            fn get_pox_payout_addrs(
                &self,
                _height: u32,
                _sortition_id: &SortitionId,
            ) -> Option<(Vec<TupleData>, u128)> {
                return None;
            }
        }

        let burn_state_db = BlockLimitBurnStateDB {};
        clarity_instance
            .begin_test_genesis_block(
                &StacksBlockId::sentinel(),
                &StacksBlockId([0; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            )
            .commit_block();

        {
            let mut conn = clarity_instance.begin_block(
                &StacksBlockId([0; 32]),
                &StacksBlockId([1; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            );

            let contract = "
            (define-public (do-expand)
              (let ((list1 (list 1 2 3 4 5 6 7 8 9 10)))
                (let ((list2 (concat list1 list1)))
                  (let ((list3 (concat list2 list2)))
                    (let ((list4 (concat list3 list3)))
                      (ok (concat list4 list4)))))))
            ";

            conn.as_transaction(|conn| {
                let (ct_ast, ct_analysis) = conn
                    .analyze_smart_contract(
                        &contract_identifier,
                        ClarityVersion::Clarity1,
                        contract,
                    )
                    .unwrap();
                conn.initialize_smart_contract(
                    &contract_identifier,
                    ClarityVersion::Clarity1,
                    &ct_ast,
                    contract,
                    None,
                    |_, _| None,
                    None,
                )
                .unwrap();
                conn.save_analysis(&contract_identifier, &ct_analysis)
                    .unwrap();
            });

            conn.commit_block();
        }

        {
            let mut conn = clarity_instance.begin_block(
                &StacksBlockId([1; 32]),
                &StacksBlockId([2; 32]),
                &TEST_HEADER_DB,
                &burn_state_db,
            );
            assert!(match conn
                .as_transaction(|tx| tx.run_contract_call(
                    &sender,
                    None,
                    &contract_identifier,
                    "do-expand",
                    &[],
                    |_, _| None,
                    None
                ))
                .unwrap_err()
            {
                ClarityError::CostError(total, limit) => {
                    eprintln!("{}, {}", total, limit);
                    limit.runtime == 100 && total.runtime > 100
                }
                x => {
                    eprintln!("{}", x);
                    false
                }
            });

            conn.commit_block();
        }
    }
}
