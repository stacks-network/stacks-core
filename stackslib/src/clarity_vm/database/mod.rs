use std::ops::{Deref, DerefMut};

use clarity::util::hash::Sha512Trunc256Sum;
use clarity::vm::analysis::AnalysisDatabase;
use clarity::vm::database::sqlite::{
    sqlite_get_contract_hash, sqlite_get_metadata, sqlite_get_metadata_manual,
    sqlite_insert_metadata,
};
use clarity::vm::database::{
    BurnStateDB, ClarityBackingStore, ClarityDatabase, HeadersDB, SpecialCaseHandler,
    SqliteConnection, NULL_BURN_STATE_DB, NULL_HEADER_DB,
};
use clarity::vm::errors::{InterpreterResult, RuntimeErrorType};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, TupleData};
use rusqlite::{Connection, OptionalExtension, Row, ToSql};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, SortitionId, StacksAddress, StacksBlockId,
    VRFSeed,
};
use stacks_common::types::Address;
use stacks_common::util::vrf::VRFProof;

use crate::chainstate::burn::db::sortdb::{
    get_ancestor_sort_id, get_ancestor_sort_id_tx, SortitionDB, SortitionDBConn, SortitionHandle,
    SortitionHandleConn, SortitionHandleTx,
};
use crate::chainstate::stacks::boot::PoxStartCycleInfo;
use crate::chainstate::stacks::db::accounts::MinerReward;
use crate::chainstate::stacks::db::{
    ChainstateTx, MinerPaymentSchedule, StacksChainState, StacksHeaderInfo,
};
use crate::chainstate::stacks::index::marf::{MarfConnection, MARF};
use crate::chainstate::stacks::index::{ClarityMarfTrieId, MarfTrieId, TrieMerkleProof};
use crate::chainstate::stacks::Error as ChainstateError;
use crate::clarity_vm::special::handle_contract_call_special_cases;
use crate::core::{StacksEpoch, StacksEpochId};
use crate::util_lib::db::{DBConn, FromColumn, FromRow};

pub mod marf;

pub struct HeadersDBConn<'a>(pub &'a Connection);

impl<'a> HeadersDB for HeadersDBConn<'a> {
    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BlockHeaderHash> {
        get_stacks_header_column(self.0, id_bhh, "block_hash", |r| {
            BlockHeaderHash::from_column(r, "block_hash").expect("FATAL: malformed block hash")
        })
    }

    fn get_burn_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BurnchainHeaderHash> {
        get_stacks_header_column(self.0, id_bhh, "burn_header_hash", |r| {
            BurnchainHeaderHash::from_row(r).expect("FATAL: malformed burn_header_hash")
        })
    }

    fn get_consensus_hash_for_block(&self, id_bhh: &StacksBlockId) -> Option<ConsensusHash> {
        get_stacks_header_column(self.0, id_bhh, "consensus_hash", |r| {
            ConsensusHash::from_row(r).expect("FATAL: malformed consensus_hash")
        })
    }

    fn get_burn_block_time_for_block(&self, id_bhh: &StacksBlockId) -> Option<u64> {
        get_stacks_header_column(self.0, id_bhh, "burn_header_timestamp", |r| {
            u64::from_row(r).expect("FATAL: malformed burn_header_timestamp")
        })
    }

    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32> {
        get_stacks_header_column(self.0, id_bhh, "burn_header_height", |r| {
            u64::from_row(r)
                .expect("FATAL: malformed burn_header_height")
                .try_into()
                .expect("FATAL: blockchain too long")
        })
    }

    fn get_vrf_seed_for_block(&self, id_bhh: &StacksBlockId) -> Option<VRFSeed> {
        get_stacks_header_column(self.0, id_bhh, "proof", |r| {
            let proof = VRFProof::from_column(r, "proof").expect("FATAL: malformed proof");
            VRFSeed::from_proof(&proof)
        })
    }

    fn get_miner_address(&self, id_bhh: &StacksBlockId) -> Option<StacksAddress> {
        get_miner_column(self.0, id_bhh, "address", |r| {
            let s: String = r.get_unwrap("address");
            let addr = StacksAddress::from_string(&s).expect("FATAL: malformed address");
            addr
        })
    }

    fn get_burnchain_tokens_spent_for_block(&self, id_bhh: &StacksBlockId) -> Option<u128> {
        get_miner_column(self.0, id_bhh, "burnchain_sortition_burn", |r| {
            u64::from_row(r).expect("FATAL: malformed sortition burn")
        })
        .map(|x| x.into())
    }

    fn get_burnchain_tokens_spent_for_winning_block(&self, id_bhh: &StacksBlockId) -> Option<u128> {
        get_miner_column(self.0, id_bhh, "burnchain_commit_burn", |r| {
            u64::from_row(r).expect("FATAL: malformed commit burn")
        })
        .map(|x| x.into())
    }

    fn get_tokens_earned_for_block(&self, id_bhh: &StacksBlockId) -> Option<u128> {
        get_matured_reward(self.0, id_bhh).map(|x| x.total().into())
    }
}

impl<'a> HeadersDB for ChainstateTx<'a> {
    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BlockHeaderHash> {
        get_stacks_header_column(self.deref().deref(), id_bhh, "block_hash", |r| {
            BlockHeaderHash::from_column(r, "block_hash").expect("FATAL: malformed block hash")
        })
    }

    fn get_burn_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BurnchainHeaderHash> {
        get_stacks_header_column(self.deref().deref(), id_bhh, "burn_header_hash", |r| {
            BurnchainHeaderHash::from_row(r).expect("FATAL: malformed burn_header_hash")
        })
    }

    fn get_consensus_hash_for_block(&self, id_bhh: &StacksBlockId) -> Option<ConsensusHash> {
        get_stacks_header_column(self.deref().deref(), id_bhh, "consensus_hash", |r| {
            ConsensusHash::from_row(r).expect("FATAL: malformed consensus_hash")
        })
    }

    fn get_burn_block_time_for_block(&self, id_bhh: &StacksBlockId) -> Option<u64> {
        get_stacks_header_column(self.deref().deref(), id_bhh, "burn_header_timestamp", |r| {
            u64::from_row(r).expect("FATAL: malformed burn_header_timestamp")
        })
    }

    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32> {
        get_stacks_header_column(self.deref().deref(), id_bhh, "burn_header_height", |r| {
            u64::from_row(r)
                .expect("FATAL: malformed burn_header_height")
                .try_into()
                .expect("FATAL: blockchain too long")
        })
    }

    fn get_vrf_seed_for_block(&self, id_bhh: &StacksBlockId) -> Option<VRFSeed> {
        get_stacks_header_column(self.deref().deref(), id_bhh, "proof", |r| {
            let proof = VRFProof::from_column(r, "proof").expect("FATAL: malformed proof");
            VRFSeed::from_proof(&proof)
        })
    }

    fn get_miner_address(&self, id_bhh: &StacksBlockId) -> Option<StacksAddress> {
        get_miner_column(self.deref().deref(), id_bhh, "address", |r| {
            let s: String = r.get_unwrap("address");
            let addr = StacksAddress::from_string(&s).expect("FATAL: malformed address");
            addr
        })
    }

    fn get_burnchain_tokens_spent_for_block(&self, id_bhh: &StacksBlockId) -> Option<u128> {
        get_miner_column(
            self.deref().deref(),
            id_bhh,
            "burnchain_sortition_burn",
            |r| u64::from_row(r).expect("FATAL: malformed sortition burn"),
        )
        .map(|x| x.into())
    }

    fn get_burnchain_tokens_spent_for_winning_block(&self, id_bhh: &StacksBlockId) -> Option<u128> {
        get_miner_column(self.deref().deref(), id_bhh, "burnchain_commit_burn", |r| {
            u64::from_row(r).expect("FATAL: malformed commit burn")
        })
        .map(|x| x.into())
    }

    fn get_tokens_earned_for_block(&self, id_bhh: &StacksBlockId) -> Option<u128> {
        get_matured_reward(self.deref().deref(), id_bhh).map(|x| x.total().into())
    }
}

impl HeadersDB for MARF<StacksBlockId> {
    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BlockHeaderHash> {
        get_stacks_header_column(self.sqlite_conn(), id_bhh, "block_hash", |r| {
            BlockHeaderHash::from_column(r, "block_hash").expect("FATAL: malformed block hash")
        })
    }

    fn get_burn_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BurnchainHeaderHash> {
        get_stacks_header_column(self.sqlite_conn(), id_bhh, "burn_header_hash", |r| {
            BurnchainHeaderHash::from_row(r).expect("FATAL: malformed burn_header_hash")
        })
    }

    fn get_consensus_hash_for_block(&self, id_bhh: &StacksBlockId) -> Option<ConsensusHash> {
        get_stacks_header_column(self.sqlite_conn(), id_bhh, "consensus_hash", |r| {
            ConsensusHash::from_row(r).expect("FATAL: malformed consensus_hash")
        })
    }

    fn get_burn_block_time_for_block(&self, id_bhh: &StacksBlockId) -> Option<u64> {
        get_stacks_header_column(self.sqlite_conn(), id_bhh, "burn_header_timestamp", |r| {
            u64::from_row(r).expect("FATAL: malformed burn_header_timestamp")
        })
    }

    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32> {
        get_stacks_header_column(self.sqlite_conn(), id_bhh, "burn_header_height", |r| {
            u64::from_row(r)
                .expect("FATAL: malformed burn_header_height")
                .try_into()
                .expect("FATAL: blockchain too long")
        })
    }

    fn get_vrf_seed_for_block(&self, id_bhh: &StacksBlockId) -> Option<VRFSeed> {
        get_stacks_header_column(self.sqlite_conn(), id_bhh, "proof", |r| {
            let proof = VRFProof::from_column(r, "proof").expect("FATAL: malformed proof");
            VRFSeed::from_proof(&proof)
        })
    }

    fn get_miner_address(&self, id_bhh: &StacksBlockId) -> Option<StacksAddress> {
        get_miner_column(self.sqlite_conn(), id_bhh, "address", |r| {
            let s: String = r.get_unwrap("address");
            let addr = StacksAddress::from_string(&s).expect("FATAL: malformed address");
            addr
        })
    }

    fn get_burnchain_tokens_spent_for_block(&self, id_bhh: &StacksBlockId) -> Option<u128> {
        get_miner_column(
            self.sqlite_conn(),
            id_bhh,
            "burnchain_sortition_burn",
            |r| u64::from_row(r).expect("FATAL: malformed sortition burn"),
        )
        .map(|x| x.into())
    }

    fn get_burnchain_tokens_spent_for_winning_block(&self, id_bhh: &StacksBlockId) -> Option<u128> {
        get_miner_column(self.sqlite_conn(), id_bhh, "burnchain_commit_burn", |r| {
            u64::from_row(r).expect("FATAL: malformed commit burn")
        })
        .map(|x| x.into())
    }

    fn get_tokens_earned_for_block(&self, id_bhh: &StacksBlockId) -> Option<u128> {
        get_matured_reward(self.sqlite_conn(), id_bhh).map(|x| x.total().into())
    }
}

fn get_stacks_header_column<F, R>(
    conn: &DBConn,
    id_bhh: &StacksBlockId,
    column_name: &str,
    loader: F,
) -> Option<R>
where
    F: Fn(&Row) -> R,
{
    let args: &[&dyn ToSql] = &[id_bhh];
    if let Some(result) = conn
        .query_row(
            &format!(
                "SELECT {} FROM block_headers WHERE index_block_hash = ?",
                column_name
            ),
            args,
            |x| Ok(loader(x)),
        )
        .optional()
        .unwrap_or_else(|_| {
            panic!(
                "Unexpected SQL failure querying block header table for '{}'",
                column_name
            )
        })
    {
        return Some(result);
    }
    // if nothing was found in `block_headers`, try `nakamoto_block_headers`
    conn.query_row(
        &format!(
            "SELECT {} FROM nakamoto_block_headers WHERE index_block_hash = ?",
            column_name
        ),
        args,
        |x| Ok(loader(x)),
    )
    .optional()
    .unwrap_or_else(|_| {
        panic!(
            "Unexpected SQL failure querying block header table for '{}'",
            column_name
        )
    })
}

fn get_miner_column<F, R>(
    conn: &DBConn,
    id_bhh: &StacksBlockId,
    column_name: &str,
    loader: F,
) -> Option<R>
where
    F: FnOnce(&Row) -> R,
{
    let args: &[&dyn ToSql] = &[id_bhh];
    conn.query_row(
        &format!(
            "SELECT {} FROM payments WHERE index_block_hash = ? AND miner = 1",
            column_name
        ),
        args,
        |x| Ok(loader(x)),
    )
    .optional()
    .unwrap_or_else(|_| {
        panic!(
            "Unexpected SQL failure querying miner payment table for '{}'",
            column_name
        )
    })
}

fn get_matured_reward(conn: &DBConn, child_id_bhh: &StacksBlockId) -> Option<MinerReward> {
    let parent_id_bhh = conn
        .query_row(
            "SELECT parent_block_id FROM block_headers WHERE index_block_hash = ?",
            [child_id_bhh].iter(),
            |x| {
                Ok(StacksBlockId::from_column(x, "parent_block_id")
                    .expect("Bad parent_block_id in database"))
            },
        )
        .optional()
        .expect("Unexpected SQL failure querying parent block ID");

    if let Some(parent_id_bhh) = parent_id_bhh {
        StacksChainState::get_matured_miner_payment(conn, &parent_id_bhh, child_id_bhh)
            .expect("Unexpected SQL failure querying miner reward table")
    } else {
        None
    }
}

/// This trait describes SortitionDB connections. This is used
/// for methods that the chainstate needs to be in common between
/// different sortition db connections or handles, but that aren't
/// used by the `clarity_db` (and therefore shouldn't appear in BurnStateDB)
pub trait SortitionDBRef: BurnStateDB {
    fn get_pox_start_cycle_info(
        &self,
        sortition_id: &SortitionId,
        parent_stacks_block_burn_ht: u64,
        cycle_index: u64,
    ) -> Result<Option<PoxStartCycleInfo>, ChainstateError>;

    /// Return an upcasted dynamic reference for the sortition DB
    fn as_burn_state_db(&self) -> &dyn BurnStateDB;

    /// Return a pointer to the underlying sqlite connection or transaction for
    /// this DB reference
    fn sqlite_conn(&self) -> &Connection;
}

fn get_pox_start_cycle_info(
    handle: &mut SortitionHandleConn,
    parent_stacks_block_burn_ht: u64,
    cycle_index: u64,
) -> Result<Option<PoxStartCycleInfo>, ChainstateError> {
    let descended_from_last_pox_anchor = match handle.get_last_anchor_block_hash()? {
        Some(pox_anchor) => handle.descended_from(parent_stacks_block_burn_ht, &pox_anchor)?,
        None => return Ok(None),
    };

    if !descended_from_last_pox_anchor {
        return Ok(None);
    }

    let start_info = handle.get_reward_cycle_unlocks(cycle_index)?;
    debug!(
        "get_pox_start_cycle_info";
        "start_info" => ?start_info,
    );
    Ok(start_info)
}

impl SortitionDBRef for SortitionHandleTx<'_> {
    fn get_pox_start_cycle_info(
        &self,
        sortition_id: &SortitionId,
        parent_stacks_block_burn_ht: u64,
        cycle_index: u64,
    ) -> Result<Option<PoxStartCycleInfo>, ChainstateError> {
        let readonly_marf = self
            .index()
            .reopen_readonly()
            .expect("BUG: failure trying to get a read-only interface into the sortition db.");
        let mut context = self.context.clone();
        context.chain_tip = sortition_id.clone();
        let mut handle = SortitionHandleConn::new(&readonly_marf, context);

        get_pox_start_cycle_info(&mut handle, parent_stacks_block_burn_ht, cycle_index)
    }

    fn as_burn_state_db(&self) -> &dyn BurnStateDB {
        self
    }

    fn sqlite_conn(&self) -> &Connection {
        self.tx()
    }
}

impl SortitionDBRef for SortitionDBConn<'_> {
    fn get_pox_start_cycle_info(
        &self,
        sortition_id: &SortitionId,
        parent_stacks_block_burn_ht: u64,
        cycle_index: u64,
    ) -> Result<Option<PoxStartCycleInfo>, ChainstateError> {
        let mut handle = self.as_handle(sortition_id);
        get_pox_start_cycle_info(&mut handle, parent_stacks_block_burn_ht, cycle_index)
    }

    fn as_burn_state_db(&self) -> &dyn BurnStateDB {
        self
    }

    fn sqlite_conn(&self) -> &Connection {
        self.conn()
    }
}

impl BurnStateDB for SortitionHandleTx<'_> {
    fn get_burn_block_height(&self, sortition_id: &SortitionId) -> Option<u32> {
        match SortitionDB::get_block_snapshot(self.tx(), sortition_id) {
            Ok(Some(x)) => Some(x.block_height as u32),
            _ => return None,
        }
    }

    /// Returns Some if `0 <= height < get_burn_block_height(sorition_id)`, and None otherwise.
    fn get_burn_header_hash(
        &self,
        height: u32,
        sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        let readonly_marf = self
            .index()
            .reopen_readonly()
            .expect("BUG: failure trying to get a read-only interface into the sortition db.");
        let mut context = self.context.clone();
        context.chain_tip = sortition_id.clone();
        let db_handle = SortitionHandleConn::new(&readonly_marf, context);
        match db_handle.get_block_snapshot_by_height(height as u64) {
            Ok(Some(x)) => Some(x.burn_header_hash),
            _ => return None,
        }
    }

    fn get_sortition_id_from_consensus_hash(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Option<SortitionId> {
        match SortitionDB::get_block_snapshot_consensus(self.tx(), consensus_hash) {
            Ok(Some(x)) => Some(x.sortition_id),
            _ => return None,
        }
    }

    fn get_stacks_epoch(&self, height: u32) -> Option<StacksEpoch> {
        SortitionDB::get_stacks_epoch(self.tx(), height as u64)
            .expect("BUG: failed to get epoch for burn block height")
    }

    fn get_burn_start_height(&self) -> u32 {
        self.context.first_block_height as u32
    }

    fn get_v1_unlock_height(&self) -> u32 {
        self.context.pox_constants.v1_unlock_height
    }

    fn get_v2_unlock_height(&self) -> u32 {
        self.context.pox_constants.v2_unlock_height
    }

    fn get_v3_unlock_height(&self) -> u32 {
        self.context.pox_constants.v3_unlock_height
    }

    fn get_pox_3_activation_height(&self) -> u32 {
        self.context.pox_constants.pox_3_activation_height
    }

    fn get_pox_4_activation_height(&self) -> u32 {
        self.context.pox_constants.pox_4_activation_height
    }

    fn get_pox_prepare_length(&self) -> u32 {
        self.context.pox_constants.prepare_length
    }

    fn get_pox_reward_cycle_length(&self) -> u32 {
        self.context.pox_constants.reward_cycle_length
    }

    fn get_pox_rejection_fraction(&self) -> u64 {
        self.context.pox_constants.pox_rejection_fraction
    }
    fn get_stacks_epoch_by_epoch_id(&self, epoch_id: &StacksEpochId) -> Option<StacksEpoch> {
        SortitionDB::get_stacks_epoch_by_epoch_id(self.tx(), epoch_id)
            .expect("BUG: failed to get epoch for epoch id")
    }
    fn get_pox_payout_addrs(
        &self,
        height: u32,
        sortition_id: &SortitionId,
    ) -> Option<(Vec<TupleData>, u128)> {
        let readonly_marf = self
            .index()
            .reopen_readonly()
            .expect("BUG: failure trying to get a read-only interface into the sortition db.");
        let mut context = self.context.clone();
        context.chain_tip = sortition_id.clone();
        let db_handle = SortitionHandleConn::new(&readonly_marf, context);

        let get_from = match get_ancestor_sort_id(&db_handle, height.into(), sortition_id)
            .expect("FATAL: failed to query sortition DB")
        {
            Some(sort_id) => sort_id,
            None => {
                return None;
            }
        };

        let (pox_addrs, payout) = self
            .get_reward_set_payouts_at(&get_from)
            .expect("FATAL: failed to query payouts");

        let addrs = pox_addrs
            .into_iter()
            .map(|addr| {
                addr.as_clarity_tuple()
                    .expect("FATAL: sortition DB did not store hash mode for PoX address")
            })
            .collect();

        Some((addrs, payout))
    }
    fn get_ast_rules(&self, height: u32) -> clarity::vm::ast::ASTRules {
        SortitionDB::get_ast_rules(self.tx(), height.into()).expect("BUG: failed to get AST rules")
    }
}

impl BurnStateDB for SortitionDBConn<'_> {
    fn get_burn_block_height(&self, sortition_id: &SortitionId) -> Option<u32> {
        match SortitionDB::get_block_snapshot(self.conn(), sortition_id) {
            Ok(Some(x)) => Some(x.block_height as u32),
            _ => return None,
        }
    }

    fn get_burn_header_hash(
        &self,
        height: u32,
        sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        let db_handle = SortitionHandleConn::open_reader(self, &sortition_id).ok()?;

        let current_height = match self.get_burn_block_height(sortition_id) {
            None => {
                return None;
            }
            Some(height) => height,
        };

        if height > current_height {
            return None;
        }

        match db_handle.get_block_snapshot_by_height(height as u64) {
            Ok(Some(x)) => Some(x.burn_header_hash),
            _ => return None,
        }
    }

    fn get_sortition_id_from_consensus_hash(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Option<SortitionId> {
        match SortitionDB::get_block_snapshot_consensus(self.conn(), consensus_hash) {
            Ok(Some(x)) => Some(x.sortition_id),
            _ => return None,
        }
    }

    fn get_stacks_epoch(&self, height: u32) -> Option<StacksEpoch> {
        SortitionDB::get_stacks_epoch(self.conn(), height as u64)
            .expect("BUG: failed to get epoch for burn block height")
    }

    fn get_burn_start_height(&self) -> u32 {
        self.context.first_block_height as u32
    }

    fn get_v1_unlock_height(&self) -> u32 {
        self.context.pox_constants.v1_unlock_height
    }

    fn get_v2_unlock_height(&self) -> u32 {
        self.context.pox_constants.v2_unlock_height
    }

    fn get_v3_unlock_height(&self) -> u32 {
        self.context.pox_constants.v3_unlock_height
    }

    fn get_pox_3_activation_height(&self) -> u32 {
        self.context.pox_constants.pox_3_activation_height
    }

    fn get_pox_4_activation_height(&self) -> u32 {
        self.context.pox_constants.pox_4_activation_height
    }

    fn get_pox_prepare_length(&self) -> u32 {
        self.context.pox_constants.prepare_length
    }

    fn get_pox_reward_cycle_length(&self) -> u32 {
        self.context.pox_constants.reward_cycle_length
    }

    fn get_pox_rejection_fraction(&self) -> u64 {
        self.context.pox_constants.pox_rejection_fraction
    }
    fn get_stacks_epoch_by_epoch_id(&self, epoch_id: &StacksEpochId) -> Option<StacksEpoch> {
        SortitionDB::get_stacks_epoch_by_epoch_id(self.conn(), epoch_id)
            .expect("BUG: failed to get epoch for epoch id")
    }
    fn get_pox_payout_addrs(
        &self,
        height: u32,
        sortition_id: &SortitionId,
    ) -> Option<(Vec<TupleData>, u128)> {
        let get_from = match get_ancestor_sort_id(self, height.into(), sortition_id)
            .expect("FATAL: failed to query sortition DB")
        {
            Some(sort_id) => sort_id,
            None => {
                return None;
            }
        };

        let (pox_addrs, payout) = self
            .get_reward_set_payouts_at(&get_from)
            .expect("FATAL: failed to query payouts");

        let addrs = pox_addrs
            .into_iter()
            .map(|addr| {
                addr.as_clarity_tuple()
                    .expect("FATAL: sortition DB did not store hash mode for PoX address")
            })
            .collect();

        Some((addrs, payout))
    }
    fn get_ast_rules(&self, height: u32) -> clarity::vm::ast::ASTRules {
        SortitionDB::get_ast_rules(self.conn(), height.into())
            .expect("BUG: failed to get AST rules")
    }
}

pub struct MemoryBackingStore {
    side_store: Connection,
}

impl MemoryBackingStore {
    pub fn new() -> MemoryBackingStore {
        let side_store = SqliteConnection::memory().unwrap();

        let mut memory_marf = MemoryBackingStore { side_store };

        memory_marf.as_clarity_db().initialize();

        memory_marf
    }

    pub fn as_clarity_db<'a>(&'a mut self) -> ClarityDatabase<'a> {
        ClarityDatabase::new(self, &NULL_HEADER_DB, &NULL_BURN_STATE_DB)
    }

    /// Returns a new ClarityDatabase with underlying databases `headers_db` and
    /// `burn_state_db`.
    pub fn as_clarity_db_with_databases<'a>(
        &'a mut self,
        headers_db: &'a dyn HeadersDB,
        burn_state_db: &'a dyn BurnStateDB,
    ) -> ClarityDatabase<'a> {
        ClarityDatabase::new(self, headers_db, burn_state_db)
    }

    pub fn as_analysis_db<'a>(&'a mut self) -> AnalysisDatabase<'a> {
        AnalysisDatabase::new(self)
    }
}

impl ClarityBackingStore for MemoryBackingStore {
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> InterpreterResult<StacksBlockId> {
        Err(RuntimeErrorType::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0)).into())
    }

    fn get_data(&mut self, key: &str) -> InterpreterResult<Option<String>> {
        SqliteConnection::get(self.get_side_store(), key)
    }

    fn get_data_with_proof(&mut self, key: &str) -> InterpreterResult<Option<(String, Vec<u8>)>> {
        Ok(SqliteConnection::get(self.get_side_store(), key)?.map(|x| (x, vec![])))
    }

    fn get_side_store(&mut self) -> &Connection {
        &self.side_store
    }

    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId> {
        if height == 0 {
            Some(StacksBlockId::sentinel())
        } else {
            None
        }
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        StacksBlockId::sentinel()
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        0
    }

    fn get_current_block_height(&mut self) -> u32 {
        0
    }

    fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        Some(&handle_contract_call_special_cases)
    }

    fn put_all_data(&mut self, items: Vec<(String, String)>) -> InterpreterResult<()> {
        for (key, value) in items.into_iter() {
            SqliteConnection::put(self.get_side_store(), &key, &value)?;
        }
        Ok(())
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
