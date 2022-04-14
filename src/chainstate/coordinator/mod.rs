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

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::SyncSender;
use std::time::Duration;

use burnchains::{
    db::{BurnchainBlockData, BurnchainDB},
    Address, Burnchain, BurnchainBlockHeader, Error as BurnchainError, Txid,
};
use chainstate::burn::{
    db::sortdb::SortitionDB, operations::leader_block_commit::RewardSetInfo,
    operations::BlockstackOperationType, BlockSnapshot, ConsensusHash,
};
use chainstate::coordinator::comm::{
    ArcCounterCoordinatorNotices, CoordinatorEvents, CoordinatorNotices, CoordinatorReceivers,
};
use chainstate::stacks::index::MarfTrieId;
use chainstate::stacks::{
    db::{
        accounts::MinerReward, ChainStateBootData, ClarityTx, MinerRewardInfo, StacksChainState,
        StacksHeaderInfo,
    },
    events::{StacksTransactionEvent, StacksTransactionReceipt, TransactionOrigin},
    Error as ChainstateError, StacksBlock, TransactionPayload,
};
use core::StacksEpoch;
use monitoring::{
    increment_contract_calls_processed, increment_stx_blocks_processed_counter,
    update_stacks_tip_height,
};
use net::atlas::{AtlasConfig, AttachmentInstance};
use util::db::Error as DBError;
use vm::{
    costs::ExecutionCost,
    types::{PrincipalData, QualifiedContractIdentifier},
    SymbolicExpression, Value,
};

use crate::cost_estimates::{CostEstimator, FeeEstimator, PessimisticEstimator};
use crate::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, PoxId, SortitionId, StacksAddress, StacksBlockHeader,
    StacksBlockId,
};
use crate::util::boot::boot_code_id;
use vm::database::BurnStateDB;

pub use self::comm::CoordinatorCommunication;
use chainstate::burn::db::sortdb::{SortitionDBConn, SortitionHandleTx};
use chainstate::stacks::boot::exit_at_reward_cycle_test_id;
use chainstate::stacks::db::StacksEpochReceipt;
use chainstate::stacks::index::marf::MarfConnection;
use chainstate::stacks::Error::PoxNoRewardCycle;
use clarity_vm::clarity::ClarityConnection;
use core::{
    BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
    POX_REWARD_CYCLE_LENGTH,
};
use std::iter::FromIterator;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use util;
use util::db::Error::{Corruption, NotFoundError};
use util::sleep_ms;
use vm::costs::LimitedCostTracker;
use vm::database::ClarityDatabase;
use vm::types::{StandardPrincipalData, TupleData};

pub mod comm;
#[cfg(test)]
pub mod tests;

/// The 3 different states for the current
///  reward cycle's relationship to its PoX anchor
#[derive(Debug, PartialEq)]
pub enum PoxAnchorBlockStatus {
    SelectedAndKnown(BlockHeaderHash, Vec<StacksAddress>),
    SelectedAndUnknown(BlockHeaderHash),
    NotSelected,
}

/// This struct is generated for each Stacks block, and holds metadata relating to the exit
/// contract. It tracks the current exit proposal as well as the current agreed upon exit height.
/// It is ultimately stored in the table `exit_at_reward_cycle_info` in the sortition DB.
#[derive(Debug)]
pub struct BlockExitRewardCycleInfo {
    /// The reward cycle of the block that corresponds to this exit cycle information
    pub block_reward_cycle: u64,
    /// This value is non-None when consensus has been achieved on a vote; the cycle after this
    /// proposal was voted on will be a rejection period for miners
    pub curr_exit_proposal: Option<u64>,
    /// The current exit reward cycle for node (can be None; when set, this values rises monotonically)
    pub curr_exit_at_reward_cycle: Option<u64>,
    /// A list of reward cycles to skip over when tallying votes (these are cycles that were
    /// previously proposed and/or rejected).
    pub invalid_reward_cycles: Vec<u64>,
}

#[derive(Debug, PartialEq)]
pub struct RewardCycleInfo {
    pub anchor_status: PoxAnchorBlockStatus,
}

impl RewardCycleInfo {
    pub fn selected_anchor_block(&self) -> Option<&BlockHeaderHash> {
        use self::PoxAnchorBlockStatus::*;
        match self.anchor_status {
            SelectedAndUnknown(ref block) | SelectedAndKnown(ref block, _) => Some(block),
            NotSelected => None,
        }
    }
    pub fn is_reward_info_known(&self) -> bool {
        use self::PoxAnchorBlockStatus::*;
        match self.anchor_status {
            SelectedAndUnknown(_) => false,
            SelectedAndKnown(_, _) | NotSelected => true,
        }
    }
    pub fn known_selected_anchor_block(&self) -> Option<&Vec<StacksAddress>> {
        use self::PoxAnchorBlockStatus::*;
        match self.anchor_status {
            SelectedAndUnknown(_) => None,
            SelectedAndKnown(_, ref reward_set) => Some(reward_set),
            NotSelected => None,
        }
    }
    pub fn known_selected_anchor_block_owned(self) -> Option<Vec<StacksAddress>> {
        use self::PoxAnchorBlockStatus::*;
        match self.anchor_status {
            SelectedAndUnknown(_) => None,
            SelectedAndKnown(_, reward_set) => Some(reward_set),
            NotSelected => None,
        }
    }
}

pub trait BlockEventDispatcher {
    fn announce_block(
        &self,
        block: StacksBlock,
        metadata: StacksHeaderInfo,
        receipts: Vec<StacksTransactionReceipt>,
        parent: &StacksBlockId,
        winner_txid: Txid,
        matured_rewards: Vec<MinerReward>,
        matured_rewards_info: Option<MinerRewardInfo>,
        parent_burn_block_hash: BurnchainHeaderHash,
        parent_burn_block_height: u32,
        parent_burn_block_timestamp: u64,
        anchored_consumed: &ExecutionCost,
        mblock_confirmed_consumed: &ExecutionCost,
    );

    /// called whenever a burn block is about to be
    ///  processed for sortition. note, in the event
    ///  of PoX forks, this will be called _multiple_
    ///  times for the same burnchain header hash.
    fn announce_burn_block(
        &self,
        burn_block: &BurnchainHeaderHash,
        burn_block_height: u64,
        rewards: Vec<(StacksAddress, u64)>,
        burns: u64,
        reward_recipients: Vec<StacksAddress>,
    );

    fn dispatch_boot_receipts(&mut self, receipts: Vec<StacksTransactionReceipt>);
}

pub struct ChainsCoordinator<
    'a,
    T: BlockEventDispatcher,
    N: CoordinatorNotices,
    R: RewardSetProvider,
    CE: CostEstimator + ?Sized,
    FE: FeeEstimator + ?Sized,
> {
    canonical_sortition_tip: Option<SortitionId>,
    canonical_chain_tip: Option<StacksBlockId>,
    canonical_pox_id: Option<PoxId>,
    burnchain_blocks_db: BurnchainDB,
    chain_state_db: StacksChainState,
    sortition_db: SortitionDB,
    burnchain: Burnchain,
    attachments_tx: SyncSender<HashSet<AttachmentInstance>>,
    dispatcher: Option<&'a T>,
    cost_estimator: Option<&'a mut CE>,
    fee_estimator: Option<&'a mut FE>,
    reward_set_provider: R,
    notifier: N,
    atlas_config: AtlasConfig,
    should_keep_running: Arc<AtomicBool>,
}

#[derive(Debug)]
pub enum Error {
    BurnchainBlockAlreadyProcessed,
    BurnchainError(BurnchainError),
    ChainstateError(ChainstateError),
    NonContiguousBurnchainBlock(BurnchainError),
    NoSortitions,
    FailedToProcessSortition(BurnchainError),
    DBError(DBError),
    NotPrepareEndBlock,
}

impl From<BurnchainError> for Error {
    fn from(o: BurnchainError) -> Error {
        Error::BurnchainError(o)
    }
}

impl From<ChainstateError> for Error {
    fn from(o: ChainstateError) -> Error {
        Error::ChainstateError(o)
    }
}

impl From<DBError> for Error {
    fn from(o: DBError) -> Error {
        Error::DBError(o)
    }
}

pub trait RewardSetProvider {
    fn get_reward_set(
        &self,
        current_burn_height: u64,
        chainstate: &mut StacksChainState,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        block_id: &StacksBlockId,
    ) -> Result<Vec<StacksAddress>, Error>;
}

pub struct OnChainRewardSetProvider();

impl RewardSetProvider for OnChainRewardSetProvider {
    fn get_reward_set(
        &self,
        current_burn_height: u64,
        chainstate: &mut StacksChainState,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        block_id: &StacksBlockId,
    ) -> Result<Vec<StacksAddress>, Error> {
        let registered_addrs =
            chainstate.get_reward_addresses(burnchain, sortdb, current_burn_height, block_id)?;

        let liquid_ustx = chainstate.get_liquid_ustx(block_id);

        let (threshold, participation) = StacksChainState::get_reward_threshold_and_participation(
            &burnchain.pox_constants,
            &registered_addrs,
            liquid_ustx,
        );

        if !burnchain
            .pox_constants
            .enough_participation(participation, liquid_ustx)
        {
            info!("PoX reward cycle did not have enough participation. Defaulting to burn";
                  "burn_height" => current_burn_height,
                  "participation" => participation,
                  "liquid_ustx" => liquid_ustx,
                  "registered_addrs" => registered_addrs.len());
            return Ok(vec![]);
        } else {
            info!("PoX reward cycle threshold computed";
                  "burn_height" => current_burn_height,
                  "threshold" => threshold,
                  "participation" => participation,
                  "liquid_ustx" => liquid_ustx,
                  "registered_addrs" => registered_addrs.len());
        }

        Ok(StacksChainState::make_reward_set(
            threshold,
            registered_addrs,
        ))
    }
}

impl<'a, T: BlockEventDispatcher, CE: CostEstimator + ?Sized, FE: FeeEstimator + ?Sized>
    ChainsCoordinator<'a, T, ArcCounterCoordinatorNotices, OnChainRewardSetProvider, CE, FE>
{
    pub fn run(
        chain_state_db: StacksChainState,
        burnchain: Burnchain,
        attachments_tx: SyncSender<HashSet<AttachmentInstance>>,
        dispatcher: &'a mut T,
        comms: CoordinatorReceivers,
        atlas_config: AtlasConfig,
        cost_estimator: Option<&mut CE>,
        fee_estimator: Option<&mut FE>,
        should_keep_running: Arc<AtomicBool>,
    ) where
        T: BlockEventDispatcher,
    {
        let stacks_blocks_processed = comms.stacks_blocks_processed.clone();
        let sortitions_processed = comms.sortitions_processed.clone();

        let sortition_db = SortitionDB::open(&burnchain.get_db_path(), true).unwrap();
        let burnchain_blocks_db =
            BurnchainDB::open(&burnchain.get_burnchaindb_path(), false).unwrap();

        let canonical_sortition_tip =
            SortitionDB::get_canonical_sortition_tip(sortition_db.conn()).unwrap();

        let arc_notices = ArcCounterCoordinatorNotices {
            stacks_blocks_processed,
            sortitions_processed,
        };

        let mut inst = ChainsCoordinator {
            canonical_chain_tip: None,
            canonical_sortition_tip: Some(canonical_sortition_tip),
            canonical_pox_id: None,
            burnchain_blocks_db,
            chain_state_db,
            sortition_db,
            burnchain,
            attachments_tx,
            dispatcher: Some(dispatcher),
            notifier: arc_notices,
            reward_set_provider: OnChainRewardSetProvider(),
            cost_estimator,
            fee_estimator,
            atlas_config,
            should_keep_running,
        };

        loop {
            // timeout so that we handle Ctrl-C a little gracefully
            match comms.wait_on() {
                CoordinatorEvents::NEW_STACKS_BLOCK => {
                    debug!("Received new stacks block notice");
                    if let Err(e) = inst.handle_new_stacks_block() {
                        warn!("Error processing new stacks block: {:?}", e);
                    }
                }
                CoordinatorEvents::NEW_BURN_BLOCK => {
                    debug!("Received new burn block notice");
                    if let Err(e) = inst.handle_new_burnchain_block() {
                        warn!("Error processing new burn block: {:?}", e);
                    }
                }
                CoordinatorEvents::STOP => {
                    debug!("Received stop notice");
                    return;
                }
                CoordinatorEvents::TIMEOUT => {}
            }
        }
    }
}

impl<'a, T: BlockEventDispatcher, U: RewardSetProvider> ChainsCoordinator<'a, T, (), U, (), ()> {
    #[cfg(test)]
    pub fn test_new(
        burnchain: &Burnchain,
        chain_id: u32,
        path: &str,
        reward_set_provider: U,
        attachments_tx: SyncSender<HashSet<AttachmentInstance>>,
    ) -> ChainsCoordinator<'a, T, (), U, (), ()> {
        ChainsCoordinator::test_new_with_observer(
            burnchain,
            chain_id,
            path,
            reward_set_provider,
            attachments_tx,
            None,
        )
    }

    #[cfg(test)]
    pub fn test_new_with_observer(
        burnchain: &Burnchain,
        chain_id: u32,
        path: &str,
        reward_set_provider: U,
        attachments_tx: SyncSender<HashSet<AttachmentInstance>>,
        dispatcher: Option<&'a T>,
    ) -> ChainsCoordinator<'a, T, (), U, (), ()> {
        let burnchain = burnchain.clone();

        let mut boot_data = ChainStateBootData::new(&burnchain, vec![], None);

        let sortition_db = SortitionDB::open(&burnchain.get_db_path(), true).unwrap();
        let burnchain_blocks_db =
            BurnchainDB::open(&burnchain.get_burnchaindb_path(), false).unwrap();
        let (chain_state_db, _) = StacksChainState::open_and_exec(
            false,
            chain_id,
            &format!("{}/chainstate/", path),
            Some(&mut boot_data),
        )
        .unwrap();
        let canonical_sortition_tip =
            SortitionDB::get_canonical_sortition_tip(sortition_db.conn()).unwrap();

        ChainsCoordinator {
            canonical_chain_tip: None,
            canonical_sortition_tip: Some(canonical_sortition_tip),
            canonical_pox_id: None,
            burnchain_blocks_db,
            chain_state_db,
            sortition_db,
            burnchain,
            dispatcher,
            cost_estimator: None,
            fee_estimator: None,
            reward_set_provider,
            notifier: (),
            attachments_tx,
            atlas_config: AtlasConfig::default(false),
            should_keep_running: Arc::new(AtomicBool::new(true)),
        }
    }
}

pub fn get_next_recipients<U: RewardSetProvider>(
    sortition_tip: &BlockSnapshot,
    chain_state: &mut StacksChainState,
    sort_db: &mut SortitionDB,
    burnchain: &Burnchain,
    provider: &U,
) -> Result<Option<RewardSetInfo>, Error> {
    let reward_cycle_info = get_reward_cycle_info(
        sortition_tip.block_height + 1,
        &sortition_tip.burn_header_hash,
        &sortition_tip.sortition_id,
        burnchain,
        chain_state,
        sort_db,
        provider,
    )?;
    sort_db
        .get_next_block_recipients(burnchain, sortition_tip, reward_cycle_info.as_ref())
        .map_err(|e| Error::from(e))
}

/// returns None if this burnchain block is _not_ the start of a reward cycle
///         otherwise, returns the required reward cycle info for this burnchain block
///                     in our current sortition view:
///           * PoX anchor block
///           * Was PoX anchor block known?
pub fn get_reward_cycle_info<U: RewardSetProvider>(
    burn_height: u64,
    parent_bhh: &BurnchainHeaderHash,
    sortition_tip: &SortitionId,
    burnchain: &Burnchain,
    chain_state: &mut StacksChainState,
    sort_db: &SortitionDB,
    provider: &U,
) -> Result<Option<RewardCycleInfo>, Error> {
    if burnchain.is_reward_cycle_start(burn_height) {
        if burn_height >= burnchain.pox_constants.sunset_end {
            return Ok(Some(RewardCycleInfo {
                anchor_status: PoxAnchorBlockStatus::NotSelected,
            }));
        }

        debug!("Beginning reward cycle";
              "burn_height" => burn_height,
              "reward_cycle_length" => burnchain.pox_constants.reward_cycle_length,
              "prepare_phase_length" => burnchain.pox_constants.prepare_length);

        let reward_cycle_info = {
            let ic = sort_db.index_handle(sortition_tip);
            ic.get_chosen_pox_anchor(&parent_bhh, &burnchain.pox_constants)
        }?;
        if let Some((consensus_hash, stacks_block_hash)) = reward_cycle_info {
            info!("Anchor block selected: {}", stacks_block_hash);
            let anchor_block_known = StacksChainState::is_stacks_block_processed(
                &chain_state.db(),
                &consensus_hash,
                &stacks_block_hash,
            )?;
            let anchor_status = if anchor_block_known {
                let block_id =
                    StacksBlockHeader::make_index_block_hash(&consensus_hash, &stacks_block_hash);
                let reward_set = provider.get_reward_set(
                    burn_height,
                    chain_state,
                    burnchain,
                    sort_db,
                    &block_id,
                )?;
                PoxAnchorBlockStatus::SelectedAndKnown(stacks_block_hash, reward_set)
            } else {
                PoxAnchorBlockStatus::SelectedAndUnknown(stacks_block_hash)
            };
            Ok(Some(RewardCycleInfo { anchor_status }))
        } else {
            Ok(Some(RewardCycleInfo {
                anchor_status: PoxAnchorBlockStatus::NotSelected,
            }))
        }
    } else {
        Ok(None)
    }
}

struct PaidRewards {
    pox: Vec<(StacksAddress, u64)>,
    burns: u64,
}

fn calculate_paid_rewards(ops: &[BlockstackOperationType]) -> PaidRewards {
    let mut reward_recipients: HashMap<_, u64> = HashMap::new();
    let mut burn_amt = 0;
    for op in ops.iter() {
        if let BlockstackOperationType::LeaderBlockCommit(commit) = op {
            if commit.commit_outs.len() == 0 {
                continue;
            }
            let amt_per_address = commit.burn_fee / (commit.commit_outs.len() as u64);
            for addr in commit.commit_outs.iter() {
                if addr.is_burn() {
                    burn_amt += amt_per_address;
                } else {
                    if let Some(prior_amt) = reward_recipients.get_mut(addr) {
                        *prior_amt += amt_per_address;
                    } else {
                        reward_recipients.insert(addr.clone(), amt_per_address);
                    }
                }
            }
        }
    }
    PaidRewards {
        pox: reward_recipients.into_iter().collect(),
        burns: burn_amt,
    }
}

fn dispatcher_announce_burn_ops<T: BlockEventDispatcher>(
    dispatcher: &T,
    burn_header: &BurnchainBlockHeader,
    paid_rewards: PaidRewards,
    reward_recipient_info: Option<RewardSetInfo>,
) {
    let recipients = if let Some(recip_info) = reward_recipient_info {
        recip_info
            .recipients
            .into_iter()
            .map(|(addr, _)| addr)
            .collect()
    } else {
        vec![]
    };

    dispatcher.announce_burn_block(
        &burn_header.block_hash,
        burn_header.block_height,
        paid_rewards.pox,
        paid_rewards.burns,
        recipients,
    );
}

impl<
        'a,
        T: BlockEventDispatcher,
        N: CoordinatorNotices,
        U: RewardSetProvider,
        CE: CostEstimator + ?Sized,
        FE: FeeEstimator + ?Sized,
    > ChainsCoordinator<'a, T, N, U, CE, FE>
{
    pub fn handle_new_stacks_block(&mut self) -> Result<(), Error> {
        if let Some(pox_anchor) = self.process_ready_blocks()? {
            self.process_new_pox_anchor(pox_anchor)
        } else {
            Ok(())
        }
    }

    pub fn handle_new_burnchain_block(&mut self) -> Result<(), Error> {
        // Retrieve canonical burnchain chain tip from the BurnchainBlocksDB
        let canonical_burnchain_tip = self.burnchain_blocks_db.get_canonical_chain_tip()?;
        debug!("Handle new canonical burnchain tip";
               "height" => %canonical_burnchain_tip.block_height,
               "block_hash" => %canonical_burnchain_tip.block_hash.to_string());

        // Retrieve all the direct ancestors of this block with an unprocessed sortition
        let mut cursor = canonical_burnchain_tip.block_hash.clone();
        let mut sortitions_to_process = VecDeque::new();

        // We halt the ancestry research as soon as we find a processed parent
        let mut last_processed_ancestor = loop {
            if let Some(found_sortition) = self.sortition_db.is_sortition_processed(&cursor)? {
                break found_sortition;
            }

            let current_block = self
                .burnchain_blocks_db
                .get_burnchain_block(&cursor)
                .map_err(|e| {
                    warn!(
                        "ChainsCoordinator: could not retrieve  block burnhash={}",
                        &cursor
                    );
                    Error::NonContiguousBurnchainBlock(e)
                })?;

            let parent = current_block.header.parent_block_hash.clone();
            sortitions_to_process.push_front(current_block);
            cursor = parent;
        };

        let burn_header_hashes: Vec<_> = sortitions_to_process
            .iter()
            .map(|block| block.header.block_hash.to_string())
            .collect();

        debug!(
            "Unprocessed burn chain blocks [{}]",
            burn_header_hashes.join(", ")
        );

        for unprocessed_block in sortitions_to_process.into_iter() {
            let BurnchainBlockData { header, ops } = unprocessed_block;

            // calculate paid rewards during this burnchain block if we announce
            //  to an events dispatcher
            let paid_rewards = if self.dispatcher.is_some() {
                calculate_paid_rewards(&ops)
            } else {
                PaidRewards {
                    pox: vec![],
                    burns: 0,
                }
            };

            // at this point, we need to figure out if the sortition we are
            //  about to process is the first block in the exit reward cycle.
            if self.reached_exit_reward_cycle(&header)? {
                sleep_ms(30000);
                self.should_keep_running.store(false, Ordering::SeqCst);
                return Ok(());
            }

            let reward_cycle_info = self.get_reward_cycle_info(&header)?;
            let (next_snapshot, _, reward_set_info) = self
                .sortition_db
                .evaluate_sortition(
                    &header,
                    ops,
                    &self.burnchain,
                    &last_processed_ancestor,
                    reward_cycle_info,
                )
                .map_err(|e| {
                    error!("ChainsCoordinator: unable to evaluate sortition {:?}", e);
                    Error::FailedToProcessSortition(e)
                })?;

            if let Some(dispatcher) = self.dispatcher {
                dispatcher_announce_burn_ops(dispatcher, &header, paid_rewards, reward_set_info);
            }

            let sortition_id = next_snapshot.sortition_id;

            self.notifier.notify_sortition_processed();

            debug!(
                "Sortition processed";
                "sortition_id" => &sortition_id.to_string(),
                "burn_header_hash" => &next_snapshot.burn_header_hash.to_string(),
                "burn_height" => next_snapshot.block_height
            );

            // always bump canonical sortition tip:
            //   if this code path is invoked, the canonical burnchain tip
            //   has moved, so we should move our canonical sortition tip as well.
            self.canonical_sortition_tip = Some(sortition_id.clone());
            last_processed_ancestor = sortition_id;

            if let Some(pox_anchor) = self.process_ready_blocks()? {
                return self.process_new_pox_anchor(pox_anchor);
            }
        }

        Ok(())
    }

    /// This function reads rejection-related information from the exit-at-rc clarity contract.
    /// It returns true if the rejection succeeded, and false if it failed.
    pub fn read_rejection_state(
        &mut self,
        rc_cycle_of_rejection: u64,
        proposed_exit_rc: u64,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
        exit_contract_id: &QualifiedContractIdentifier,
    ) -> Result<bool, Error> {
        let stacks_block_id = StacksBlockHeader::make_index_block_hash(consensus_hash, block_hash);
        let reward_cycle_length = self.burnchain.pox_constants.reward_cycle_length;
        let rejection_percent_threshold = self
            .burnchain
            .exit_contract_constants
            .rejection_confirmation_percent;
        let is_mainnet = self.burnchain.is_mainnet();
        self.chain_state_db
            .with_read_only_clarity_tx(&self.sortition_db.index_conn(), &stacks_block_id, |conn| {
                conn.with_clarity_db_readonly(|db| {
                    // from map rc-proposal-rejections, use key pair (proposed_rc, curr_rc) to get the # of rejections
                    let entry = db
                        .fetch_entry_unknown_descriptor(
                            exit_contract_id,
                            "rc-proposal-rejections",
                            &Value::from(
                                TupleData::from_data(vec![
                                    ("proposed-rc".into(), Value::UInt(proposed_exit_rc as u128)),
                                    ("curr-rc".into(), Value::UInt(rc_cycle_of_rejection as u128)),
                                ])
                                .expect("BUG: failed to construct simple tuple"),
                            ),
                        )
                        .expect("BUG: Failed querying rc-proposal-rejections")
                        .expect_optional();

                    let num_rejections = match entry {
                        Some(val) => {
                            let tuple_data = val.expect_tuple();
                            tuple_data
                                .get("rejections")
                                .expect("BUG: malformed cost proposal tuple")
                                .to_owned()
                                .expect_u128()
                        }
                        None => 0,
                    };

                    info!(
                        "chains coordinator: in rejection check, proposed_exit: {}, num num_rejections: {:?}",
                        proposed_exit_rc, num_rejections
                    );
                    // Check if the percent rejection crosses the minimum threshold
                    let percent_rejection = num_rejections * 100 / (reward_cycle_length as u128);

                    Ok(percent_rejection >= (rejection_percent_threshold as u128))
                })
            })
            .ok_or(Error::DBError(NotFoundError))?
    }

    /// Returns map of exit proposals to the number of votes for each, as well as the sum total of all
    /// votes.
    /// The range of this map corresponds to rc_cycle_of_vote + EXIT_RC_MINIMUM_RC_BUFFER_FROM_PRESENT
    /// to rc_cycle_of_vote + EXIT_RC_MAXIMUM_RC_BUFFER_FROM_PRESENT.
    pub fn read_vote_state(
        &mut self,
        rc_cycle_of_vote: u64,
        curr_exit_at_rc_opt: Option<u64>,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
        invalid_reward_cycles: Vec<u64>,
        exit_contract_id: &QualifiedContractIdentifier,
    ) -> Result<(BTreeMap<u64, u128>, u128), Error> {
        let stacks_block_id = StacksBlockHeader::make_index_block_hash(consensus_hash, block_hash);
        let mut vote_map = BTreeMap::new();
        let mut min_rc = self
            .burnchain
            .exit_contract_constants
            .absolute_minimum_exit_rc
            .max(
                rc_cycle_of_vote
                    + self
                        .burnchain
                        .exit_contract_constants
                        .minimum_rc_buffer_from_present,
            );
        let max_rc = rc_cycle_of_vote
            + self
                .burnchain
                .exit_contract_constants
                .maximum_rc_buffer_from_present;

        // Check what value is stored for the current exit at rc.
        // If there is an existing exit rc, make sure the minimum rc we consider for the votes is
        // greater than it.
        if let Some(curr_exit_at_rc) = curr_exit_at_rc_opt {
            min_rc = min_rc.max(curr_exit_at_rc + 1);
        }

        let mut total_votes = 0;
        let invalid_reward_cycles: HashSet<u64> =
            HashSet::from_iter(invalid_reward_cycles.into_iter());
        let is_mainnet = self.burnchain.is_mainnet();

        self.chain_state_db
            .with_read_only_clarity_tx(&self.sortition_db.index_conn(), &stacks_block_id, |conn| {
                conn.with_clarity_db_readonly(|db| {
                    for proposed_exit_rc in min_rc..max_rc {
                        if invalid_reward_cycles.contains(&proposed_exit_rc) {
                            continue;
                        }
                        // from map rc-proposal-votes, use key pair (proposed_rc, curr_rc) to get the # of votes
                        let entry_res = db.fetch_entry_unknown_descriptor(
                            &exit_contract_id,
                            "rc-proposal-votes",
                            &Value::from(
                                TupleData::from_data(vec![
                                    ("proposed-rc".into(), Value::UInt(proposed_exit_rc as u128)),
                                    ("curr-rc".into(), Value::UInt(rc_cycle_of_vote as u128)),
                                ])
                                .expect("BUG: failed to construct simple tuple"),
                            ),
                        );
                        if let Ok(entry) = entry_res {
                            let entry_opt = entry.expect_optional();
                            match entry_opt {
                                Some(entry) => {
                                    let entry = entry.expect_tuple();
                                    let num_votes = entry
                                        .get("votes")
                                        .expect("BUG: malformed cost proposal tuple")
                                        .to_owned()
                                        .expect_u128();

                                    vote_map.insert(proposed_exit_rc, num_votes);
                                    total_votes += num_votes;
                                }
                                None => {}
                            };
                        } else {
                            info!("BUG: Unable to load exit contract map: {:?}", entry_res);
                        }
                    }
                })
            })
            .ok_or(Error::DBError(NotFoundError))?;

        Ok((vote_map, total_votes))
    }

    /// At the end of each reward cycle, we tally the votes for the exit at RC contract.
    /// We need to read PoX contract state to see how much STX is stacked into the protocol - we then
    /// ensure that at least 50% of staked STX has a valid vote.
    /// Regarding vote validity: we discard votes for invalid reward cycles. Examples of invalid
    /// reward cycles include those that are the absolute minimum exit cycle, or those below a
    /// previously confirmed exit RC.
    /// This function returns a result. If ok, it returns an option of the agreed upon
    /// proposal for the exit reward cycle, where the option is None is there is no valid proposal.
    pub fn tally_votes(
        &mut self,
        rc_cycle_of_vote: u64,
        curr_exit_at_rc_opt: Option<u64>,
        invalid_reward_cycles: Vec<u64>,
        curr_block_hash: &BlockHeaderHash,
        curr_block_consensus_hash: &ConsensusHash,
        exit_contract_id: &QualifiedContractIdentifier,
    ) -> Result<Option<u64>, Error> {
        let stacks_block_id =
            StacksBlockHeader::make_index_block_hash(curr_block_consensus_hash, curr_block_hash);
        // read STX contract state
        let stacks_tip = SortitionDB::get_block_snapshot_consensus(
            self.sortition_db.conn(),
            curr_block_consensus_hash,
        )?
        .ok_or(Error::ChainstateError(ChainstateError::NoSuchBlockError))?;

        // ensure that PoX is active
        let is_pox_active = self.sortition_db.is_pox_active_in_reward_cycle(
            rc_cycle_of_vote,
            &self.burnchain,
            &stacks_tip,
        )?;
        if !is_pox_active {
            return Ok(None);
        }

        let stacked_stx = self.chain_state_db.get_total_ustx_stacked(
            &self.sortition_db,
            &stacks_block_id,
            rc_cycle_of_vote as u128,
        )?;
        // Want to round up here, so calculating (x + n - 1) / n here instead of (x / n)
        let min_stx_for_valid_vote = ((stacked_stx
            * self
                .burnchain
                .exit_contract_constants
                .percent_stacked_stx_for_valid_vote as u128)
            + 99)
            / 100;

        // obtain map of exit proposal to number of valid votes
        let (vote_map, total_votes) = self.read_vote_state(
            rc_cycle_of_vote,
            curr_exit_at_rc_opt,
            curr_block_consensus_hash,
            curr_block_hash,
            invalid_reward_cycles,
            exit_contract_id,
        )?;

        // ensure that there are enough votes for a valid vote
        if total_votes < min_stx_for_valid_vote as u128 {
            return Ok(None);
        }

        // Explanation of voting mechanics: a vote to exit at RC x is a vote for the blockchain to
        // exit at RC x OR higher. To count the votes, we iterate from the lowest to the highest
        // valid exit proposal in the vote map, until the total accrued votes surpasses the
        // threshold for consensus.
        let min_stx_for_consensus = (min_stx_for_valid_vote
            * self
                .burnchain
                .exit_contract_constants
                .vote_confirmation_percent as u128
            + 99)
            / 100;
        let mut accrued_votes = 0;
        // Since vote map is a BTreeMap, iteration over keys will occur in a sorted order
        for (curr_rc_proposal, curr_votes) in vote_map.iter() {
            accrued_votes += curr_votes;
            if accrued_votes > min_stx_for_consensus {
                // If the accrued votes is greater than the minimum needed to achieve consensus,
                // store this value for the upcoming rejection
                return Ok(Some(*curr_rc_proposal));
            }
        }
        Ok(None)
    }

    pub fn reached_exit_reward_cycle(&self, header: &BurnchainBlockHeader) -> Result<bool, Error> {
        let current_reward_cycle = self
            .burnchain
            .block_height_to_reward_cycle(header.block_height as u64)
            .ok_or_else(|| DBError::NotFoundError)?;
        let exit_info_opt = SortitionDB::get_exit_at_reward_cycle_info(
            self.sortition_db.conn(),
            current_reward_cycle,
        )?;

        if let Some(exit_info) = exit_info_opt {
            if let Some(exit_reward_cycle) = exit_info.curr_exit_at_reward_cycle {
                // get the first reward cycle in this epoch
                let epochs = SortitionDB::get_stacks_epochs(self.sortition_db.conn())?;
                let curr_epoch = StacksEpoch::get_current_epoch(&epochs, header.block_height);
                let first_reward_cycle_in_epoch = self
                    .burnchain
                    .block_height_to_reward_cycle(curr_epoch.start_height)
                    .ok_or(Error::ChainstateError(PoxNoRewardCycle))?;

                let curr_reward_cycle = self
                    .burnchain
                    .block_height_to_reward_cycle(header.block_height)
                    .ok_or(Error::ChainstateError(PoxNoRewardCycle))?;
                if curr_reward_cycle >= exit_reward_cycle
                    && exit_reward_cycle > first_reward_cycle_in_epoch
                {
                    // the burnchain has reached the exit reward cycle (as voted in the
                    // "exit-at-rc" contract)
                    info!("Reached the exit reward cycle that was voted on in the \
                                'exit-at-rc' contract, ignoring subsequent burn blocks";
                                       "exit_reward_cycle" => exit_reward_cycle,
                                       "current_reward_cycle" => curr_reward_cycle);
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// returns None if this burnchain block is _not_ the start of a reward cycle
    ///         otherwise, returns the required reward cycle info for this burnchain block
    ///                     in our current sortition view:
    ///           * PoX anchor block
    ///           * Was PoX anchor block known?
    pub fn get_reward_cycle_info(
        &mut self,
        burn_header: &BurnchainBlockHeader,
    ) -> Result<Option<RewardCycleInfo>, Error> {
        let sortition_tip_id = self
            .canonical_sortition_tip
            .as_ref()
            .expect("FATAL: Processing anchor block, but no known sortition tip");

        get_reward_cycle_info(
            burn_header.block_height,
            &burn_header.parent_block_hash,
            sortition_tip_id,
            &self.burnchain,
            &mut self.chain_state_db,
            &self.sortition_db,
            &self.reward_set_provider,
        )
    }

    fn process_exit_reward_cycle(
        &mut self,
        block_receipt: &StacksEpochReceipt,
        block_hash: &BlockHeaderHash,
        canonical_sortition_tip: &SortitionId,
        exit_contract_id: &QualifiedContractIdentifier,
    ) -> Result<(), Error> {
        let current_block_height = block_receipt.header.burn_header_height as u64;
        let current_reward_cycle = self
            .burnchain
            .block_height_to_reward_cycle(current_block_height)
            .ok_or_else(|| DBError::NotFoundError)?;
        let parent_reward_cycle = self
            .burnchain
            .block_height_to_reward_cycle(block_receipt.parent_burn_block_height as u64)
            .ok_or_else(|| DBError::NotFoundError)?;

        if parent_reward_cycle < current_reward_cycle {
            // set up data
            let mut current_exit_at_rc = None;
            let mut current_proposal = None;
            let mut invalid_reward_cycles = vec![];

            // get the exit reward cycle info for the parent's reward cycle
            let exit_info_opt = SortitionDB::get_exit_at_reward_cycle_info(
                self.sortition_db.conn(),
                parent_reward_cycle,
            )?;
            if let Some(parent_exit_info) = exit_info_opt {
                // copy over some information from the parent exit info object
                current_exit_at_rc = parent_exit_info.curr_exit_at_reward_cycle;
                invalid_reward_cycles = parent_exit_info
                    .invalid_reward_cycles
                    .iter()
                    .filter(|rc| **rc > current_reward_cycle)
                    .map(|rc| *rc)
                    .collect();

                // Check if there is some proposal. If so, need to check for a rejection.
                if let Some(curr_exit_proposal) = parent_exit_info.curr_exit_proposal {
                    let rejection_passed = self.read_rejection_state(
                        parent_exit_info.block_reward_cycle,
                        curr_exit_proposal,
                        &block_receipt.header.consensus_hash,
                        &block_hash,
                        exit_contract_id,
                    )?;
                    // if rejection fails, record exit block height
                    if !rejection_passed {
                        info!(
                            "RCPR: cc: rejection did not pass for {}",
                            curr_exit_proposal
                        );
                        current_exit_at_rc = Some(curr_exit_proposal);
                    }
                } else {
                    // tally votes of previous reward cycle if there is no rejection happening
                    // if there is consensus for some proposal, record it
                    current_proposal = self.tally_votes(
                        parent_exit_info.block_reward_cycle,
                        parent_exit_info.curr_exit_at_reward_cycle,
                        parent_exit_info.invalid_reward_cycles,
                        &block_hash,
                        &block_receipt.header.consensus_hash,
                        exit_contract_id,
                    )?;
                    if let Some(exit_proposal) = current_proposal {
                        info!("RCPR: storing proposal info for {:?}", exit_proposal);
                        // record the proposal in invalid_reward_cycles
                        invalid_reward_cycles.push(exit_proposal);
                    }
                }
            } else {
                warn!(
                    "Block exit reward cycle info not found for reward cycle: {}",
                    parent_reward_cycle
                );
            }

            let exit_info = BlockExitRewardCycleInfo {
                block_reward_cycle: current_reward_cycle,
                curr_exit_proposal: current_proposal,
                curr_exit_at_reward_cycle: current_exit_at_rc,
                invalid_reward_cycles,
            };
            info!("RCPR: cc: exit info is: {:?}", exit_info);
            let sortdb_tx = self
                .sortition_db
                .tx_handle_begin(&canonical_sortition_tip)?;
            sortdb_tx.store_exit_at_reward_cycle_info(exit_info)?;
            sortdb_tx.commit()?;
        }

        Ok(())
    }

    ///
    /// Process any ready staging blocks until there are either:
    ///   * there are no more to process
    ///   * a PoX anchor block is processed which invalidates the current PoX fork
    ///
    /// Returns Some(StacksBlockId) if such an anchor block is discovered,
    ///   otherwise returns None
    ///
    fn process_ready_blocks(&mut self) -> Result<Option<BlockHeaderHash>, Error> {
        let canonical_sortition_tip = self.canonical_sortition_tip.clone().expect(
            "FAIL: processing a new Stacks block, but don't have a canonical sortition tip",
        );

        let sortdb_handle = self
            .sortition_db
            .tx_handle_begin(&canonical_sortition_tip)?;
        let mut processed_blocks = self.chain_state_db.process_blocks(sortdb_handle, 1)?;
        let stacks_tip = SortitionDB::get_canonical_burn_chain_tip(self.sortition_db.conn())?;
        update_stacks_tip_height(stacks_tip.canonical_stacks_tip_height as i64);

        while let Some(block_result) = processed_blocks.pop() {
            if let (Some(block_receipt), _) = block_result {
                // only bump the coordinator's state if the processed block
                //   is in our sortition fork
                //  TODO: we should update the staging block logic to prevent
                //    blocks like these from getting processed at all.
                let in_sortition_set = self.sortition_db.is_stacks_block_in_sortition_set(
                    &canonical_sortition_tip,
                    &block_receipt.header.anchored_header.block_hash(),
                )?;
                if in_sortition_set {
                    let new_canonical_block_snapshot = SortitionDB::get_block_snapshot(
                        self.sortition_db.conn(),
                        &canonical_sortition_tip,
                    )?
                    .expect(&format!(
                        "FAIL: could not find data for the canonical sortition {}",
                        &canonical_sortition_tip
                    ));
                    let new_canonical_stacks_block =
                        new_canonical_block_snapshot.get_canonical_stacks_block_id();
                    self.canonical_chain_tip = Some(new_canonical_stacks_block);
                    debug!("Bump blocks processed");
                    self.notifier.notify_stacks_block_processed();
                    increment_stx_blocks_processed_counter();

                    let block_hash = block_receipt.header.anchored_header.block_hash();

                    let mut attachments_instances = HashSet::new();
                    for receipt in block_receipt.tx_receipts.iter() {
                        if let TransactionOrigin::Stacks(ref transaction) = receipt.transaction {
                            if let TransactionPayload::ContractCall(ref contract_call) =
                                transaction.payload
                            {
                                let contract_id = contract_call.to_clarity_contract_id();
                                increment_contract_calls_processed();
                                if self.atlas_config.contracts.contains(&contract_id) {
                                    for event in receipt.events.iter() {
                                        if let StacksTransactionEvent::SmartContractEvent(
                                            ref event_data,
                                        ) = event
                                        {
                                            let res = AttachmentInstance::try_new_from_value(
                                                &event_data.value,
                                                &contract_id,
                                                block_receipt.header.index_block_hash(),
                                                block_receipt.header.block_height,
                                                receipt.transaction.txid(),
                                            );
                                            if let Some(attachment_instance) = res {
                                                attachments_instances.insert(attachment_instance);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if !attachments_instances.is_empty() {
                        info!(
                            "Atlas: {} attachment instances emitted from events",
                            attachments_instances.len()
                        );
                        match self.attachments_tx.send(attachments_instances) {
                            Ok(_) => {}
                            Err(e) => {
                                error!("Atlas: error dispatching attachments {}", e);
                            }
                        };
                    }

                    if let Some(ref mut estimator) = self.cost_estimator {
                        let stacks_epoch = self
                            .sortition_db
                            .index_conn()
                            .get_stacks_epoch_by_epoch_id(&block_receipt.evaluated_epoch)
                            .expect("Could not find a stacks epoch.");
                        estimator.notify_block(
                            &block_receipt.tx_receipts,
                            &stacks_epoch.block_limit,
                            &stacks_epoch.epoch_id,
                        );
                    }

                    if let Some(ref mut estimator) = self.fee_estimator {
                        let stacks_epoch = self
                            .sortition_db
                            .index_conn()
                            .get_stacks_epoch_by_epoch_id(&block_receipt.evaluated_epoch)
                            .expect("Could not find a stacks epoch.");
                        if let Err(e) =
                            estimator.notify_block(&block_receipt, &stacks_epoch.block_limit)
                        {
                            warn!("FeeEstimator failed to process block receipt";
                                  "stacks_block" => %block_hash,
                                  "stacks_height" => %block_receipt.header.block_height,
                                  "error" => %e);
                        }
                    }

                    // compute and store information relating to exiting at a reward cycle
                    if let Some(exit_contract_id) = self.burnchain.exit_contract_id.clone() {
                        self.process_exit_reward_cycle(
                            &block_receipt,
                            &block_hash,
                            &canonical_sortition_tip,
                            &exit_contract_id,
                        )?;
                    }

                    if let Some(dispatcher) = self.dispatcher {
                        let metadata = &block_receipt.header;
                        let winner_txid = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &self.sortition_db.index_conn(),
                            &canonical_sortition_tip,
                            &block_hash,
                        )
                        .expect("FAIL: could not find block snapshot for winning block hash")
                        .expect("FAIL: could not find block snapshot for winning block hash")
                        .winning_block_txid;

                        let block: StacksBlock = {
                            let block_path = StacksChainState::get_block_path(
                                &self.chain_state_db.blocks_path,
                                &metadata.consensus_hash,
                                &block_hash,
                            )
                            .unwrap();
                            StacksChainState::consensus_load(&block_path).unwrap()
                        };
                        let stacks_block =
                            StacksBlockId::new(&metadata.consensus_hash, &block_hash);

                        let parent = self
                            .chain_state_db
                            .get_parent(&stacks_block)
                            .expect("BUG: failed to get parent for processed block");

                        dispatcher.announce_block(
                            block,
                            block_receipt.header.clone(),
                            block_receipt.tx_receipts,
                            &parent,
                            winner_txid,
                            block_receipt.matured_rewards,
                            block_receipt.matured_rewards_info,
                            block_receipt.parent_burn_block_hash,
                            block_receipt.parent_burn_block_height,
                            block_receipt.parent_burn_block_timestamp,
                            &block_receipt.anchored_block_cost,
                            &block_receipt.parent_microblocks_cost,
                        );
                    }

                    // if, just after processing the block, we _know_ that this block is a pox anchor, that means
                    //   that sortitions have already begun processing that didn't know about this pox anchor.
                    //   we need to trigger an unwind
                    if let Some(pox_anchor) = self
                        .sortition_db
                        .is_stacks_block_pox_anchor(&block_hash, &canonical_sortition_tip)?
                    {
                        info!("Discovered an old anchor block: {}", &pox_anchor);
                        return Ok(Some(pox_anchor));
                    }
                }
            }
            // TODO: do something with a poison result

            let sortdb_handle = self
                .sortition_db
                .tx_handle_begin(&canonical_sortition_tip)?;
            processed_blocks = self.chain_state_db.process_blocks(sortdb_handle, 1)?;
        }

        Ok(None)
    }

    fn process_new_pox_anchor(&mut self, block_id: BlockHeaderHash) -> Result<(), Error> {
        // get the last sortition in the prepare phase that chose this anchor block
        //   that sortition is now the current canonical sortition,
        //   and now that we have process the anchor block for the corresponding reward phase,
        //   update the canonical pox bitvector.
        let sortition_id = self.canonical_sortition_tip.as_ref().expect(
            "FAIL: processing a new anchor block, but don't have a canonical sortition tip",
        );

        let mut prep_end = self
            .sortition_db
            .get_prepare_end_for(sortition_id, &block_id)?
            .expect(&format!(
                "FAIL: expected to get a sortition for a chosen anchor block {}, but not found.",
                &block_id
            ));

        // was this block a pox anchor for an even earlier reward cycle?
        while let Some(older_prep_end) = self
            .sortition_db
            .get_prepare_end_for(&prep_end.sortition_id, &block_id)?
        {
            prep_end = older_prep_end;
        }

        info!(
            "Reprocessing with anchor block information, starting at block height: {}",
            prep_end.block_height
        );
        let mut pox_id = self.sortition_db.get_pox_id(sortition_id)?;
        pox_id.extend_with_present_block();

        // invalidate all the sortitions > canonical_sortition_tip, in the same burnchain fork
        self.sortition_db
            .invalidate_descendants_of(&prep_end.burn_header_hash)?;

        // roll back to the state as of prep_end
        self.canonical_chain_tip = Some(StacksBlockId::new(
            &prep_end.consensus_hash,
            &prep_end.canonical_stacks_tip_hash,
        ));
        self.canonical_sortition_tip = Some(prep_end.sortition_id);
        self.canonical_pox_id = Some(pox_id);

        // Start processing from the beginning of the new PoX reward set
        self.handle_new_burnchain_block()
    }
}

/// Determine whether or not the current chainstate databases are up-to-date with the current
/// epoch.
pub fn check_chainstate_db_versions(
    epochs: &[StacksEpoch],
    sortdb_path: &str,
    chainstate_path: &str,
) -> Result<bool, DBError> {
    let mut cur_epoch_opt = None;
    if fs::metadata(&sortdb_path).is_ok() {
        // check sortition DB and load up the current epoch
        let max_height = SortitionDB::get_highest_block_height_from_path(&sortdb_path)
            .expect("FATAL: could not query sortition DB for maximum block height");
        let cur_epoch_idx = StacksEpoch::find_epoch(epochs, max_height).expect(&format!(
            "FATAL: no epoch defined for burn height {}",
            max_height
        ));
        let cur_epoch = epochs[cur_epoch_idx].epoch_id;

        // save for later
        cur_epoch_opt = Some(cur_epoch.clone());
        let db_version = SortitionDB::get_db_version_from_path(&sortdb_path)?
            .expect("FATAL: could not load sortition DB version");

        if !SortitionDB::is_db_version_supported_in_epoch(cur_epoch, &db_version) {
            error!(
                "Sortition DB at {} does not support epoch {}",
                &sortdb_path, cur_epoch
            );
            return Ok(false);
        }
    } else {
        warn!("Sortition DB {} does not exist; assuming it will be instantiated with the correct version", sortdb_path);
    }

    if fs::metadata(&chainstate_path).is_ok() {
        let cur_epoch = cur_epoch_opt.expect(
            "FATAL: chainstate corruption: sortition DB does not exist, but chainstate does.",
        );
        let db_config = StacksChainState::get_db_config_from_path(&chainstate_path)?;
        if !db_config.supports_epoch(cur_epoch) {
            error!(
                "Chainstate DB at {} does not support epoch {}",
                &chainstate_path, cur_epoch
            );
            return Ok(false);
        }
    } else {
        warn!("Chainstate DB {} does not exist; assuming it will be instantiated with the correct version", chainstate_path);
    }

    Ok(true)
}
