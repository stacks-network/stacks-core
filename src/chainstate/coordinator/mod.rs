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

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use crate::burnchains::{
    db::{BurnchainBlockData, BurnchainDB},
    Address, Burnchain, BurnchainBlockHeader, Error as BurnchainError, Txid,
};
use crate::chainstate::burn::{
    db::sortdb::SortitionDB, operations::leader_block_commit::RewardSetInfo,
    operations::BlockstackOperationType, BlockSnapshot, ConsensusHash,
};
use crate::chainstate::coordinator::comm::{
    ArcCounterCoordinatorNotices, CoordinatorEvents, CoordinatorNotices, CoordinatorReceivers,
};
use crate::chainstate::stacks::index::MarfTrieId;
use crate::chainstate::stacks::{
    db::{
        accounts::MinerReward, ChainStateBootData, ClarityTx, MinerRewardInfo, StacksChainState,
        StacksHeaderInfo,
    },
    events::{StacksTransactionEvent, StacksTransactionReceipt, TransactionOrigin},
    miner::{signal_mining_blocked, signal_mining_ready, MinerStatus},
    Error as ChainstateError, StacksBlock, TransactionPayload,
};
use crate::core::StacksEpoch;
use crate::monitoring::{
    increment_contract_calls_processed, increment_stx_blocks_processed_counter,
};
use crate::net::atlas::{AtlasConfig, AttachmentInstance};
use crate::util_lib::db::Error as DBError;
use clarity::vm::{
    costs::ExecutionCost,
    types::{PrincipalData, QualifiedContractIdentifier},
    Value,
};

use crate::cost_estimates::{CostEstimator, FeeEstimator, PessimisticEstimator};
use crate::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, PoxId, SortitionId, StacksAddress, StacksBlockId,
};
use clarity::vm::database::BurnStateDB;

use crate::chainstate::stacks::index::marf::MARFOpenOpts;

pub use self::comm::CoordinatorCommunication;

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
        block: &StacksBlock,
        metadata: &StacksHeaderInfo,
        receipts: &Vec<StacksTransactionReceipt>,
        parent: &StacksBlockId,
        winner_txid: Txid,
        matured_rewards: &Vec<MinerReward>,
        matured_rewards_info: Option<&MinerRewardInfo>,
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
        miner_status: Arc<Mutex<MinerStatus>>,
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
        };

        loop {
            // timeout so that we handle Ctrl-C a little gracefully
            match comms.wait_on() {
                CoordinatorEvents::NEW_STACKS_BLOCK => {
                    signal_mining_blocked(miner_status.clone());
                    debug!("Received new stacks block notice");
                    if let Err(e) = inst.handle_new_stacks_block() {
                        warn!("Error processing new stacks block: {:?}", e);
                    }
                    signal_mining_ready(miner_status.clone());
                }
                CoordinatorEvents::NEW_BURN_BLOCK => {
                    signal_mining_blocked(miner_status.clone());
                    debug!("Received new burn block notice");
                    if let Err(e) = inst.handle_new_burnchain_block() {
                        warn!("Error processing new burn block: {:?}", e);
                    }
                    signal_mining_ready(miner_status.clone());
                }
                CoordinatorEvents::STOP => {
                    signal_mining_blocked(miner_status.clone());
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
            None,
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
                let block_id = StacksBlockId::new(&consensus_hash, &stacks_block_hash);
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
            //  about to process is the first block in reward cycle.
            let reward_cycle_info = self.get_reward_cycle_info(&header)?;
            // bind a reference here to avoid tripping up the borrow-checker
            let dispatcher_ref = &self.dispatcher;
            let (next_snapshot, _) = self
                .sortition_db
                .evaluate_sortition(
                    &header,
                    ops,
                    &self.burnchain,
                    &last_processed_ancestor,
                    reward_cycle_info,
                    |reward_set_info| {
                        if let Some(dispatcher) = dispatcher_ref {
                            dispatcher_announce_burn_ops(
                                *dispatcher,
                                &header,
                                paid_rewards,
                                reward_set_info,
                            );
                        }
                    },
                )
                .map_err(|e| {
                    error!("ChainsCoordinator: unable to evaluate sortition {:?}", e);
                    Error::FailedToProcessSortition(e)
                })?;

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

    ///
    /// Process any ready staging blocks until there are either:
    ///   * there are no more to process
    ///   * a PoX anchor block is processed which invalidates the current PoX fork
    ///
    /// Returns Some(StacksBlockId) if such an anchor block is discovered,
    ///   otherwise returns None
    ///
    fn process_ready_blocks(&mut self) -> Result<Option<BlockHeaderHash>, Error> {
        let canonical_sortition_tip = self.canonical_sortition_tip.as_ref().expect(
            "FAIL: processing a new Stacks block, but don't have a canonical sortition tip",
        );

        let sortdb_handle = self.sortition_db.tx_handle_begin(canonical_sortition_tip)?;
        let mut processed_blocks =
            self.chain_state_db
                .process_blocks(sortdb_handle, 1, self.dispatcher)?;

        while let Some(block_result) = processed_blocks.pop() {
            if let (Some(block_receipt), _) = block_result {
                // only bump the coordinator's state if the processed block
                //   is in our sortition fork
                //  TODO: we should update the staging block logic to prevent
                //    blocks like these from getting processed at all.
                let in_sortition_set = self.sortition_db.is_stacks_block_in_sortition_set(
                    canonical_sortition_tip,
                    &block_receipt.header.anchored_header.block_hash(),
                )?;
                if in_sortition_set {
                    let new_canonical_block_snapshot = SortitionDB::get_block_snapshot(
                        self.sortition_db.conn(),
                        canonical_sortition_tip,
                    )?
                    .expect(&format!(
                        "FAIL: could not find data for the canonical sortition {}",
                        canonical_sortition_tip
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
                                                block_receipt.header.stacks_block_height,
                                                receipt.transaction.txid(),
                                                Some(
                                                    new_canonical_block_snapshot
                                                        .canonical_stacks_tip_height,
                                                ),
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
                                  "stacks_height" => %block_receipt.header.stacks_block_height,
                                  "error" => %e);
                        }
                    }

                    // if, just after processing the block, we _know_ that this block is a pox anchor, that means
                    //   that sortitions have already begun processing that didn't know about this pox anchor.
                    //   we need to trigger an unwind
                    if let Some(pox_anchor) = self
                        .sortition_db
                        .is_stacks_block_pox_anchor(&block_hash, canonical_sortition_tip)?
                    {
                        info!("Discovered an old anchor block: {}", &pox_anchor);
                        return Ok(Some(pox_anchor));
                    }
                }
            }
            // TODO: do something with a poison result

            let sortdb_handle = self.sortition_db.tx_handle_begin(canonical_sortition_tip)?;
            // Right before a block is set to processed, the event dispatcher will emit a new block event
            processed_blocks =
                self.chain_state_db
                    .process_blocks(sortdb_handle, 1, self.dispatcher)?;
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

/// Migrate all databases to their latest schemas.
/// Verifies that this is possible as well
pub fn migrate_chainstate_dbs(
    epochs: &[StacksEpoch],
    sortdb_path: &str,
    chainstate_path: &str,
    chainstate_marf_opts: Option<MARFOpenOpts>,
) -> Result<(), Error> {
    if !check_chainstate_db_versions(epochs, sortdb_path, chainstate_path)? {
        warn!("Unable to migrate chainstate DBs to the latest schemas in the current epoch");
        return Err(DBError::TooOldForEpoch.into());
    }

    if fs::metadata(&sortdb_path).is_ok() {
        info!("Migrating sortition DB to the latest schema version");
        SortitionDB::migrate_if_exists(&sortdb_path, epochs)?;
    }
    if fs::metadata(&chainstate_path).is_ok() {
        info!("Migrating chainstate DB to the latest schema version");
        let db_config = StacksChainState::get_db_config_from_path(&chainstate_path)?;

        // this does the migration internally
        let _ = StacksChainState::open(
            db_config.mainnet,
            db_config.chain_id,
            chainstate_path,
            chainstate_marf_opts,
        )?;
    }
    Ok(())
}
