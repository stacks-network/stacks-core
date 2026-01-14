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
use std::fs;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use clarity::vm::costs::ExecutionCost;
use stacks_common::bitvec::BitVec;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, SortitionId, StacksBlockId,
};
use stacks_common::util::get_epoch_time_secs;

pub use self::comm::CoordinatorCommunication;
use super::stacks::boot::{RewardSet, RewardSetData};
use super::stacks::db::blocks::DummyEventDispatcher;
use crate::burnchains::db::{BurnchainBlockData, BurnchainDB, BurnchainHeaderReader};
use crate::burnchains::{
    Burnchain, BurnchainBlockHeader, Error as BurnchainError, PoxConstants, Txid,
};
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleTx};
use crate::chainstate::burn::operations::leader_block_commit::RewardSetInfo;
use crate::chainstate::burn::operations::BlockstackOperationType;
use crate::chainstate::burn::{BlockSnapshot, ConsensusHash};
use crate::chainstate::coordinator::comm::{
    ArcCounterCoordinatorNotices, CoordinatorEvents, CoordinatorNotices, CoordinatorReceivers,
};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::{POX_3_NAME, POX_4_NAME};
use crate::chainstate::stacks::db::accounts::MinerReward;
#[cfg(test)]
use crate::chainstate::stacks::db::ChainStateBootData;
use crate::chainstate::stacks::db::{
    MinerRewardInfo, StacksChainState, StacksEpochReceipt, StacksHeaderInfo,
};
use crate::chainstate::stacks::events::{
    StacksBlockEventData, StacksTransactionEvent, StacksTransactionReceipt, TransactionOrigin,
};
use crate::chainstate::stacks::index::marf::MARFOpenOpts;
use crate::chainstate::stacks::index::Error as IndexError;
use crate::chainstate::stacks::miner::{signal_mining_blocked, signal_mining_ready, MinerStatus};
use crate::chainstate::stacks::{Error as ChainstateError, StacksBlockHeader, TransactionPayload};
use crate::core::{StacksEpoch, StacksEpochId};
use crate::cost_estimates::{CostEstimator, FeeEstimator};
use crate::monitoring::{
    increment_contract_calls_processed, increment_stx_blocks_processed_counter,
};
use crate::net::atlas::{AtlasConfig, AtlasDB, AttachmentInstance};
use crate::util_lib::db::{DBConn, DBTx, Error as DBError};

pub mod comm;
#[cfg(test)]
pub mod tests;

/// The 3 different states for the current
///  reward cycle's relationship to its PoX anchor
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PoxAnchorBlockStatus {
    SelectedAndKnown(BlockHeaderHash, Txid, RewardSet),
    SelectedAndUnknown(BlockHeaderHash, Txid),
    NotSelected,
}

/// The possible outcomes of processing a burnchain block.
/// Indicates whether or not we're ready to process Stacks blocks, or if not, whether or not we're
/// blocked on a Stacks 2.x anchor block or a Nakamoto anchor block
pub enum NewBurnchainBlockStatus {
    /// Ready to process Stacks blocks
    Ready,
    /// Missing 2.x PoX anchor block
    WaitForPox2x(BlockHeaderHash),
    /// Missing Nakamoto anchor block. Unlike 2.x, we won't know its hash.
    WaitForPoxNakamoto,
}

impl NewBurnchainBlockStatus {
    /// Test helper to convert this status into the optional hash of the missing PoX anchor block.
    /// Because there are unit tests that expect a Some(..) result if PoX cannot proceed, the
    /// missing Nakamoto anchor block case is converted into a placeholder Some(..) value
    #[cfg(test)]
    pub fn into_missing_block_hash(self) -> Option<BlockHeaderHash> {
        match self {
            Self::Ready => None,
            Self::WaitForPox2x(block_hash) => Some(block_hash),
            Self::WaitForPoxNakamoto => Some(BlockHeaderHash([0x00; 32])),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct RewardCycleInfo {
    pub reward_cycle: u64,
    pub anchor_status: PoxAnchorBlockStatus,
}

impl RewardCycleInfo {
    pub fn selected_anchor_block(&self) -> Option<(&BlockHeaderHash, &Txid)> {
        use self::PoxAnchorBlockStatus::*;
        match self.anchor_status {
            SelectedAndUnknown(ref block, ref txid) | SelectedAndKnown(ref block, ref txid, _) => {
                Some((block, txid))
            }
            NotSelected => None,
        }
    }
    pub fn is_reward_info_known(&self) -> bool {
        use self::PoxAnchorBlockStatus::*;
        match self.anchor_status {
            SelectedAndUnknown(..) => false,
            SelectedAndKnown(..) | NotSelected => true,
        }
    }
    pub fn known_selected_anchor_block(&self) -> Option<&RewardSet> {
        use self::PoxAnchorBlockStatus::*;
        match self.anchor_status {
            SelectedAndUnknown(..) => None,
            SelectedAndKnown(_, _, ref reward_set) => Some(reward_set),
            NotSelected => None,
        }
    }
    pub fn known_selected_anchor_block_owned(self) -> Option<RewardSet> {
        use self::PoxAnchorBlockStatus::*;
        match self.anchor_status {
            SelectedAndUnknown(..) => None,
            SelectedAndKnown(_, _, reward_set) => Some(reward_set),
            NotSelected => None,
        }
    }
}

pub trait BlockEventDispatcher {
    fn announce_block(
        &self,
        block: &StacksBlockEventData,
        metadata: &StacksHeaderInfo,
        receipts: &[StacksTransactionReceipt],
        parent: &StacksBlockId,
        winner_txid: &Txid,
        matured_rewards: &[MinerReward],
        matured_rewards_info: Option<&MinerRewardInfo>,
        parent_burn_block_hash: &BurnchainHeaderHash,
        parent_burn_block_height: u32,
        parent_burn_block_timestamp: u64,
        anchored_consumed: &ExecutionCost,
        mblock_confirmed_consumed: &ExecutionCost,
        pox_constants: &PoxConstants,
        reward_set_data: &Option<RewardSetData>,
        signer_bitvec: &Option<BitVec<4000>>,
        block_timestamp: Option<u64>,
        coinbase_height: u64,
    );

    /// called whenever a burn block is about to be
    ///  processed for sortition. note, in the event
    ///  of PoX forks, this will be called _multiple_
    ///  times for the same burnchain header hash.
    fn announce_burn_block(
        &self,
        burn_block: &BurnchainHeaderHash,
        burn_block_height: u64,
        rewards: Vec<(PoxAddress, u64)>,
        burns: u64,
        reward_recipients: Vec<PoxAddress>,
        consensus_hash: &ConsensusHash,
        parent_burn_block_hash: &BurnchainHeaderHash,
    );
}

pub struct ChainsCoordinatorConfig {
    /// true: enable transactions indexing
    /// false: no transactions indexing
    pub txindex: bool,
}

impl ChainsCoordinatorConfig {
    pub fn new() -> ChainsCoordinatorConfig {
        ChainsCoordinatorConfig { txindex: false }
    }

    pub fn test_new(txindex: bool) -> ChainsCoordinatorConfig {
        ChainsCoordinatorConfig { txindex }
    }
}

pub struct ChainsCoordinator<
    'a,
    T: BlockEventDispatcher,
    N: CoordinatorNotices,
    R: RewardSetProvider,
    CE: CostEstimator + ?Sized,
    FE: FeeEstimator + ?Sized,
    B: BurnchainHeaderReader,
> {
    pub canonical_sortition_tip: Option<SortitionId>,
    pub burnchain_blocks_db: BurnchainDB,
    pub chain_state_db: StacksChainState,
    pub sortition_db: SortitionDB,
    pub burnchain: Burnchain,
    pub atlas_db: Option<AtlasDB>,
    pub dispatcher: Option<&'a T>,
    pub cost_estimator: Option<&'a mut CE>,
    pub fee_estimator: Option<&'a mut FE>,
    pub reward_set_provider: R,
    pub notifier: N,
    pub atlas_config: AtlasConfig,
    pub config: ChainsCoordinatorConfig,
    burnchain_indexer: B,
    /// Used to tell the P2P thread that the stackerdb
    ///  needs to be refreshed.
    pub refresh_stacker_db: Arc<AtomicBool>,
    /// whether or not the canonical tip is now a Nakamoto header
    pub in_nakamoto_epoch: bool,
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
    IndexError(IndexError),
    NotPrepareEndBlock,
    NotPoXAnchorBlock,
    NotInPreparePhase,
    RewardSetAlreadyProcessed,
    PoXAnchorBlockRequired,
    PoXNotProcessedYet,
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

impl From<IndexError> for Error {
    fn from(o: IndexError) -> Error {
        Error::IndexError(o)
    }
}

pub trait RewardSetProvider {
    fn get_reward_set(
        &self,
        cycle_start_burn_height: u64,
        chainstate: &mut StacksChainState,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        block_id: &StacksBlockId,
    ) -> Result<RewardSet, Error>;

    fn get_reward_set_nakamoto(
        &self,
        chainstate: &mut StacksChainState,
        cycle: u64,
        sortdb: &SortitionDB,
        block_id: &StacksBlockId,
    ) -> Result<RewardSet, Error>;
}

pub struct OnChainRewardSetProvider<'a, T: BlockEventDispatcher>(pub Option<&'a T>);

impl OnChainRewardSetProvider<'static, DummyEventDispatcher> {
    pub fn new() -> Self {
        Self(None)
    }
}

impl<T: BlockEventDispatcher> RewardSetProvider for OnChainRewardSetProvider<'_, T> {
    fn get_reward_set(
        &self,
        cycle_start_burn_height: u64,
        chainstate: &mut StacksChainState,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        block_id: &StacksBlockId,
    ) -> Result<RewardSet, Error> {
        let cur_epoch = SortitionDB::get_stacks_epoch(sortdb.conn(), cycle_start_burn_height)?
            .unwrap_or_else(|| panic!("FATAL: no epoch for burn height {cycle_start_burn_height}"));
        let cycle = burnchain
            .block_height_to_reward_cycle(cycle_start_burn_height)
            .expect("FATAL: no reward cycle for burn height");
        // `self.get_reward_set_nakamoto` reads the reward set from data written during
        //   updates to .signers
        // `self.get_reward_set_epoch2` reads the reward set from the `.pox-*` contract
        //
        //  Data **cannot** be read from `.signers` in epoch 2.5 because the write occurs
        //   in the first block of the prepare phase, but the PoX anchor block is *before*
        //   the prepare phase. Therefore, we fetch the reward set in the 2.x style, and then
        //   apply the necessary nakamoto assertions if the reward set is going to be
        //   active in Nakamoto (i.e., check for signer set existence).

        let is_nakamoto_reward_set = match SortitionDB::get_stacks_epoch_by_epoch_id(
            sortdb.conn(),
            &StacksEpochId::Epoch30,
        )? {
            Some(epoch_30) => {
                let first_nakamoto_cycle = burnchain
                    .block_height_to_reward_cycle(epoch_30.start_height)
                    .expect("FATAL: no reward cycle for burn height");
                first_nakamoto_cycle <= cycle
            }
            // if epoch-3.0 isn't defined, then never use a nakamoto reward set.
            None => false,
        };

        let reward_set = self.get_reward_set_epoch2(
            cycle_start_burn_height,
            chainstate,
            burnchain,
            sortdb,
            block_id,
            cur_epoch,
        )?;

        if is_nakamoto_reward_set
            && (reward_set.signers.is_none() || reward_set.signers == Some(vec![]))
        {
            error!("FATAL: Signer sets are empty in a reward set that will be used in nakamoto"; "reward_set" => ?reward_set);
            return Err(Error::PoXAnchorBlockRequired);
        }

        Ok(reward_set)
    }

    fn get_reward_set_nakamoto(
        &self,
        chainstate: &mut StacksChainState,
        reward_cycle: u64,
        sortdb: &SortitionDB,
        block_id: &StacksBlockId,
    ) -> Result<RewardSet, Error> {
        self.read_reward_set_nakamoto(chainstate, reward_cycle, sortdb, block_id, false)
    }
}

impl<T: BlockEventDispatcher> OnChainRewardSetProvider<'_, T> {
    fn get_reward_set_epoch2(
        &self,
        // Todo: `current_burn_height` is a misleading name: should be the `cycle_start_burn_height`
        current_burn_height: u64,
        chainstate: &mut StacksChainState,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        block_id: &StacksBlockId,
        cur_epoch: StacksEpoch,
    ) -> Result<RewardSet, Error> {
        match cur_epoch.epoch_id {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21 => {
                // Epochs 1.0 - 2.1 compute reward sets
            }
            StacksEpochId::Epoch22 | StacksEpochId::Epoch23 => {
                info!("PoX reward cycle defaulting to burn in Epochs 2.2 and 2.3");
                return Ok(RewardSet::empty());
            }
            StacksEpochId::Epoch24 => {
                // Epoch 2.4 computes reward sets, but *only* if PoX-3 is active
                if burnchain
                    .pox_constants
                    .active_pox_contract(current_burn_height)
                    != POX_3_NAME
                {
                    // Note: this should not happen in mainnet or testnet, because the no reward cycle start height
                    //        exists between Epoch 2.4's instantiation height and the pox-3 activation height.
                    //  However, this *will* happen in testing if Epoch 2.4's instantiation height is set == a reward cycle
                    //   start height
                    info!("PoX reward cycle defaulting to burn in Epoch 2.4 because cycle start is before PoX-3 activation");
                    return Ok(RewardSet::empty());
                }
            }
            StacksEpochId::Epoch25
            | StacksEpochId::Epoch30
            | StacksEpochId::Epoch31
            | StacksEpochId::Epoch32
            | StacksEpochId::Epoch33 => {
                // Epoch 2.5, 3.0, 3.1 and 3.2 compute reward sets, but *only* if PoX-4 is active
                if burnchain
                    .pox_constants
                    .active_pox_contract(current_burn_height)
                    != POX_4_NAME
                {
                    // Note: this should not happen in mainnet or testnet, because the no reward cycle start height
                    //        exists between Epoch 2.5's instantiation height and the pox-4 activation height.
                    //  However, this *will* happen in testing if Epoch 2.5's instantiation height is set == a reward cycle
                    //   start height
                    info!("PoX reward cycle defaulting to burn in Epoch 2.5 because cycle start is before PoX-4 activation");
                    return Ok(RewardSet::empty());
                }
            }
        };

        let registered_addrs =
            chainstate.get_reward_addresses(burnchain, sortdb, current_burn_height, block_id)?;

        let liquid_ustx = chainstate.get_liquid_ustx(block_id);

        let (threshold, participation) = StacksChainState::get_reward_threshold_and_participation(
            &burnchain.pox_constants,
            &registered_addrs[..],
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
            return Ok(RewardSet::empty());
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
            cur_epoch.epoch_id,
        ))
    }
}

impl<
        'a,
        T: BlockEventDispatcher,
        CE: CostEstimator + ?Sized,
        FE: FeeEstimator + ?Sized,
        B: BurnchainHeaderReader,
    >
    ChainsCoordinator<
        'a,
        T,
        ArcCounterCoordinatorNotices,
        OnChainRewardSetProvider<'a, T>,
        CE,
        FE,
        B,
    >
{
    pub fn run(
        config: ChainsCoordinatorConfig,
        chain_state_db: StacksChainState,
        burnchain: Burnchain,
        dispatcher: &'a T,
        comms: CoordinatorReceivers,
        atlas_config: AtlasConfig,
        cost_estimator: Option<&'a mut CE>,
        fee_estimator: Option<&'a mut FE>,
        miner_status: Arc<Mutex<MinerStatus>>,
        burnchain_indexer: B,
        atlas_db: AtlasDB,
    ) where
        T: BlockEventDispatcher,
    {
        let stacks_blocks_processed = comms.stacks_blocks_processed.clone();
        let sortitions_processed = comms.sortitions_processed.clone();

        let sortition_db = burnchain.open_sortition_db(true).unwrap();
        let burnchain_blocks_db = burnchain.open_burnchain_db(false).unwrap();

        let canonical_sortition_tip =
            SortitionDB::get_canonical_sortition_tip(sortition_db.conn()).unwrap();

        let arc_notices = ArcCounterCoordinatorNotices {
            stacks_blocks_processed,
            sortitions_processed,
        };

        let mut inst = ChainsCoordinator {
            canonical_sortition_tip: Some(canonical_sortition_tip),
            burnchain_blocks_db,
            chain_state_db,
            sortition_db,
            burnchain,
            dispatcher: Some(dispatcher),
            notifier: arc_notices,
            reward_set_provider: OnChainRewardSetProvider(Some(dispatcher)),
            cost_estimator,
            fee_estimator,
            atlas_config,
            atlas_db: Some(atlas_db),
            config,
            burnchain_indexer,
            refresh_stacker_db: comms.refresh_stacker_db.clone(),
            in_nakamoto_epoch: false,
        };

        loop {
            let bits = comms.wait_on();
            if inst.in_subsequent_nakamoto_reward_cycle() {
                debug!("Coordinator: in subsequent Nakamoto reward cycle");
                if !inst.handle_comms_nakamoto(bits, miner_status.clone()) {
                    return;
                }
            } else if inst.in_first_nakamoto_reward_cycle() {
                debug!("Coordinator: in first Nakamoto reward cycle");
                if !inst.handle_comms_nakamoto(bits, miner_status.clone()) {
                    return;
                }
                if !inst.handle_comms_epoch2(bits, miner_status.clone()) {
                    return;
                }
            } else {
                debug!("Coordinator: in epoch2 reward cycle");
                if !inst.handle_comms_epoch2(bits, miner_status.clone()) {
                    return;
                }
            }
        }
    }

    /// This is the Stacks 2.x coordinator loop body, which handles communications
    /// from the given `comms`.  It returns `true` if the coordinator is still running, and `false`
    /// if not.
    pub fn handle_comms_epoch2(&mut self, bits: u8, miner_status: Arc<Mutex<MinerStatus>>) -> bool {
        // timeout so that we handle Ctrl-C a little gracefully
        if (bits & (CoordinatorEvents::NEW_STACKS_BLOCK as u8)) != 0 {
            signal_mining_blocked(miner_status.clone());
            debug!("Received new stacks block notice");
            match self.handle_new_stacks_block() {
                Ok(missing_block_opt) => {
                    if missing_block_opt.is_some() {
                        debug!(
                            "Missing affirmed anchor block: {:?}",
                            &missing_block_opt.as_ref().expect("unreachable")
                        );
                    }
                }
                Err(e) => {
                    warn!("Error processing new stacks block: {:?}", e);
                }
            }

            signal_mining_ready(miner_status.clone());
        }
        if (bits & (CoordinatorEvents::NEW_BURN_BLOCK as u8)) != 0 {
            signal_mining_blocked(miner_status.clone());
            debug!("Received new burn block notice");
            match self.handle_new_burnchain_block() {
                Ok(burn_block_status) => match burn_block_status {
                    NewBurnchainBlockStatus::Ready => {}
                    NewBurnchainBlockStatus::WaitForPox2x(block_hash) => {
                        debug!("Missing canonical Stacks 2.x anchor block {}", &block_hash,);
                    }
                    NewBurnchainBlockStatus::WaitForPoxNakamoto => {
                        debug!("Missing canonical Nakamoto anchor block");
                    }
                },
                Err(e) => {
                    warn!("Error processing new burn block: {:?}", e);
                }
            }
            signal_mining_ready(miner_status.clone());
        }
        if (bits & (CoordinatorEvents::STOP as u8)) != 0 {
            signal_mining_blocked(miner_status);
            debug!("Received stop notice");
            return false;
        }

        return true;
    }
}

impl<T: BlockEventDispatcher, U: RewardSetProvider, B: BurnchainHeaderReader>
    ChainsCoordinator<'_, T, (), U, (), (), B>
{
    /// Create a coordinator for testing, with some parameters defaulted to None
    #[cfg(test)]
    pub fn test_new<'a>(
        burnchain: &Burnchain,
        chain_id: u32,
        path: &str,
        reward_set_provider: U,
        indexer: B,
        txindex: bool,
    ) -> ChainsCoordinator<'a, T, (), U, (), (), B> {
        ChainsCoordinator::test_new_full(
            burnchain,
            chain_id,
            path,
            reward_set_provider,
            None,
            indexer,
            None,
            txindex,
        )
    }

    /// Create a coordinator for testing allowing for all configurable params
    #[cfg(test)]
    pub fn test_new_full<'a>(
        burnchain: &Burnchain,
        chain_id: u32,
        path: &str,
        reward_set_provider: U,
        dispatcher: Option<&'a T>,
        burnchain_indexer: B,
        atlas_config: Option<AtlasConfig>,
        txindex: bool,
    ) -> ChainsCoordinator<'a, T, (), U, (), (), B> {
        let burnchain = burnchain.clone();

        let mut boot_data = ChainStateBootData::new(&burnchain, vec![], None);

        let sortition_db = SortitionDB::open(
            &burnchain.get_db_path(),
            true,
            burnchain.pox_constants.clone(),
            None,
        )
        .unwrap();
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

        let atlas_config = atlas_config.unwrap_or(AtlasConfig::new(false));
        let atlas_db = AtlasDB::connect(
            atlas_config.clone(),
            &format!("{}/atlas.sqlite", path),
            true,
        )
        .unwrap();

        ChainsCoordinator {
            canonical_sortition_tip: Some(canonical_sortition_tip),
            burnchain_blocks_db,
            chain_state_db,
            sortition_db,
            burnchain,
            dispatcher,
            cost_estimator: None,
            fee_estimator: None,
            reward_set_provider,
            notifier: (),
            atlas_config,
            atlas_db: Some(atlas_db),
            config: ChainsCoordinatorConfig::test_new(txindex),
            burnchain_indexer,
            refresh_stacker_db: Arc::new(AtomicBool::new(false)),
            in_nakamoto_epoch: false,
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
        .map_err(Error::from)
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
    sort_db: &mut SortitionDB,
    provider: &U,
) -> Result<Option<RewardCycleInfo>, Error> {
    let epoch_at_height = SortitionDB::get_stacks_epoch(sort_db.conn(), burn_height)?
        .unwrap_or_else(|| panic!("FATAL: no epoch defined for burn height {}", burn_height));

    if !burnchain.is_reward_cycle_start(burn_height) {
        return Ok(None);
    }

    let reward_cycle = burnchain
        .block_height_to_reward_cycle(burn_height)
        .expect("FATAL: no reward cycle for burn height");

    if burnchain
        .pox_constants
        .is_after_pox_sunset_end(burn_height, epoch_at_height.epoch_id)
    {
        return Ok(Some(RewardCycleInfo {
            reward_cycle,
            anchor_status: PoxAnchorBlockStatus::NotSelected,
        }));
    }

    debug!("Beginning reward cycle";
           "burn_height" => burn_height,
           "reward_cycle" => reward_cycle,
           "reward_cycle_length" => burnchain.pox_constants.reward_cycle_length,
           "prepare_phase_length" => burnchain.pox_constants.prepare_length);

    let reward_cycle_info = {
        let ic = sort_db.index_handle(sortition_tip);
        ic.get_chosen_pox_anchor(parent_bhh, &burnchain.pox_constants)
    }?;
    let reward_cycle_info =
        if let Some((consensus_hash, stacks_block_hash, txid)) = reward_cycle_info {
            let anchor_block_known = StacksChainState::is_stacks_block_processed(
                chain_state.db(),
                &consensus_hash,
                &stacks_block_hash,
            )?;
            let stacks_block_id = StacksBlockId::new(&consensus_hash, &stacks_block_hash);
            info!(
                "PoX Anchor block selected";
                "cycle" => reward_cycle,
                "consensus_hash" => %consensus_hash,
                "stacks_block_hash" => %stacks_block_hash,
                "stacks_block_id" => %stacks_block_id,
                "is_known" => anchor_block_known,
                "commit_txid" => %txid,
                "cycle_burn_height" => burn_height
            );
            let anchor_status = if anchor_block_known {
                let reward_set = provider.get_reward_set(
                    burn_height,
                    chain_state,
                    burnchain,
                    sort_db,
                    &stacks_block_id,
                )?;
                PoxAnchorBlockStatus::SelectedAndKnown(stacks_block_hash, txid, reward_set)
            } else {
                PoxAnchorBlockStatus::SelectedAndUnknown(stacks_block_hash, txid)
            };
            RewardCycleInfo {
                reward_cycle,
                anchor_status,
            }
        } else {
            info!(
                "PoX anchor block NOT chosen for reward cycle {} at burn height {}",
                reward_cycle, burn_height
            );
            RewardCycleInfo {
                reward_cycle,
                anchor_status: PoxAnchorBlockStatus::NotSelected,
            }
        };

    // cache the reward cycle info as of the first sortition in the prepare phase, so that
    // the first Nakamoto epoch can go find it later.  Subsequent Nakamoto epochs will use the
    // reward set stored to the Nakamoto chain state.
    let ic = sort_db.index_handle(sortition_tip);
    let prev_reward_cycle = burnchain
        .block_height_to_reward_cycle(burn_height)
        .expect("FATAL: no reward cycle for burn height");

    if prev_reward_cycle > 1 {
        let prepare_phase_start = burnchain
            .pox_constants
            .prepare_phase_start(burnchain.first_block_height, prev_reward_cycle - 1);
        let first_prepare_sn =
            SortitionDB::get_ancestor_snapshot(&ic, prepare_phase_start, sortition_tip)?
                .expect("FATAL: no start-of-prepare-phase sortition");

        let mut tx = sort_db.tx_begin()?;
        let preprocessed_reward_set =
            SortitionDB::get_preprocessed_reward_set(&tx, &first_prepare_sn.sortition_id)?;

        // It's possible that we haven't processed the PoX anchor block at the time we have
        // processed the burnchain block which commits to it.  In this case, the PoX anchor block
        // status would be SelectedAndUnknown.  However, it's overwhelmingly likely (and in
        // Nakamoto, _required_) that the PoX anchor block will be processed shortly thereafter.
        // When this happens, we need to _update_ the sortition DB with the newly-processed reward
        // set.  This code performs this check to determine whether or not we need to store this
        // calculated reward set.
        let need_to_store = if let Some(reward_cycle_info) = preprocessed_reward_set {
            // overwrite if we have an unknown anchor block
            !reward_cycle_info.is_reward_info_known()
        } else {
            true
        };
        if need_to_store {
            debug!(
                "Store preprocessed reward set for cycle";
                "reward_cycle" => prev_reward_cycle,
                "prepare-start sortition" => %first_prepare_sn.sortition_id,
                "reward_cycle_info" => format!("{:?}", &reward_cycle_info)
            );
            SortitionDB::store_preprocessed_reward_set(
                &mut tx,
                &first_prepare_sn.sortition_id,
                &reward_cycle_info,
            )?;
        }
        tx.commit()?;
    }

    Ok(Some(reward_cycle_info))
}

/// PoX payout event to be sent to connected event observers
pub struct PaidRewards {
    pub pox: Vec<(PoxAddress, u64)>,
    pub burns: u64,
}

/// Determine the rewards paid for a given set of burnchain operations.  All of these operations
/// ought to be from the same burnchain block.
pub fn calculate_paid_rewards(ops: &[BlockstackOperationType]) -> PaidRewards {
    let mut reward_recipients: HashMap<_, u64> = HashMap::new();
    let mut burn_amt = 0;
    for op in ops.iter() {
        if let BlockstackOperationType::LeaderBlockCommit(commit) = op {
            if commit.commit_outs.is_empty() {
                continue;
            }
            let amt_per_address = commit.burn_fee / (commit.commit_outs.len() as u64);
            for addr in commit.commit_outs.iter() {
                if addr.is_burn() {
                    burn_amt += amt_per_address;
                } else if let Some(prior_amt) = reward_recipients.get_mut(addr) {
                    *prior_amt += amt_per_address;
                } else {
                    reward_recipients.insert(addr.clone(), amt_per_address);
                }
            }
        }
    }
    PaidRewards {
        pox: reward_recipients.into_iter().collect(),
        burns: burn_amt,
    }
}

pub fn dispatcher_announce_burn_ops<T: BlockEventDispatcher>(
    dispatcher: &T,
    burn_header: &BurnchainBlockHeader,
    paid_rewards: PaidRewards,
    reward_recipient_info: Option<RewardSetInfo>,
    consensus_hash: &ConsensusHash,
) {
    let recipients = if let Some(recip_info) = reward_recipient_info {
        recip_info
            .recipients
            .into_iter()
            .map(|(addr, ..)| addr)
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
        consensus_hash,
        &burn_header.parent_block_hash,
    );
}

/// Forget that all Stacks blocks that were mined on descendants of `burn_header` are orphaned.
/// They may be valid again, after a PoX reorg.
fn forget_orphan_stacks_blocks(
    sort_conn: &DBConn,
    chainstate_db_tx: &mut DBTx,
    burn_header: &BurnchainHeaderHash,
    invalidation_height: u64,
) -> Result<(), Error> {
    if let Ok(sns) = SortitionDB::get_all_snapshots_for_burn_block(sort_conn, burn_header) {
        for sn in sns.into_iter() {
            // only retry blocks that are truly in descendant
            // sortitions.
            if sn.sortition && sn.block_height > invalidation_height {
                StacksChainState::forget_orphaned_epoch_data(
                    chainstate_db_tx,
                    &sn.consensus_hash,
                    &sn.winning_stacks_block_hash,
                )?;
            }
        }
    }
    Ok(())
}

impl<
        T: BlockEventDispatcher,
        N: CoordinatorNotices,
        U: RewardSetProvider,
        CE: CostEstimator + ?Sized,
        FE: FeeEstimator + ?Sized,
        B: BurnchainHeaderReader,
    > ChainsCoordinator<'_, T, N, U, CE, FE, B>
{
    /// Process new Stacks blocks.  If we get stuck for want of a missing PoX anchor block, return
    /// its hash.
    pub fn handle_new_stacks_block(&mut self) -> Result<Option<BlockHeaderHash>, Error> {
        debug!("Handle new Stacks block");
        if let Some(pox_anchor) = self.process_ready_blocks()? {
            self.process_new_pox_anchor(pox_anchor, &mut HashSet::new())
        } else {
            Ok(None)
        }
    }

    /// Try to revalidate a sortition if it exists already.  This can happen if the node flip/flops
    /// between two PoX forks.
    ///
    /// If it succeeds, then return the revalidated snapshot.  Otherwise, return None
    fn try_revalidate_sortition(
        &mut self,
        canonical_snapshot: &BlockSnapshot,
        header: &BurnchainBlockHeader,
        last_processed_ancestor: &SortitionId,
        next_pox_info: Option<&RewardCycleInfo>,
    ) -> Result<Option<BlockSnapshot>, Error> {
        let parent_sort_id = self
            .sortition_db
            .get_sortition_id(&header.parent_block_hash, last_processed_ancestor)?
            .ok_or_else(|| {
                warn!("Unknown block {:?}", header.parent_block_hash);
                BurnchainError::MissingParentBlock
            })?;

        let parent_pox = {
            let mut sortition_db_handle =
                SortitionHandleTx::begin(&mut self.sortition_db, &parent_sort_id)?;
            sortition_db_handle.get_pox_id()?
        };

        let new_sortition_id =
            SortitionDB::make_next_sortition_id(parent_pox, &header.block_hash, next_pox_info);
        let sortition_opt =
            SortitionDB::get_block_snapshot(self.sortition_db.conn(), &new_sortition_id)?;

        if let Some(sortition) = sortition_opt {
            // existing sortition -- go revalidate it
            info!(
                "Revalidate already-processed snapshot {new_sortition_id} height {} to have canonical tip {}/{} height {}",
                sortition.block_height,
                &canonical_snapshot.canonical_stacks_tip_consensus_hash,
                &canonical_snapshot.canonical_stacks_tip_hash,
                canonical_snapshot.canonical_stacks_tip_height,
            );

            let tx = self.sortition_db.tx_begin()?;
            SortitionDB::revalidate_snapshot_with_block(
                &tx,
                &new_sortition_id,
                &canonical_snapshot.canonical_stacks_tip_consensus_hash,
                &canonical_snapshot.canonical_stacks_tip_hash,
                canonical_snapshot.canonical_stacks_tip_height,
                Some(false), // we'll mark it processed after this call, if it's still valid.
            )?;
            tx.commit()?;

            Ok(Some(sortition))
        } else {
            Ok(None)
        }
    }

    /// Check to see if the discovery of a PoX anchor block means it's time to process a new reward
    /// cycle.
    ///
    /// This mutates `rc_info` to be the affirmed anchor block status.
    ///
    /// Returns Some(...) if we have a _missing_ PoX anchor block that _must be_ downloaded
    /// before burnchain processing can continue.
    /// Returns None if not
    fn check_missing_anchor_block(
        &self,
        _header: &BurnchainBlockHeader,
        rc_info: &mut RewardCycleInfo,
    ) -> Option<BlockHeaderHash> {
        // anchor blocks are always assumed to be present in the chain history,
        // so report its absence if we don't have it.
        if let PoxAnchorBlockStatus::SelectedAndUnknown(missing_anchor_block, _) =
            &rc_info.anchor_status
        {
            info!("Currently missing PoX anchor block {missing_anchor_block}, which is assumed to be present");
            return Some(missing_anchor_block.clone());
        }

        test_debug!(
            "Reward cycle info at height {}: {rc_info:?}",
            &_header.block_height
        );
        None
    }

    /// Outermost call to process a burnchain block.
    /// Will call the Stacks 2.x or Nakamoto handler, depending on whether or not
    /// Not called internally.
    pub fn handle_new_burnchain_block(&mut self) -> Result<NewBurnchainBlockStatus, Error> {
        let canonical_burnchain_tip = self.burnchain_blocks_db.get_canonical_chain_tip()?;
        let epochs = SortitionDB::get_stacks_epochs(self.sortition_db.conn())?;
        let target_epoch = epochs
            .epoch_at_height(canonical_burnchain_tip.block_height)
            .expect("FATAL: epoch not defined for burnchain height");
        if target_epoch.epoch_id < StacksEpochId::Epoch30 {
            // burnchain has not yet advanced to epoch 3.0
            return self
                .handle_new_epoch2_burnchain_block(&mut HashSet::new())
                .map(|block_hash_opt| {
                    if let Some(block_hash) = block_hash_opt {
                        NewBurnchainBlockStatus::WaitForPox2x(block_hash)
                    } else {
                        NewBurnchainBlockStatus::Ready
                    }
                });
        }

        // burnchain has advanced to epoch 3.0, but has our sortition DB?
        let canonical_snapshot = match self.canonical_sortition_tip.as_ref() {
            Some(sn_tip) => SortitionDB::get_block_snapshot(self.sortition_db.conn(), sn_tip)?
                .unwrap_or_else(|| {
                    panic!("FATAL: do not have previously-calculated highest valid sortition tip {sn_tip}")
                }),
            None => SortitionDB::get_canonical_burn_chain_tip(self.sortition_db.conn())?,
        };
        let target_epoch = epochs
            .epoch_at_height(canonical_snapshot.block_height)
            .expect("FATAL: epoch not defined for BlockSnapshot height");

        if target_epoch.epoch_id < StacksEpochId::Epoch30 {
            // need to catch the sortition DB up
            self.handle_new_epoch2_burnchain_block(&mut HashSet::new())?;
        }

        // proceed to process sortitions in epoch 3.0
        self.handle_new_nakamoto_burnchain_block()
            .map(|can_proceed| {
                if can_proceed {
                    NewBurnchainBlockStatus::Ready
                } else {
                    // missing PoX anchor block, but unlike in 2.x, we don't know what it is!
                    NewBurnchainBlockStatus::WaitForPoxNakamoto
                }
            })
    }

    // TODO: add tests from mutation testing results #4852
    #[cfg_attr(test, mutants::skip)]
    /// Handle a new burnchain block, optionally rolling back the canonical PoX sortition history
    /// and setting it up to be replayed in the event the network affirms a different history.  If
    /// this happens, *and* if re-processing the new affirmed history is *blocked on* the
    /// unavailability of a PoX anchor block that *must now* exist, then return the hash of this
    /// anchor block.
    pub fn handle_new_epoch2_burnchain_block(
        &mut self,
        already_processed_burn_blocks: &mut HashSet<BurnchainHeaderHash>,
    ) -> Result<Option<BlockHeaderHash>, Error> {
        debug!("Handle new burnchain block");

        // Retrieve canonical burnchain chain tip from the BurnchainBlocksDB
        let canonical_snapshot = match self.canonical_sortition_tip.as_ref() {
            Some(sn_tip) => SortitionDB::get_block_snapshot(self.sortition_db.conn(), sn_tip)?
                .unwrap_or_else(|| {
                    panic!("FATAL: do not have previously-calculated highest valid sortition tip {sn_tip}")
                }),
            None => SortitionDB::get_canonical_burn_chain_tip(self.sortition_db.conn())?,
        };

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
                debug!("Ancestor sortition {found_sortition} of block {cursor} is processed");
                break found_sortition;
            }

            let current_block =
                BurnchainDB::get_burnchain_block(self.burnchain_blocks_db.conn(), &cursor)
                    .map_err(|e| {
                        warn!(
                            "ChainsCoordinator: could not retrieve block burnhash={}",
                            &cursor
                        );
                        Error::NonContiguousBurnchainBlock(e)
                    })?;

            debug!(
                "Unprocessed block: ({}, {})",
                &current_block.header.block_hash.to_string(),
                current_block.header.block_height
            );

            let parent = current_block.header.parent_block_hash.clone();
            sortitions_to_process.push_front(current_block);
            cursor = parent;
        };

        let burn_header_hashes: Vec<_> = sortitions_to_process
            .iter()
            .map(|block| {
                format!(
                    "({}, {})",
                    &block.header.block_hash.to_string(),
                    block.header.block_height
                )
            })
            .collect();

        debug!(
            "Unprocessed burn chain blocks [{}]",
            burn_header_hashes.join(", ")
        );

        // if this is set to true, the notify that a stacks block has been processed.
        // this wakes up anyone waiting for their block to have been processed.
        let mut revalidated_stacks_block = false;

        for unprocessed_block in sortitions_to_process.into_iter() {
            let BurnchainBlockData { header, ops } = unprocessed_block;

            // only evaluate epoch 2.x.
            // NOTE: epoch 3 starts _right after_ the first block in the first epoch3 reward cycle,
            // so we use the 2.x rules to process the PoX reward set.
            let sortition_epoch =
                SortitionDB::get_stacks_epoch(self.sortition_db.conn(), header.block_height)?
                    .expect("FATAL: no epoch defined for a valid block height");

            if sortition_epoch.epoch_id >= StacksEpochId::Epoch30 {
                // stop processing
                break;
            }

            if already_processed_burn_blocks.contains(&header.block_hash) {
                // don't re-process something we recursively processed already, by means of finding
                // a heretofore missing anchor block
                continue;
            }

            let reward_cycle = self
                .burnchain
                .block_height_to_reward_cycle(header.block_height)
                .unwrap_or(u64::MAX);

            debug!(
                "Process burn block {} reward cycle {reward_cycle} in {}",
                header.block_height, &self.burnchain.working_dir,
            );

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
            //  about to process is the first block in reward cycle, and if so,
            //  whether or not there ought to be an anchor block.
            let mut reward_cycle_info = self.get_reward_cycle_info(&header)?;

            if let Some(rc_info) = reward_cycle_info.as_mut() {
                if let Some(missing_anchor_block) =
                    self.check_missing_anchor_block(&header, rc_info)
                {
                    info!("Burnchain block processing stops due to missing affirmed anchor stacks block hash {missing_anchor_block}");
                    return Ok(Some(missing_anchor_block));
                }
            }

            // track a list of (consensus hash, parent block hash, block hash, height) pairs of revalidated sortitions whose
            // blocks will need to be re-marked as accepted.
            let mut stacks_blocks_to_reaccept = vec![];

            // track a list of (burn header, burn block height) pairs for revalidated sortitions whose
            // blocks we need to un-orphan
            let mut unorphan_blocks = vec![];

            let next_snapshot = {
                // if this sortition exists already, then revalidate it with the canonical Stacks
                // tip.  Otherwise, process it.  This can be necessary if we're trying to mine
                // while not having all canonical PoX anchor blocks.
                if let Some(sortition) = self.try_revalidate_sortition(
                    &canonical_snapshot,
                    &header,
                    &last_processed_ancestor,
                    reward_cycle_info.as_ref(),
                )? {
                    if sortition.sortition {
                        if let Some(stacks_block_header) =
                            StacksChainState::get_stacks_block_header_info_by_index_block_hash(
                                self.chain_state_db.db(),
                                &StacksBlockId::new(
                                    &sortition.consensus_hash,
                                    &sortition.winning_stacks_block_hash,
                                ),
                            )?
                        {
                            // we accepted this block
                            debug!(
                                "Will re-accept Stacks block {}/{} height {}",
                                &sortition.consensus_hash,
                                &sortition.winning_stacks_block_hash,
                                stacks_block_header.anchored_header.height(),
                            );
                            stacks_blocks_to_reaccept.push((
                                sortition.consensus_hash.clone(),
                                sortition.winning_stacks_block_hash.clone(),
                                stacks_block_header.anchored_header.height(),
                            ));
                        } else {
                            debug!(
                                "Will un-orphan Stacks block {}/{} if it is orphaned",
                                &sortition.consensus_hash, &sortition.winning_stacks_block_hash
                            );
                            unorphan_blocks.push((sortition.burn_header_hash.clone(), 0));
                        }
                    }
                    sortition
                } else {
                    // bind a reference here to avoid tripping up the borrow-checker
                    let dispatcher_ref = &self.dispatcher;
                    let (next_snapshot, _) = self
                        .sortition_db
                        .evaluate_sortition(
                            self.chain_state_db.mainnet,
                            &header,
                            ops,
                            &self.burnchain,
                            &last_processed_ancestor,
                            reward_cycle_info,
                            |reward_set_info, consensus_hash| {
                                if let Some(dispatcher) = dispatcher_ref {
                                    dispatcher_announce_burn_ops(
                                        *dispatcher,
                                        &header,
                                        paid_rewards,
                                        reward_set_info,
                                        consensus_hash,
                                    );
                                }
                            },
                        )
                        .map_err(|e| {
                            error!("ChainsCoordinator: unable to evaluate sortition: {:?}", e);
                            Error::FailedToProcessSortition(e)
                        })?;

                    next_snapshot
                }
            };

            // don't process this burnchain block again in this recursive call.
            already_processed_burn_blocks.insert(next_snapshot.burn_header_hash.clone());

            // reaccept any stacks blocks
            let mut sortition_db_handle =
                SortitionHandleTx::begin(&mut self.sortition_db, &next_snapshot.sortition_id)?;

            for (ch, bhh, height) in stacks_blocks_to_reaccept.into_iter() {
                debug!("Re-accept Stacks block {}/{} height {}", &ch, &bhh, height);
                revalidated_stacks_block = true;
                sortition_db_handle.set_stacks_block_accepted(&ch, &bhh, height)?;
            }
            sortition_db_handle.commit()?;

            if !unorphan_blocks.is_empty() {
                revalidated_stacks_block = true;
                let ic = self.sortition_db.index_conn();
                let mut chainstate_db_tx = self.chain_state_db.db_tx_begin()?;
                for (burn_header, invalidation_height) in unorphan_blocks {
                    // permit re-processing of any associated stacks blocks if they're
                    // orphaned
                    forget_orphan_stacks_blocks(
                        &ic,
                        &mut chainstate_db_tx,
                        &burn_header,
                        invalidation_height,
                    )?;
                }
                chainstate_db_tx.commit().map_err(DBError::SqliteError)?;
            }

            let sortition_id = next_snapshot.sortition_id.clone();

            self.notifier.notify_sortition_processed();
            if revalidated_stacks_block {
                debug!("Bump Stacks block(s) reprocessed");
                self.notifier.notify_stacks_block_processed();
            }

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

            // we may already have the associated Stacks block, but linked to a different sortition
            // history.  For example, if an anchor block was selected but PoX was voted disabled or
            // not voted to activate, then the same Stacks blocks could be chosen but with
            // different consensus hashes.  So, check here if we happen to already have the block
            // stored, and proceed to put it into staging again.
            if next_snapshot.sortition {
                self.try_replay_stacks_block(&canonical_snapshot, &next_snapshot)?;
            }

            if let Some(pox_anchor) = self.process_ready_blocks()? {
                if let Some(expected_anchor_block_hash) =
                    self.process_new_pox_anchor(pox_anchor, already_processed_burn_blocks)?
                {
                    info!(
                        "Burnchain block processing stops due to missing affirmed anchor stacks block hash {}",
                        &expected_anchor_block_hash
                    );
                    return Ok(Some(expected_anchor_block_hash));
                }
            }
        }

        debug!("Done handling new burnchain blocks");

        Ok(None)
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
            &mut self.sortition_db,
            &self.reward_set_provider,
        )
    }

    /// Process any Atlas attachment events and forward them to the Atlas subsystem
    pub fn process_atlas_attachment_events(
        atlas_db: Option<&mut AtlasDB>,
        atlas_config: &AtlasConfig,
        block_receipt: &StacksEpochReceipt,
        canonical_stacks_tip_height: u64,
    ) {
        let mut attachments_instances = HashSet::new();
        for receipt in block_receipt.tx_receipts.iter() {
            if let TransactionOrigin::Stacks(ref transaction) = receipt.transaction {
                if let TransactionPayload::ContractCall(ref contract_call) = transaction.payload {
                    let contract_id = contract_call.to_clarity_contract_id();
                    increment_contract_calls_processed();
                    if atlas_config.contracts.contains(&contract_id) {
                        for event in receipt.events.iter() {
                            if let StacksTransactionEvent::SmartContractEvent(ref event_data) =
                                event
                            {
                                let res = AttachmentInstance::try_new_from_value(
                                    &event_data.value,
                                    &contract_id,
                                    block_receipt.header.index_block_hash(),
                                    block_receipt.header.stacks_block_height,
                                    receipt.transaction.txid(),
                                    Some(canonical_stacks_tip_height),
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
                "Atlas: New attachment instances emitted by block";
                "attachments_count" => attachments_instances.len(),
                "index_block_hash" => %block_receipt.header.index_block_hash(),
                "stacks_height" => block_receipt.header.stacks_block_height,
                "burn_height" => block_receipt.header.burn_header_height,
                "burn_block_hash" => %block_receipt.header.burn_header_hash,
                "consensus_hash" => %block_receipt.header.consensus_hash,
            );
            if let Some(atlas_db) = atlas_db {
                for new_attachment in attachments_instances.into_iter() {
                    if let Err(e) = atlas_db.queue_attachment_instance(&new_attachment) {
                        warn!(
                            "Atlas: Error writing attachment instance to DB";
                            "err" => ?e,
                            "index_block_hash" => %new_attachment.index_block_hash,
                            "contract_id" => %new_attachment.contract_id,
                            "attachment_index" => %new_attachment.attachment_index,
                        );
                    }
                }
            } else {
                warn!("Atlas: attempted to write attachments, but stacks-node not configured with Atlas DB");
            }
        }
    }

    /// Replay any existing Stacks blocks we have that arose on a different PoX fork.
    /// This is best-effort -- if a block isn't found or can't be loaded, it's skipped.
    fn replay_stacks_blocks(
        &mut self,
        tip: &BlockSnapshot,
        blocks: Vec<BlockHeaderHash>,
    ) -> Result<(), Error> {
        for bhh in blocks.into_iter() {
            let staging_block_chs = StacksChainState::get_staging_block_consensus_hashes(
                self.chain_state_db.db(),
                &bhh,
            )?;
            let mut processed = false;

            debug!("Consider replaying {} from {:?}", &bhh, &staging_block_chs);

            for alt_ch in staging_block_chs.into_iter() {
                let alt_id = StacksBlockHeader::make_index_block_hash(&alt_ch, &bhh);
                if !StacksChainState::has_block_indexed(&self.chain_state_db.blocks_path, &alt_id)
                    .unwrap_or(false)
                {
                    continue;
                }

                // does this consensus hash exist somewhere? Doesn't have to be on the canonical
                // PoX fork.
                let ch_height_opt = self.sortition_db.get_consensus_hash_height(&alt_ch)?;
                let ch_height = if let Some(ch_height) = ch_height_opt {
                    ch_height
                } else {
                    continue;
                };

                // Find the corresponding snapshot on the canonical PoX fork.
                let ancestor_sn = if let Some(sn) = SortitionDB::get_ancestor_snapshot(
                    &self.sortition_db.index_conn(),
                    ch_height,
                    &tip.sortition_id,
                )? {
                    sn
                } else {
                    continue;
                };

                // the new consensus hash
                let ch = ancestor_sn.consensus_hash;

                if let Ok(Some(block)) =
                    StacksChainState::load_block(&self.chain_state_db.blocks_path, &alt_ch, &bhh)
                {
                    let ic = self.sortition_db.index_conn();
                    if let Some(parent_snapshot) = ic
                        .find_parent_snapshot_for_stacks_block(&ch, &bhh)
                        .unwrap_or(None)
                    {
                        // replay in this consensus hash history
                        debug!("Replay Stacks block from {} to {}/{}", &alt_ch, &ch, &bhh);
                        let ic = self.sortition_db.index_conn();
                        let _ = self.chain_state_db.preprocess_anchored_block(
                            &ic,
                            &ch,
                            &block,
                            &parent_snapshot.consensus_hash,
                            get_epoch_time_secs(),
                        );
                        processed = true;
                        break;
                    }
                }
            }

            if !processed {
                test_debug!("Did NOT replay {}", &bhh);
            }
        }
        Ok(())
    }

    /// Try and replay a newly-discovered (or re-affirmed) sortition's associated Stacks block, if
    /// we have it.
    #[cfg_attr(test, mutants::skip)]
    fn try_replay_stacks_block(
        &mut self,
        canonical_snapshot: &BlockSnapshot,
        next_snapshot: &BlockSnapshot,
    ) -> Result<(), Error> {
        let staging_block_chs = StacksChainState::get_staging_block_consensus_hashes(
            self.chain_state_db.db(),
            &next_snapshot.winning_stacks_block_hash,
        )?;

        let mut found = false;
        for ch in staging_block_chs.iter() {
            if *ch == next_snapshot.consensus_hash {
                found = true;
                break;
            }
        }

        if !found && !staging_block_chs.is_empty() {
            // we have seen this block before, but in a different consensus fork.
            // queue it for re-processing -- it might still be valid if it's in a reward
            // cycle that exists on the new PoX fork.
            debug!(
                "Sortition re-processes Stacks block {}, which is present on a different PoX fork",
                &next_snapshot.winning_stacks_block_hash
            );

            self.replay_stacks_blocks(
                canonical_snapshot,
                vec![next_snapshot.winning_stacks_block_hash.clone()],
            )?;
        }
        Ok(())
    }

    ///
    /// Process any ready staging blocks until there are either:
    ///   * there are no more to process
    ///   * a PoX anchor block is processed which invalidates the current PoX fork
    ///
    /// Returns Some(BlockHeaderHash) if such an anchor block is discovered,
    ///   otherwise returns None
    ///
    fn process_ready_blocks(&mut self) -> Result<Option<BlockHeaderHash>, Error> {
        let canonical_sortition_tip = self.canonical_sortition_tip.clone().expect(
            "FAIL: processing a new Stacks block, but don't have a canonical sortition tip",
        );

        let sortdb_handle = self
            .sortition_db
            .tx_handle_begin(&canonical_sortition_tip)?;
        let mut processed_blocks =
            self.chain_state_db
                .process_blocks(sortdb_handle, 1, self.dispatcher)?;

        while let Some(block_result) = processed_blocks.pop() {
            if block_result.0.is_none() && block_result.1.is_none() {
                // this block was invalid
                debug!("Bump blocks processed (invalid)");
                self.notifier.notify_stacks_block_processed();
                increment_stx_blocks_processed_counter();
            } else if let (Some(block_receipt), _) = block_result {
                // only bump the coordinator's state if the processed block
                //   is in our sortition fork
                //  TODO: we should update the staging block logic to prevent
                //    blocks like these from getting processed at all.
                let in_sortition_set = self.sortition_db.is_stacks_block_in_sortition_set(
                    &canonical_sortition_tip,
                    &block_receipt.header.anchored_header.block_hash(),
                )?;

                if in_sortition_set {
                    // if .signers was updated, notify the p2p thread
                    if block_receipt.signers_updated {
                        self.refresh_stacker_db
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                    }

                    let new_canonical_block_snapshot = SortitionDB::get_block_snapshot(
                        self.sortition_db.conn(),
                        &canonical_sortition_tip,
                    )?
                    .unwrap_or_else(|| {
                        panic!(
                            "FAIL: could not find data for the canonical sortition {}",
                            &canonical_sortition_tip
                        )
                    });
                    let new_canonical_stacks_block =
                        new_canonical_block_snapshot.get_canonical_stacks_block_id();

                    debug!("Bump blocks processed ({})", &new_canonical_stacks_block);

                    self.notifier.notify_stacks_block_processed();
                    increment_stx_blocks_processed_counter();

                    Self::process_atlas_attachment_events(
                        self.atlas_db.as_mut(),
                        &self.atlas_config,
                        &block_receipt,
                        new_canonical_block_snapshot.canonical_stacks_tip_height,
                    );

                    let block_hash = block_receipt.header.anchored_header.block_hash();

                    // update cost estimator
                    if let Some(ref mut estimator) = self.cost_estimator {
                        let stacks_epoch = SortitionDB::get_stacks_epoch_by_epoch_id(
                            self.sortition_db.conn(),
                            &block_receipt.evaluated_epoch,
                        )?
                        .expect("Could not find a stacks epoch.");
                        estimator.notify_block(
                            &block_receipt.tx_receipts,
                            &stacks_epoch.block_limit,
                            &stacks_epoch.epoch_id,
                        );
                    }

                    // update fee estimator
                    if let Some(ref mut estimator) = self.fee_estimator {
                        let stacks_epoch = SortitionDB::get_stacks_epoch_by_epoch_id(
                            self.sortition_db.conn(),
                            &block_receipt.evaluated_epoch,
                        )?
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

                    // Was this block sufficiently confirmed by the prepare phase that it was a PoX
                    // anchor block?  And if we're in epoch 2.1, does it match the heaviest-confirmed
                    // block-commit in the burnchain DB, and is it affirmed by the majority of the
                    // network?
                    if let Some(pox_anchor) = self
                        .sortition_db
                        .is_stacks_block_pox_anchor(&block_hash, &canonical_sortition_tip)?
                    {
                        debug!("Discovered PoX anchor block {block_hash} off of canonical sortition tip {canonical_sortition_tip}");

                        return Ok(Some(pox_anchor));
                    }
                }
            }
            // TODO: do something with a poison result

            let sortdb_handle = self
                .sortition_db
                .tx_handle_begin(&canonical_sortition_tip)?;
            // Right before a block is set to processed, the event dispatcher will emit a new block event
            processed_blocks =
                self.chain_state_db
                    .process_blocks(sortdb_handle, 1, self.dispatcher)?;
        }

        Ok(None)
    }

    /// A helper function for exposing the private process_new_pox_anchor_test function
    #[cfg(test)]
    pub fn process_new_pox_anchor_test(
        &mut self,
        block_id: BlockHeaderHash,
        already_processed_burn_blocks: &mut HashSet<BurnchainHeaderHash>,
    ) -> Result<Option<BlockHeaderHash>, Error> {
        self.process_new_pox_anchor(block_id, already_processed_burn_blocks)
    }

    /// Process a new PoX anchor block, possibly resulting in the PoX history being unwound and
    /// replayed through a different sequence of consensus hashes.  If the new anchor block causes
    /// the node to reach a prepare-phase that elects a network-affirmed anchor block that we don't
    /// have, then return its block hash so the caller can go download and process it.
    fn process_new_pox_anchor(
        &mut self,
        block_id: BlockHeaderHash,
        already_processed_burn_blocks: &mut HashSet<BurnchainHeaderHash>,
    ) -> Result<Option<BlockHeaderHash>, Error> {
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
            .unwrap_or_else(|| panic!("FAIL: expected to get a sortition for a chosen anchor block {block_id}, but not found."));

        // was this block a pox anchor for an even earlier reward cycle?
        while let Some(older_prep_end) = self
            .sortition_db
            .get_prepare_end_for(&prep_end.sortition_id, &block_id)?
        {
            prep_end = older_prep_end;
        }

        info!(
            "Reprocessing with anchor block information, starting at block height: {}",
            prep_end.block_height;
            "consensus_hash" => %prep_end.consensus_hash,
            "burn_block_hash" => %prep_end.burn_header_hash,
            "stacks_block_height" => prep_end.stacks_block_height
        );
        let mut pox_id = self.sortition_db.get_pox_id(sortition_id)?;
        pox_id.extend_with_present_block();

        // invalidate all the sortitions > canonical_sortition_tip, in the same burnchain fork
        self.sortition_db
            .invalidate_descendants_of(&prep_end.burn_header_hash)?;

        // roll back to the state as of prep_end
        self.canonical_sortition_tip = Some(prep_end.sortition_id);

        // Start processing from the beginning of the new PoX reward set
        self.handle_new_epoch2_burnchain_block(already_processed_burn_blocks)
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
        let max_height = SortitionDB::get_highest_block_height_from_path(sortdb_path)
            .expect("FATAL: could not query sortition DB for maximum block height");
        let cur_epoch_idx = StacksEpoch::find_epoch(epochs, max_height)
            .unwrap_or_else(|| panic!("FATAL: no epoch defined for burn height {max_height}"));
        let cur_epoch = epochs
            .get(cur_epoch_idx)
            .expect("FATAL: failed to index epochs list")
            .epoch_id;

        // save for later
        cur_epoch_opt = Some(cur_epoch);
        let db_version = SortitionDB::get_db_version_from_path(sortdb_path)?
            .expect("FATAL: could not load sortition DB version");

        if !SortitionDB::is_db_version_supported_in_epoch(cur_epoch, db_version) {
            error!("Sortition DB at {sortdb_path} does not support epoch {cur_epoch}");
            return Ok(false);
        }
    } else {
        warn!("Sortition DB {} does not exist; assuming it will be instantiated with the correct version", sortdb_path);
    }

    if fs::metadata(chainstate_path).is_ok() {
        let cur_epoch = cur_epoch_opt.expect(
            "FATAL: chainstate corruption: sortition DB does not exist, but chainstate does.",
        );
        let db_config = StacksChainState::get_db_config_from_path(chainstate_path)?;
        if !db_config.supports_epoch(cur_epoch) {
            error!("Chainstate DB at {chainstate_path} does not support epoch {cur_epoch}");
            return Ok(false);
        }
    } else {
        warn!("Chainstate DB {chainstate_path} does not exist; assuming it will be instantiated with the correct version");
    }

    Ok(true)
}

/// Sortition DB migrator.
/// This is an opaque struct that is meant to assist migrating an epoch 2.1-2.4 chainstate to epoch
/// 2.5.  It will not work for 2.5 to 3.0+
pub struct SortitionDBMigrator {
    chainstate: Option<StacksChainState>,
    burnchain: Burnchain,
    burnchain_db: BurnchainDB,
}

impl SortitionDBMigrator {
    /// Instantiate the migrator.
    /// The chainstate must already exist
    pub fn new(
        burnchain: Burnchain,
        chainstate_path: &str,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<Self, Error> {
        let db_config = StacksChainState::get_db_config_from_path(chainstate_path)?;
        let (chainstate, _) = StacksChainState::open(
            db_config.mainnet,
            db_config.chain_id,
            chainstate_path,
            marf_opts,
        )?;
        let burnchain_db = BurnchainDB::open(&burnchain.get_burnchaindb_path(), false)?;

        Ok(Self {
            chainstate: Some(chainstate),
            burnchain,
            burnchain_db,
        })
    }

    /// Get the burnchain reference
    pub fn get_burnchain(&self) -> &Burnchain {
        &self.burnchain
    }

    /// Regenerate a reward cycle.  Do this by re-calculating the RewardSetInfo for the given
    /// reward cycle.  This should store the preprocessed reward cycle info to the sortition DB.
    pub fn regenerate_reward_cycle_info(
        &mut self,
        sort_db: &mut SortitionDB,
        reward_cycle: u64,
    ) -> Result<RewardCycleInfo, DBError> {
        let rc_start = sort_db
            .pox_constants
            .reward_cycle_to_block_height(sort_db.first_block_height, reward_cycle)
            .saturating_sub(1);

        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn())?;

        let ancestor_sn = {
            let sort_ih = sort_db.index_handle(&sort_tip.sortition_id);
            let sn = sort_ih
                .get_block_snapshot_by_height(rc_start)?
                .ok_or(DBError::NotFoundError)?;
            sn
        };

        let mut chainstate = self
            .chainstate
            .take()
            .expect("FATAL: failed to replace chainstate");

        // NOTE: this stores the preprocessed reward cycle info to the sortition DB as a
        // side-effect!
        let rc_info_opt_res = get_reward_cycle_info(
            ancestor_sn.block_height + 1,
            &ancestor_sn.burn_header_hash,
            &ancestor_sn.sortition_id,
            &self.burnchain,
            &mut chainstate,
            sort_db,
            &OnChainRewardSetProvider::new(),
        )
        .map_err(|e| DBError::Other(format!("get_reward_cycle_info: {:?}", &e)));

        self.chainstate = Some(chainstate);

        let rc_info = rc_info_opt_res?
            .expect("FATAL: No reward cycle info calculated at a reward-cycle start");
        Ok(rc_info)
    }
}

/// Migrate all databases to their latest schemas.
/// Verifies that this is possible as well
#[cfg_attr(test, mutants::skip)]
pub fn migrate_chainstate_dbs(
    epochs: &[StacksEpoch],
    burnchain: &Burnchain,
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
        let migrator = SortitionDBMigrator::new(
            burnchain.clone(),
            chainstate_path,
            chainstate_marf_opts.clone(),
        )?;
        SortitionDB::migrate_if_exists(sortdb_path, epochs, migrator)?;
    }
    if fs::metadata(&chainstate_path).is_ok() {
        info!("Migrating chainstate DB to the latest schema version");
        let db_config = StacksChainState::get_db_config_from_path(chainstate_path)?;

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
