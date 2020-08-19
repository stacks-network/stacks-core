use std::collections::VecDeque;
use std::time::{
    Duration
};

use burnchains::{
    Error as BurnchainError,
    Burnchain, BurnchainBlockHeader,
    db::{
        BurnchainDB, BurnchainBlockData
    }
};
use chainstate::burn::{
    BlockHeaderHash, ConsensusHash,
    db::sortdb::{
        SortitionDB, PoxId, SortitionId
    }
};
use chainstate::stacks::{
    StacksBlock, StacksBlockId, StacksAddress,
    Error as ChainstateError, events::StacksTransactionReceipt,
    db::{
        StacksHeaderInfo, StacksChainState, ClarityTx
    }
};
use monitoring::{
    increment_stx_blocks_processed_counter,
};
use vm::{
    costs::ExecutionCost,
    types::PrincipalData
};
use util::db::{
    Error as DBError
};

pub mod comm;

#[cfg(test)]
mod tests;

pub use self::comm::CoordinatorCommunication;

use chainstate::coordinator::comm::{
    CoordinatorNotices, CoordinatorReceivers, ArcCounterCoordinatorNotices, CoordinatorEvents
};

/// The 3 different states for the current
///  reward cycle's relationship to its PoX anchor
#[derive(Debug, PartialEq)]
pub enum PoxAnchorBlockStatus {
    SELECTED_AND_KNOWN(BlockHeaderHash, Vec<StacksAddress>),
    SELECTED_AND_UNKNOWN(BlockHeaderHash),
    NOT_SELECTED,
}

#[derive(Debug, PartialEq)]
pub struct RewardCycleInfo {
    pub anchor_status: PoxAnchorBlockStatus,
}

impl RewardCycleInfo {
    pub fn selected_anchor_block(&self) -> Option<&BlockHeaderHash> {
        use self::PoxAnchorBlockStatus::*;
        match self.anchor_status {
            SELECTED_AND_UNKNOWN(ref block) | SELECTED_AND_KNOWN(ref block, _) => Some(block),
            NOT_SELECTED => None
        }
    }
    pub fn is_reward_info_known(&self) -> bool {
        use self::PoxAnchorBlockStatus::*;
        match self.anchor_status {
            SELECTED_AND_UNKNOWN(_) => false,
            SELECTED_AND_KNOWN(_, _) | NOT_SELECTED => true
        }
    }
    pub fn known_selected_anchor_block(&self) -> Option<&Vec<StacksAddress>> {
        use self::PoxAnchorBlockStatus::*;
        match self.anchor_status {
            SELECTED_AND_UNKNOWN(_) => None,
            SELECTED_AND_KNOWN(_, ref reward_set) => Some(reward_set),
            NOT_SELECTED => None
        }
    }
    pub fn known_selected_anchor_block_owned(self) -> Option<Vec<StacksAddress>> {
        use self::PoxAnchorBlockStatus::*;
        match self.anchor_status {
            SELECTED_AND_UNKNOWN(_) => None,
            SELECTED_AND_KNOWN(_, reward_set) => Some(reward_set),
            NOT_SELECTED => None
        }
    }
}

pub trait BlockEventDispatcher {
    fn announce_block(&self, block: StacksBlock, metadata: StacksHeaderInfo,
                      receipts: Vec<StacksTransactionReceipt>, parent: &StacksBlockId);
}

pub struct ChainsCoordinator <'a, T: BlockEventDispatcher, N: CoordinatorNotices, R: RewardSetProvider> {
    canonical_sortition_tip: Option<SortitionId>,
    canonical_chain_tip: Option<StacksBlockId>,
    canonical_pox_id: Option<PoxId>,
    burnchain_blocks_db: BurnchainDB,
    chain_state_db: StacksChainState,
    sortition_db: SortitionDB,
    burnchain: Burnchain,
    dispatcher: Option<&'a T>,
    reward_set_provider: R,
    notifier: N,
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
    fn get_reward_set(&self, chainstate: &StacksChainState,
                      pox_anchor_hash: &BlockHeaderHash, pox_anchor_consensus: &ConsensusHash) -> Result<Vec<StacksAddress>, Error>;
}

pub struct PlaceholderRewardSetProvider();
impl RewardSetProvider for PlaceholderRewardSetProvider {
    fn get_reward_set(&self, _chainstate: &StacksChainState,
                      _pox_anchor_hash: &BlockHeaderHash, _pox_anchor_consensus: &ConsensusHash) -> Result<Vec<StacksAddress>, Error> {
        Ok(vec![])
    }
}

impl <'a, T: BlockEventDispatcher> ChainsCoordinator <'a, T, ArcCounterCoordinatorNotices, PlaceholderRewardSetProvider> {
    pub fn run<F>(chain_state_path: &str, burnchain: Burnchain, stacks_mainnet: bool, stacks_chain_id: u32,
                  initial_balances: Option<Vec<(PrincipalData, u64)>>,
                  block_limit: ExecutionCost, dispatcher: &T, comms: CoordinatorReceivers,
                  boot_block_exec: F)
        where F: FnOnce(&mut ClarityTx), T: BlockEventDispatcher {

        let stacks_blocks_processed = comms.stacks_blocks_processed.clone();
        let sortitions_processed = comms.sortitions_processed.clone();

        let sortition_db = SortitionDB::open(&burnchain.get_db_path(), true).unwrap();
        let burnchain_blocks_db = BurnchainDB::open(&burnchain.get_burnchaindb_path(), false).unwrap();
        let chain_state_db = StacksChainState::open_and_exec(
            stacks_mainnet, stacks_chain_id, chain_state_path,
            initial_balances, boot_block_exec, block_limit).unwrap();

        let canonical_sortition_tip = SortitionDB::get_canonical_sortition_tip(sortition_db.conn()).unwrap();

        let arc_notices = ArcCounterCoordinatorNotices { stacks_blocks_processed, sortitions_processed };

        let mut inst = ChainsCoordinator {
            canonical_chain_tip: None,
            canonical_sortition_tip: Some(canonical_sortition_tip),
            canonical_pox_id: None,
            burnchain_blocks_db,
            chain_state_db,
            sortition_db,
            burnchain,
            dispatcher: Some(dispatcher),
            notifier: arc_notices,
            reward_set_provider: PlaceholderRewardSetProvider(),
        };

        loop {
            // timeout so that we handle Ctrl-C a little gracefully
            match comms.wait_on() {
                CoordinatorEvents::NEW_STACKS_BLOCK => {
                    debug!("Received new stacks block notice");
                    if let Err(e) = inst.handle_new_stacks_block() {
                        warn!("Error processing new stacks block: {:?}", e);
                    }
                },
                CoordinatorEvents::NEW_BURN_BLOCK => {
                    debug!("Received new burn block notice");
                    if let Err(e) = inst.handle_new_burnchain_block() {
                        warn!("Error processing new burn block: {:?}", e);
                    }
                },
                CoordinatorEvents::STOP => {
                    debug!("Received stop notice");
                    return
                },
                CoordinatorEvents::TIMEOUT => {
                },
            }
        }
    }
}

impl <'a, T: BlockEventDispatcher, U: RewardSetProvider> ChainsCoordinator <'a, T, (), U> {
    #[cfg(test)]
    pub fn test_new(burnchain: &Burnchain, path: &str, reward_set_provider: U) -> ChainsCoordinator<'a, T, (), U> {
        let burnchain = burnchain.clone();

        let sortition_db = SortitionDB::open(&burnchain.get_db_path(), true).unwrap();
        let burnchain_blocks_db = BurnchainDB::open(&burnchain.get_burnchaindb_path(), false).unwrap();
        let chain_state_db = StacksChainState::open(false, 0xdeadbeef, &format!("{}/chainstate/", path)).unwrap();

        let canonical_sortition_tip = SortitionDB::get_canonical_sortition_tip(sortition_db.conn()).unwrap();

        ChainsCoordinator {
            canonical_chain_tip: None,
            canonical_sortition_tip: Some(canonical_sortition_tip),
            canonical_pox_id: None,
            burnchain_blocks_db,
            chain_state_db,
            sortition_db,
            burnchain,
            dispatcher: None,
            reward_set_provider,
            notifier: ()
        }
    }
}

impl <'a, T: BlockEventDispatcher, N: CoordinatorNotices, U: RewardSetProvider> ChainsCoordinator <'a, T, N, U> {
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

        // Retrieve canonical pox id (<=> reward cycle id)
        let mut canonical_sortition_tip = self.canonical_sortition_tip.clone()
            .expect("FAIL: no canonical sortition tip");

        // Retrieve all the direct ancestors of this block with an unprocessed sortition 
        let mut cursor = canonical_burnchain_tip.block_hash.clone();
        let mut sortitions_to_process = VecDeque::new();

        // We halt the ancestry research as soon as we find a processed parent
        while !(self.sortition_db.is_sortition_processed(&cursor, &canonical_sortition_tip)?) {
            let current_block = self.burnchain_blocks_db.get_burnchain_block(&cursor)
                .map_err(|e| {
                    warn!("ChainsCoordinator: could not retrieve  block burnhash={}", &cursor);
                    Error::NonContiguousBurnchainBlock(e)
                })?;

            let parent = current_block.header.parent_block_hash.clone();
            sortitions_to_process.push_front(current_block);
            cursor = parent;
        }

        for unprocessed_block in sortitions_to_process.drain(..) {
            let BurnchainBlockData { header, ops } = unprocessed_block;

            let sortition_tip_snapshot = SortitionDB::get_block_snapshot(
                self.sortition_db.conn(), &canonical_sortition_tip)?
                .expect("BUG: no data for sortition");

            // at this point, we need to figure out if the sortition we are
            //  about to process is the first block in reward cycle.
            let reward_cycle_info = self.get_reward_cycle_info(&header)?;
            let sortition_id = self.sortition_db.evaluate_sortition(
                &header, ops, &self.burnchain, &canonical_sortition_tip, reward_cycle_info)
                .map_err(|e| {
                    error!("ChainsCoordinator: unable to evaluate sortition {:?}", e);
                    Error::FailedToProcessSortition(e)
                })?
                .0.sortition_id;

            self.notifier.notify_sortition_processed();

            debug!("Sortition processed: {}", &sortition_id);

            if sortition_tip_snapshot.block_height < header.block_height {
                // bump canonical sortition...
                self.canonical_sortition_tip = Some(sortition_id.clone());
                canonical_sortition_tip = sortition_id;
            }

            if let Some(pox_anchor) = self.process_ready_blocks()? {
                return self.process_new_pox_anchor(pox_anchor)
            }
        }

        Ok(())
    }

    /// returns None if this burnchain block is _not_ the start of a reward cycle
    ///         otherwise, returns the required reward cycle info for this burnchain block
    ///                     in our current sortition view:
    ///           * PoX anchor block
    ///           * Was PoX anchor block known?
    pub fn get_reward_cycle_info(&self, burn_header: &BurnchainBlockHeader) -> Result<Option<RewardCycleInfo>, Error> {
        if self.burnchain.is_reward_cycle_start(burn_header.block_height) {
            info!("Beginning reward cycle. block_height={}", burn_header.block_height);
            let reward_cycle_info = {
                let ic = self.sortition_db.index_handle(
                    self.canonical_sortition_tip.as_ref()
                        .expect("FATAL: Processing anchor block, but no known sortition tip"));
                ic.get_reward_cycle_info(&burn_header.parent_block_hash, &self.burnchain.pox_constants)
            }?;
            if let Some((consensus_hash, stacks_block_hash)) = reward_cycle_info {
                info!("Anchor block selected: {}", stacks_block_hash);
                let anchor_block_known = StacksChainState::is_stacks_block_processed(
                    &self.chain_state_db.headers_db, &consensus_hash, &stacks_block_hash)?;
                let anchor_status = if anchor_block_known {
                    let reward_set = self.reward_set_provider.get_reward_set(
                        &self.chain_state_db, &stacks_block_hash, &consensus_hash)?;
                    PoxAnchorBlockStatus::SELECTED_AND_KNOWN(stacks_block_hash, reward_set)
                } else {
                    PoxAnchorBlockStatus::SELECTED_AND_UNKNOWN(stacks_block_hash)
                };
                Ok(Some(RewardCycleInfo { anchor_status }))
            } else {
                Ok(Some(RewardCycleInfo {
                    anchor_status: PoxAnchorBlockStatus::NOT_SELECTED
                }))
            }
        } else {
            Ok(None)
        }
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
        let canonical_sortition_tip = self.canonical_sortition_tip.as_ref()
            .expect("FAIL: processing a new Stacks block, but don't have a canonical sortition tip");

        let sortdb_handle = self.sortition_db.tx_handle_begin(canonical_sortition_tip)?;
        let mut processed_blocks = self.chain_state_db.process_blocks(sortdb_handle, 1)?;

        while let Some(block_result) = processed_blocks.pop() {
            if let (Some(block_receipt), _) = block_result {
                // only bump the coordinator's state if the processed block
                //   is in our sortition fork
                //  TODO: we should update the staging block logic to prevent
                //    blocks like these from getting processed at all.
                let in_sortition_set = self.sortition_db.is_stacks_block_in_sortition_set(
                    canonical_sortition_tip, &block_receipt.header.anchored_header.block_hash())?;
                if in_sortition_set {
                    let new_canonical_stacks_block = SortitionDB::get_block_snapshot(self.sortition_db.conn(), canonical_sortition_tip)?
                        .expect(&format!("FAIL: could not find data for the canonical sortition {}", canonical_sortition_tip))
                        .get_canonical_stacks_block_id();
                    self.canonical_chain_tip = Some(new_canonical_stacks_block);
                    debug!("Bump blocks processed");
                    self.notifier.notify_stacks_block_processed();
                    increment_stx_blocks_processed_counter();
                    let block_hash = block_receipt.header.anchored_header.block_hash();

                    if let Some(dispatcher) = self.dispatcher {
                        let metadata = &block_receipt.header;
                        let block: StacksBlock = {
                            let block_path = StacksChainState::get_block_path(
                                &self.chain_state_db.blocks_path,
                                &metadata.consensus_hash,
                                &block_hash).unwrap();
                            StacksChainState::consensus_load(&block_path).unwrap()
                        };
                        let stacks_block = StacksBlockId::new(&metadata.consensus_hash, &block_hash);
                        let parent = self.chain_state_db.get_parent(&stacks_block)
                            .expect("BUG: failed to get parent for processed block");
                        dispatcher.announce_block(block, block_receipt.header, block_receipt.tx_receipts, &parent);
                    }

                    // if, just after processing the block, we _know_ that this block is a pox anchor, that means
                    //   that sortitions have already begun processing that didn't know about this pox anchor.
                    //   we need to trigger an unwind 
                    if let Some(pox_anchor) = self.sortition_db.is_stacks_block_pox_anchor(&block_hash, canonical_sortition_tip)? {
                        info!("Discovered an old anchor block: {}", &pox_anchor);
                        return Ok(Some(pox_anchor));
                    }
                }
            }
            // TODO: do something with a poison result

            let sortdb_handle = self.sortition_db.tx_handle_begin(canonical_sortition_tip)?;
            processed_blocks = self.chain_state_db.process_blocks(sortdb_handle, 1)?;
        }

        Ok(None)
    }

    fn process_new_pox_anchor(&mut self, block_id: BlockHeaderHash) -> Result<(), Error> {
        // get the last sortition in the prepare phase that chose this anchor block
        //   that sortition is now the current canonical sortition,
        //   and now that we have process the anchor block for the corresponding reward phase,
        //   update the canonical pox bitvector.
        let sortition_id = self.canonical_sortition_tip.as_ref()
            .expect("FAIL: processing a new anchor block, but don't have a canonical sortition tip");

        let mut prep_end = self.sortition_db.get_prepare_end_for(sortition_id, &block_id)?
            .expect(&format!("FAIL: expected to get a sortition for a chosen anchor block {}, but not found.", &block_id));

        // was this block a pox anchor for an even earlier reward cycle?
        while let Some(older_prep_end) = self.sortition_db.get_prepare_end_for(&prep_end.sortition_id, &block_id)? {
            prep_end = older_prep_end;
        }

        info!("Reprocessing with anchor block information, starting at block height: {}", prep_end.block_height);
        let mut pox_id = self.sortition_db.get_pox_id(sortition_id)?;
        pox_id.extend_with_present_block();

        // invalidate all the sortitions > canonical_sortition_tip, in the same burnchain fork
        self.sortition_db.invalidate_descendants_of(&prep_end.burn_header_hash)?;

        // roll back to the state as of prep_end
        self.canonical_chain_tip = Some(StacksBlockId::new(&prep_end.consensus_hash, &prep_end.canonical_stacks_tip_hash));
        self.canonical_sortition_tip = Some(prep_end.sortition_id);
        self.canonical_pox_id = Some(pox_id);

        // Start processing from the beginning of the new PoX reward set
        self.handle_new_burnchain_block()
    }
}
