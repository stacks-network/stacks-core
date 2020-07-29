use std::collections::VecDeque;
use std::{
    thread, process
};
use std::time::Duration;
use std::sync::{Arc, RwLock};

use crossbeam_channel::{select, bounded, Sender, Receiver, Select, TrySendError};


use burnchains::{
    BurnchainHeaderHash, Error as BurnchainError,
    Burnchain, BurnchainBlockHeader
};
use chainstate::burn::{BlockHeaderHash, BlockSnapshot};
use chainstate::burn::db::sortdb::{SortitionDB, PoxId, SortitionId};
use chainstate::stacks::{
    StacksBlock, StacksBlockId, TransactionPayload,
    Error as ChainstateError
};
use chainstate::stacks::db::{
    StacksHeaderInfo, StacksChainState
};
use core;
use chainstate::stacks::events::{StacksTransactionReceipt};

use burnchains::db::{
    BurnchainDB, BurnchainBlockData
};

use util::db::{
    Error as DBError
};

#[derive(Debug, PartialEq)]
pub struct RewardCycleInfo {
    /// what was the elected PoX anchor, if any?
    pub anchor_block: Option<BlockHeaderHash>,
    /// was the elected PoX anchor known?
    pub anchor_block_known: bool
}

pub struct ChainsCoordinator {
    canonical_burnchain_chain_tip: Option<BurnchainHeaderHash>,
    canonical_sortition_tip: Option<SortitionId>,
    canonical_chain_tip: Option<StacksBlockId>,
    canonical_pox_id: Option<PoxId>,
    burnchain_blocks_db: BurnchainDB,
    chain_state_db: StacksChainState,
    sortition_db: SortitionDB,
    burnchain: Burnchain,
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

struct CoordinatorChannels {
    new_stacks_block_channel: Sender<()>,
    new_burn_block_channel: Sender<()>
}

pub enum ChainsEventCallback {
    BlockProcessed,
    BurnchainBlockProcessed,
}

// Singleton for ChainsCoordinator

lazy_static! {
    // ChainsCoordinator takes two kinds of signals:
    //    new stacks block & new burn block
    // These signals can be coalesced -- the coordinator doesn't need
    //    handles _all_ new blocks whenever it processes an event
    //    because of this, we can avoid trying to set large bounds on these
    //    event channels by using a coalescing thread.
    static ref COORDINATOR_CHANNELS: RwLock<Option<CoordinatorChannels>> = RwLock::new(None);
}

impl ChainsCoordinator {
    pub fn announce_new_stacks_block() {
        let result = COORDINATOR_CHANNELS.read().unwrap()
            .as_ref()
            .expect("FAIL: attempted to announce new stacks block to chains coordinator, but instance not constructed.")
            .new_stacks_block_channel
            .try_send(());
        match result {
            // don't need to do anything if the channel is full -- the coordinator
            //  will check for the new block when it processes the next block anyways
            Ok(_) | Err(TrySendError::Full(_)) => {},
            Err(TrySendError::Disconnected(_)) => {
                warn!("ChainsCoordinator hung up, exiting...");
                process::exit(-1);
            },
        }
    }

    pub fn announce_burn_block() {
        let result = COORDINATOR_CHANNELS.read().unwrap()
            .as_ref()
            .expect("FAIL: attempted to announce new stacks block to chains coordinator, but instance not constructed.")
            .new_burn_block_channel
            .try_send(());
        match result {
            // don't need to do anything if the channel is full -- the coordinator
            //  will check for the new block when it processes the next block anyways
            Ok(_) | Err(TrySendError::Full(_)) => {},
            Err(TrySendError::Disconnected(_)) => {
                warn!("ChainsCoordinator hung up, exiting...");
                process::exit(-1);
            },
        }
    }

    pub fn main() {
        let (stacks_block_receiver, burn_block_receiver) = {
            let mut channel_storage = COORDINATOR_CHANNELS.write().unwrap();
            if channel_storage.is_some() {
                panic!("FAIL: attempted to start chains coordinator, but instance already constructed.");
            }

            let (stacks_block_sender, stacks_block_receiver) = bounded(1);
            let (burn_block_sender, burn_block_receiver) = bounded(1);

            channel_storage.replace(CoordinatorChannels {
                new_stacks_block_channel: stacks_block_sender,
                new_burn_block_channel: burn_block_sender
            });

            (stacks_block_receiver, burn_block_receiver)
        };

        let burnchain_blocks_db = BurnchainDB::open("burnchain.db", true).unwrap();
        let chain_state_db = StacksChainState::open(true, 0x80, "chainstate.db").unwrap();
        let sortition_db = SortitionDB::connect(
            "sortition_db", 0, &core::FIRST_BURNCHAIN_BLOCK_HASH, core::FIRST_BURNCHAIN_BLOCK_TIMESTAMP, true).unwrap();
        let burnchain = Burnchain::new("burnchain_dir", "bitcoin", "testnet").unwrap();

        let mut inst = ChainsCoordinator {
            canonical_burnchain_chain_tip: None,
            canonical_chain_tip: None,
            canonical_sortition_tip: None,
            canonical_pox_id: None,
            burnchain_blocks_db,
            chain_state_db,
            sortition_db,
            burnchain,
        };


        let mut recv_selector = Select::new();
        let oper_stacks_block = recv_selector.recv(&stacks_block_receiver);
        let oper_burn_block = recv_selector.recv(&burn_block_receiver);

        loop {
            // timeout so that we handle Ctrl-C a little gracefully
            let ready_oper = match recv_selector.select_timeout(Duration::from_millis(500)) {
                Ok(op) => op.index(),
                Err(_) => continue,
            };

            if ready_oper == oper_stacks_block {
                if let Err(e) = inst.process_ready_blocks() {
                    warn!("Error processing new stacks block: {:?}", e);
                }
            } else if ready_oper == oper_burn_block {
                if let Err(e) = inst.handle_new_burnchain_block() {
                    warn!("Error processing new burn block: {:?}", e);
                }
            } else {
                unreachable!("Ready channel for non-registered channel");
            }
        }
    }

    pub fn handle_new_burnchain_block(&mut self) -> Result<(), Error> {
        // Retrieve canonical burnchain chain tip from the BurnchainBlocksDB
        let canonical_burnchain_tip = self.burnchain_blocks_db.get_canonical_chain_tip()?;

        // Early return: this block has already been processed
        if let Some(ref current) = self.canonical_burnchain_chain_tip {
            if current == &canonical_burnchain_tip.block_hash {
                return Err(Error::BurnchainBlockAlreadyProcessed)
            }
        }

        // Retrieve canonical pox id (<=> reward cycle id)
        let canonical_sortition_tip = self.canonical_sortition_tip.as_ref()
            .expect("FAIL: no canonical sortition tip");

        // Retrieve all the direct ancestors of this block with an unprocessed sortition 
        let mut cursor = canonical_burnchain_tip.block_hash.clone();
        let mut sortitions_to_process = VecDeque::new();

        // We halt the ancestry research as soon as we find a processed parent
        while !(self.sortition_db.is_sortition_processed(&cursor, canonical_sortition_tip)?) {
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
            let canonical_sortition_tip = self.canonical_sortition_tip.as_ref()
                .expect("FAIL: no canonical sortition tip");

            // at this point, we need to figure out if the sortition we are
            //  about to process is the first block in reward cycle.
            let reward_cycle_info = self.get_reward_cycle_info(&header);
            let sortition_id = self.sortition_db.evaluate_sortition(
                &header, ops, &self.burnchain, &canonical_sortition_tip, reward_cycle_info)
                .map_err(|e| {
                    error!("ChainsCoordinator: unable to evaluate sortition {:?}", e);
                    Error::FailedToProcessSortition(e)
                })?
                .0.sortition_id;

            debug!("Sortition processed: {}", sortition_id);

            if let Some(pox_anchor) = self.process_ready_blocks()? {
                return self.process_new_pox_anchor(&pox_anchor)
            }
        }

        Ok(())
    }

    /// returns None if this burnchain block is _not_ the start of a reward cycle
    ///         otherwise, returns the required reward cycle info for this burnchain block
    ///                     in our current sortition view:
    ///           * PoX anchor block
    ///           * Was PoX anchor block known?
    fn get_reward_cycle_info(&self, burn_header: &BurnchainBlockHeader) -> Option<RewardCycleInfo> {
        if self.burnchain.is_reward_cycle_start(burn_header.block_height) {
            Some(RewardCycleInfo {
                anchor_block: None,
                anchor_block_known: true
            })
        } else {
            None
        }
    }

    ///
    /// Process any ready staging blocks until there are no more to process
    ///  _or_ a PoX anchor block is discovered.
    ///
    /// Returns Some(StacksBlockId) if an anchor block is discovered,
    ///   otherwise returns None
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
                    if let Some(pox_anchor) = self.sortition_db.is_stacks_block_pox_anchor(&block_receipt.header, canonical_sortition_tip)? {
                        return Ok(Some(pox_anchor));
                    }
                }

                // TODO: broadcast the events
            }
            // TODO: do something with a poison result

            let sortdb_handle = self.sortition_db.tx_handle_begin(canonical_sortition_tip)?;
            processed_blocks = self.chain_state_db.process_blocks(sortdb_handle, 1)?;
        }

        Ok(None)
    }

    fn process_new_pox_anchor(&mut self, block_id: &BlockHeaderHash) -> Result<(), Error> {
        // get the last sortition in the prepare phase that chose this anchor block
        //   that sortition is now the current canonical sortition,
        //   and now that we have process the anchor block for the corresponding reward phase,
        //   update the canonical pox bitvector.
        let sortition_id = self.canonical_sortition_tip.as_ref()
            .expect("FAIL: processing a new anchor block, but don't have a canonical sortition tip");

        let prep_end = self.sortition_db.get_prepare_end_for(sortition_id, block_id)?
            .expect(&format!("FAIL: expected to get a sortition for a chosen anchor block {}, but not found.", block_id));
        let mut pox_id = self.sortition_db.get_pox_id(sortition_id)?;
        pox_id.extend_with_present_block();

        // roll back to the state as of prep_end
        self.canonical_chain_tip = Some(StacksBlockId::new(&prep_end.consensus_hash, &prep_end.canonical_stacks_tip_hash));
        self.canonical_sortition_tip = Some(prep_end.sortition_id);
        self.canonical_pox_id = Some(pox_id);

        // Start processing from the beginning of the new PoX reward set
        self.handle_new_burnchain_block()
    }
}
