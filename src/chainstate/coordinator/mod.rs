use std::collections::VecDeque;
use std::{
    thread, process
};
use std::time::{
    Duration, Instant
};
use std::sync::{
    Arc, RwLock,
    atomic::{Ordering, AtomicU64}
};

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
    new_burn_block_channel: Sender<()>,
}

struct CoordinatorReceivers {
    event_stacks_block: Receiver<()>,
    event_burn_block: Receiver<()>,
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
    // how many stacks blocks have been processed by this Coordinator thread since startup?
    static ref STACKS_BLOCKS_PROCESSED: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    // how many sortitions have been processed by this Coordinator thread since startup?
    static ref SORTITIONS_PROCESSED: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    //
    static ref COORDINATOR_RECEIVERS: RwLock<Option<CoordinatorReceivers>> = RwLock::new(None);
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

    pub fn get_stacks_blocks_processed() -> u64 {
        STACKS_BLOCKS_PROCESSED.load(Ordering::SeqCst)
    }

    pub fn get_sortitions_processed() -> u64 {
        SORTITIONS_PROCESSED.load(Ordering::SeqCst)
    }

    /// wait for `current` to be surpassed, or timeout
    ///   returns `false` if timeout is reached
    ///   returns `true` if sortitions processed is passed
    pub fn wait_for_sortitions_processed(current: u64, timeout_millis: u64) -> bool {
        let start = Instant::now();
        while SORTITIONS_PROCESSED.load(Ordering::SeqCst) <= current {
            if start.elapsed() > Duration::from_millis(timeout_millis) {
                return false;
            }
            thread::sleep(Duration::from_millis(100));
            std::sync::atomic::spin_loop_hint();
        }
        return true
    }

    /// wait for `current` to be surpassed, or timeout
    ///   returns `false` if timeout is reached
    ///   returns `true` if sortitions processed is passed
    pub fn wait_for_stacks_blocks_processed(current: u64, timeout_millis: u64) -> bool {
        let start = Instant::now();
        while STACKS_BLOCKS_PROCESSED.load(Ordering::SeqCst) <= current {
            if start.elapsed() > Duration::from_millis(timeout_millis) {
                return false;
            }
            thread::sleep(Duration::from_millis(100));
            std::sync::atomic::spin_loop_hint();
        }
        return true
    }

    pub fn instantiate() {
        let (event_stacks_block, event_burn_block) = {
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

        let mut receiver_storage = COORDINATOR_RECEIVERS.write().unwrap();
        receiver_storage.replace(CoordinatorReceivers {
            event_burn_block, event_stacks_block
        });
    }

    pub fn run(state_path: &str, burnchain: &str) {
        let receivers = COORDINATOR_RECEIVERS.write().unwrap().take()
            .expect("FAIL: run() called before receiver channels set up, or ChainsCoordinator already running");

        let mut event_receiver = Select::new();
        let event_stacks_block = event_receiver.recv(&receivers.event_stacks_block);
        let event_burn_block = event_receiver.recv(&receivers.event_burn_block);

        let burnchain = Burnchain::new(&format!("{}/burnchain/db/", state_path), "bitcoin", burnchain).unwrap();

        let sortition_db = SortitionDB::open(&burnchain.get_db_path(), true).unwrap();
        let burnchain_blocks_db = BurnchainDB::open(&burnchain.get_burnchaindb_path(), false).unwrap();
        let chain_state_db = StacksChainState::open(true, 0x80, &format!("{}/chainstate/", state_path)).unwrap();

        let canonical_sortition_tip = SortitionDB::get_canonical_sortition_tip(sortition_db.conn()).unwrap();

        let mut inst = ChainsCoordinator {
            canonical_chain_tip: None,
            canonical_sortition_tip: Some(canonical_sortition_tip),
            canonical_pox_id: None,
            burnchain_blocks_db,
            chain_state_db,
            sortition_db,
            burnchain,
        };

        loop {
            // timeout so that we handle Ctrl-C a little gracefully
            let ready_oper = match event_receiver.select_timeout(Duration::from_millis(500)) {
                Ok(op) => op,
                Err(_) => continue,
            };

            match ready_oper.index() {
                i if i == event_stacks_block => {
                    info!("Received new stacks block notice");
                    // pop operation off of receiver
                    ready_oper.recv(&receivers.event_stacks_block).unwrap();
                    if let Err(e) = inst.process_ready_blocks() {
                        warn!("Error processing new stacks block: {:?}", e);
                    }
                },
                i if i == event_burn_block => {
                    // pop operation off of receiver
                    info!("Received new burn block notice");
                    ready_oper.recv(&receivers.event_burn_block).unwrap();
                    if let Err(e) = inst.handle_new_burnchain_block() {
                        warn!("Error processing new burn block: {:?}", e);
                    }
                },
                _ => {
                    unreachable!("Ready channel for non-registered channel");
                },
            }
        }
    }

    pub fn handle_new_burnchain_block(&mut self) -> Result<(), Error> {
        // Retrieve canonical burnchain chain tip from the BurnchainBlocksDB
        let canonical_burnchain_tip = self.burnchain_blocks_db.get_canonical_chain_tip()?;

        // Retrieve canonical pox id (<=> reward cycle id)
        let mut canonical_sortition_tip = self.canonical_sortition_tip.clone()
            .expect("FAIL: no canonical sortition tip");

//        info!("Canonical sortition tip: {}", canonical_sortition_tip);
//        info!("Canonical burnchain tip: {}@{}", canonical_burnchain_tip.block_hash, canonical_burnchain_tip.block_height);

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

            info!("Sortitions to process include: {}", cursor);
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
            let reward_cycle_info = self.get_reward_cycle_info(&header);
            let sortition_id = self.sortition_db.evaluate_sortition(
                &header, ops, &self.burnchain, &canonical_sortition_tip, reward_cycle_info)
                .map_err(|e| {
                    error!("ChainsCoordinator: unable to evaluate sortition {:?}", e);
                    Error::FailedToProcessSortition(e)
                })?
                .0.sortition_id;

            SORTITIONS_PROCESSED.fetch_add(1, Ordering::SeqCst);

            debug!("Sortition processed: {}", &sortition_id);

            if sortition_tip_snapshot.block_height < header.block_height {
                // bump canonical sortition...
                self.canonical_sortition_tip = Some(sortition_id.clone());
                canonical_sortition_tip = sortition_id;
            }

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
                    let block_hash = block_receipt.header.anchored_header.block_hash();
                    if let Some(pox_anchor) = self.sortition_db.is_stacks_block_pox_anchor(&block_hash, canonical_sortition_tip)? {
                        return Ok(Some(pox_anchor));
                    }
                }

                STACKS_BLOCKS_PROCESSED.fetch_add(1, Ordering::SeqCst);


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
