use std::collections::VecDeque;
use std::thread;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Sender};
use std::process;

use burnchains::{BurnchainHeaderHash, Error as BurnchainError};
use chainstate::burn::{BlockHeaderHash, BlockSnapshot};
use chainstate::burn::db::sortdb::{SortitionDB, PoxDB, PoxId, SortitionId};
use chainstate::stacks::{StacksBlock, StacksBlockId, TransactionPayload};
use chainstate::stacks::db::{StacksHeaderInfo};
use chainstate::stacks::events::{StacksTransactionReceipt};
use chainstate::stacks::db::StacksChainState;

use burnchains::db::BurnchainDB;

struct BlocksDB;
impl BlocksDB {

    pub fn stubbed() -> BlocksDB {
        BlocksDB {}
    }

    #[allow(unused_variables)]
    pub fn get_blocks_ready_to_process(&self, sortition_id: &SortitionId, sortition_db: &SortitionDB) -> Option<Vec<StacksBlockId>> {
        // This method will be calling sortition_db::latest_stacks_blocks_processed
        unimplemented!()
    }
}

struct ChainsCoordinator {
    canonical_burnchain_chain_tip: Option<BurnchainHeaderHash>,
    canonical_chain_tip: Option<StacksBlockId>,
    canonical_pox_id: Option<PoxId>,
    blocks_db: BlocksDB,
    burnchain_blocks_db: BurnchainDB,
    chain_state_db: StacksChainState,
    pox_db: PoxDB, 
    sortition_db: SortitionDB,
}

#[derive(Debug)]
pub enum Error {
    BurnchainBlockAlreadyProcessed,
    BurnchainError(BurnchainError),
    NonContiguousBurnchainBlock(BurnchainError),
    NoSortitions,
}

impl From<BurnchainError> for Error {
    fn from(o: BurnchainError) -> Error {
        Error::BurnchainError(o)
    }
}

impl ChainsCoordinator {

    pub fn new() -> ChainsCoordinator {
        
        let blocks_db = BlocksDB::stubbed();
        let burnchain_blocks_db = BurnchainDB::open("burnchain.db");
        let chain_state_db = ChainStateDB::stubbed();
        let pox_db = PoxDB::stubbed(); 
        let sortition_db = SortitionDB::stubbed();
            
        ChainsCoordinator {
            canonical_burnchain_chain_tip: None,
            canonical_chain_tip: None,
            canonical_pox_id: None,
            blocks_db,
            burnchain_blocks_db,
            chain_state_db,
            pox_db, 
            sortition_db
        }
    }

    pub fn handle_new_burnchain_block(&mut self) -> Result<(), Error> {
        // Retrieve canonical burnchain chain tip from the BurnchainBlocksDB
        let canonical_burnchain_tip = self.burnchain_blocks_db.get_canonical_chain_tip()?;

        // Early return: this block has already been processed
        if let Some(ref current) = self.canonical_burnchain_chain_tip {
            if current == canonical_burnchain_tip.block_hash {
                return Err(Error::BurnchainBlockAlreadyProcessed)
            }
        }

        // Retrieve canonical pox id (<=> reward cycle id)
        let pox_id = self.pox_db.get_canonical_pox_id(&canonical_burnchain_tip.block_hash);

        // Retrieve all the direct ancestors of this block with an unprocessed sortition 
        let mut cursor = (canonical_burnchain_tip.block_hash.clone(), pox_id);
        let mut sortitions_to_process = VecDeque::new();

        // We halt the ancestry research as soon as we find a processed parent
        while !(self.sortition_db.is_sortition_processed(&cursor.0, &cursor.1)?) {
            let current_block = self.burnchain_blocks_db.get_burnchain_block(&cursor.0)
                .map_err(|e| {
                    warn!("ChainsCoordinator: could not retrieve  block burnhash={} (PoxId={})", &cursor.0, &cursor.1);
                    Error::NonContiguousBurnchainBlock(e)
                })?;

            let parent = current_block.header.parent_block_hash.clone();
            let parent_pox_id = self.pox_db.get_canonical_pox_id(&parent);
            sortitions_to_process.push_front((current_block, cursor.1.clone()));
            cursor = (parent, parent_pox_id);
        }

        for (unprocessed_block, unprocessed_pox_id) in sortitions_to_process.drain(..) {
            let BurnchainBlockData { header, ops } = unprocessed_block;
            let sortition_id = self.sortition_db.evaluate_sortition(
                &header.block_hash, ops, &self.burnchain, &unprocessed_pox_id, &self.pox_db)
                .map_err(|e| {
                    error!("ChainsCoordinator: unable to evaluate sortition {:?}", e);
                    Error::FailedToProcessSortition(e)
                })?;

            if let Some(pox_anchor) = self.process_ready_blocks()? {
                return self.process_new_pox_anchor(pox_anchor)
            }
        }

        Ok(())
    }

    fn is_stacks_block_pox_anchor(&mut self, block: &StacksHeaderInfo) -> Option<StacksBlockId> {
        // PoX TODO -- anchor block selection and tracking
        return None;
    }

    ///
    /// Process any ready staging blocks until there are no more to process
    ///  _or_ a PoX anchor block is discovered.
    ///
    /// Returns Some(StacksBlockId) if an anchor block is discovered,
    ///   otherwise returns None
    fn process_ready_blocks(&mut self) -> Result<Option<StacksBlockId>, Error> {
        let mut processed_blocks = self.chain_state_db.process_blocks(&mut self.sortition_db, 1)?;
        while let Some(block_result) = processed_blocks.pop() {
            if let (Some(block_receipt), _) = block_result {
                // only bump the coordinator's state if the processed block
                //   is in our sortition fork
                //  TODO: we should update the staging block logic to prevent
                //    blocks like these from getting processed at all.
                if self.sortition_db.is_stacks_block_in_sortition_set(
                    &self.canonical_pox_id, &block_receipt.header.anchored_header.block_hash())? {

                    if let Some(pox_anchor) = self.is_stacks_block_pox_anchor(&block_receipt.header) {
                        return Some(pox_anchor);
                    }

                }

                // TODO: broadcast the events
            }
            // TODO: do something with a poison result
        }

        None
    }

    pub fn handle_new_block(&mut self) -> Result<(), Error> {
        // Rebuild sortition id
        let sortition_id = match (&self.canonical_pox_id, &self.canonical_burnchain_chain_tip) {
            (Some(pox_id), Some(burnchain_block)) => SortitionId::new(burnchain_block, pox_id),
            (_, _) => {
                // We received our first BlockDiscovered event before even receiving a BurnchainBlockDiscovered event
                return Err(Error::NoSortitions)
            }
        };

        if let Some(pox_anchor) = self.process_ready_blocks()? {
            return self.process_new_pox_anchor(pox_anchor)
        }

        Ok(())
    }

    fn process_new_pox_anchor(&mut self, block_id: &StacksBlockId) -> Result<(), Error> {
        // Ensure that the chain of anchored blocks (up to block_id) has been processed  
        let ordered_missing_anchored_blocks = self.pox_db.get_ordered_missing_anchors(block_id);
        for block_id in ordered_missing_anchored_blocks.iter() {
            match self.chain_state_db.is_block_processed(&block_id) {
                Ok(is_processed) => {
                    if is_processed {
                        PoxDB::process_anchor(&block_id, &self.chain_state_db)?;
                        let canonical_bhh = self.pox_db.get_reward_set_start_for(&block_id);
                        // Retrieve the corresponding block
                        self.canonical_burnchain_chain_tip = Some(canonical_bhh); 
                        self.canonical_pox_id = Some(self.pox_db.get_canonical_pox_id(&canonical_bhh));
                        self.canonical_chain_tip = None;
                        // Start processing from the beginning of the new PoX reward set
                        self.handle_new_burnchain_block()?;    
                    }
                    Ok(())
                },
                Err(e) => {
                    error!("ChainsCoordinator: unable to retrieve processed block {:?}", block_id);
                    Err(e)
                }
            }?;
        }
        self.discover_new_pox_anchor(block_id)
    }

    #[allow(unused_variables)]
    fn process_block(&self, block: &StacksBlock) -> Result<bool, Error> {
        unimplemented!()
    }

    fn discover_new_pox_anchor(&mut self, block_id: &StacksBlockId) -> Result<(), Error> {
        PoxDB::process_anchor(block_id, &self.chain_state_db)
    }
}

pub enum ChainsEvent {
    BlockDiscovered(Option<Sender<ChainsEventCallback>>),
    BurnchainBlockDiscovered(Option<Sender<ChainsEventCallback>>),
}

pub enum ChainsEventCallback {
    BlockProcessed,
    BurnchainBlockProcessed,
}
