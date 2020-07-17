use std::collections::VecDeque;
use std::thread;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Sender};
use std::process;

use burnchains::BurnchainHeaderHash;
use chainstate::burn::{BlockHeaderHash, BlockSnapshot};
use chainstate::stacks::{StacksBlock, TransactionPayload};
use chainstate::stacks::db::StacksHeaderInfo;
use chainstate::stacks::events::{StacksTransactionReceipt};

#[derive(Debug, Clone)]
struct PoxId;

#[derive(Debug, Clone)]
pub struct SortitionId (
    BurnchainHeaderHash,
    PoxId
);

#[derive(Debug, Clone)]
pub struct StacksBlockId {
    burnchain_header_hash: BurnchainHeaderHash,
    header_hash: BlockHeaderHash,
    pox_identifier: PoxId,
}

struct ChainStateDB;
impl ChainStateDB {

    pub fn stubbed() -> ChainStateDB {
        ChainStateDB {}
    }

    #[allow(unused_variables)]
    pub fn is_block_processed(&self, block_id: &StacksBlockId) -> Result<bool, ()> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    pub fn process_blocks(&mut self, burnchain_blocks_db: &mut BurnchainBlocksDB, pox_identifier: PoxId) -> Result<Vec<(Option<(StacksHeaderInfo, Vec<StacksTransactionReceipt>)>, Option<TransactionPayload>)>, ()> {
        unimplemented!()
    }
}

struct BurnchainBlocksDB;
impl BurnchainBlocksDB {

    pub fn stubbed() -> BurnchainBlocksDB {
        BurnchainBlocksDB {}
    }

    pub fn get_canonical_chain_tip(&self) -> BlockSnapshot {
        unimplemented!()
    }

    #[allow(unused_variables)]
    pub fn get_burnchain_block(&self, burnchain_header_hash: &BurnchainHeaderHash) -> Result<BlockSnapshot, ()> {
        unimplemented!()
    }
}

struct BlocksDB;
impl BlocksDB {

    pub fn stubbed() -> BlocksDB {
        BlocksDB {}
    }

    #[allow(unused_variables)]
    pub fn get_blocks_ready_to_process(&self, sortition_id: &SortitionId, sortition_db: &SortitionDB) -> Option<Vec<StacksBlock>> {
        // This method will be calling sortition_db::latest_stacks_blocks_processed
        unimplemented!()
    }
}

struct PoxDB;
impl PoxDB {

    pub fn stubbed() -> PoxDB {
        PoxDB {}
    }

    #[allow(unused_variables)]
    pub fn get_canonical_pox_id(&self, burnchain_header_hash: &BurnchainHeaderHash) -> PoxId {
        unimplemented!()
    }

    #[allow(unused_variables)]
    pub fn get_ordered_missing_anchors(&self, upper_bound: &StacksBlockId) -> Vec<StacksBlockId> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    // Note: we'd be temporary using an associated function instead of method, because this call is writing. 
    pub fn process_anchor(block: &StacksBlockId, chain_state: &ChainStateDB) -> Result<(), ()> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    pub fn get_reward_set_start_for(&self, block: &StacksBlockId) -> &BurnchainHeaderHash {
        unimplemented!()
    }
}

struct SortitionDB;
impl SortitionDB {

    pub fn stubbed() -> SortitionDB {
        SortitionDB {}
    }
  
    #[allow(unused_variables)]
    pub fn get_sortition_id(&self, burnchain_header_hash: &BurnchainHeaderHash, pox_id: &PoxId) -> Result<SortitionId, ()> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    pub fn is_sortition_processed(&self, burnchain_header_hash: &BurnchainHeaderHash, pox_id: &PoxId) -> Result<bool, ()> {
        unimplemented!()
    }
    
    #[allow(unused_variables)]
    pub fn evaluate_sortition(burnchain_block: &BlockSnapshot, pox_id: &PoxId, pox_db: &PoxDB) -> Result<SortitionId, ()> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    pub fn is_stacks_block_in_sortition_set(sortition_id: &SortitionId, block_to_check: &BlockHeaderHash) -> Result<bool, ()> {
        unimplemented!()
    }
 
    #[allow(unused_variables)]
    pub fn latest_stacks_blocks_processed(sortition_id: &SortitionId) -> Result<u64, ()> {
        unimplemented!()
    }
}

struct ChainsCoordinator {
    canonical_burnchain_chain_tip: Option<BlockSnapshot>,
    canonical_chain_tip: Option<StacksBlock>,
    canonical_pox_id: Option<PoxId>,
    blocks_db: BlocksDB,
    burnchain_blocks_db: BurnchainBlocksDB,
    chain_state_db: ChainStateDB,
    pox_db: PoxDB, 
    sortition_db: SortitionDB,
}

impl ChainsCoordinator {

    pub fn new() -> ChainsCoordinator {
        
        let blocks_db = BlocksDB::stubbed();
        let burnchain_blocks_db = BurnchainBlocksDB::stubbed();
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

    pub fn handle_new_burnchain_block(&mut self) -> Result<(), ()> {
        // Retrieve canonical burnchain chain tip from the BurnchainBlocksDB
        let canonical_burnchain_tip = self.burnchain_blocks_db.get_canonical_chain_tip();
        
        // Early return: this block has already been processed
        match self.canonical_burnchain_chain_tip {
            Some(ref current) if current.burn_header_hash == canonical_burnchain_tip.burn_header_hash => Err(()),
            _ => Ok(())
        }?;

        // Retrieve canonical pox id (<=> reward cycle id)
        let pox_id = self.pox_db.get_canonical_pox_id(&canonical_burnchain_tip.burn_header_hash);

        // Retrieve all the direct ancestors of this block with an unprocessed sortition 
        let mut cursor = canonical_burnchain_tip.burn_header_hash.clone();
        let mut sortitions_to_process = VecDeque::new();

        while match self.sortition_db.is_sortition_processed(&cursor, &pox_id) {
            Ok(ref is_processed)  => !is_processed, // We halt the ancestry research as soon as we find a processed parent
            _ => false
        } {
            if let Ok(block) = self.burnchain_blocks_db.get_burnchain_block(&cursor) {
                let parent = block.parent_burn_header_hash.clone();
                sortitions_to_process.push_front(block);
                cursor = parent;
            } else {
                info!("ChainsCoordinator: could not retrieve block {}", cursor);
                break;
            }
        }

        for unprocessed_block in sortitions_to_process.drain(..) {
            let sortition_id = match SortitionDB::evaluate_sortition(&unprocessed_block, &pox_id, &self.pox_db) {
                Ok(sortition_id) => sortition_id,
                Err(e) => {
                    error!("ChainsCoordinator: unable to retrieve sortition {:?}", e);
                    break
                }
            };

            while let Some(blocks_ready_to_process) = self.blocks_db.get_blocks_ready_to_process(&sortition_id, &self.sortition_db) {
                for block in blocks_ready_to_process {
                    match self.process_block(&block) {
                        Ok(is_pox_anchor) => {
                            if is_pox_anchor == true {
                                // todo: can call this method when the BlockSnapshot struct is augmented with block_id field
                                // self.process_new_pox_anchor(block.block_id)?;
                            }
                            Ok(())
                        }
                        Err(err) => Err(err)
                    }?;
                }
            }
        }

        Ok(())
    }

    pub fn handle_new_block(&mut self) -> Result<(), ()> {
        // Rebuild sortition id
        let sortition_id = match (&self.canonical_pox_id, &self.canonical_burnchain_chain_tip) {
            (Some(pox_id), Some(burnchain_block)) => SortitionId(burnchain_block.burn_header_hash.clone(), pox_id.clone()),
            (_, _) => {
                // We received our first BlockDiscovered event before even receiving a BurnchainBlockDiscovered event
                return Err(())
            }
        };

        while let Some(blocks_ready_to_process) = self.blocks_db.get_blocks_ready_to_process(&sortition_id, &self.sortition_db) {
            for block in blocks_ready_to_process {
                match self.process_block(&block) {
                    Ok(is_pox_anchor) => {
                        if is_pox_anchor == true {
                            // todo: can call this method when the BlockSnapshot struct is augmented with block_id field
                            // self.process_new_pox_anchor(block.block_id)?;
                        }
                        Ok(())
                    }
                    Err(err) => Err(err)
                }?;
                self.canonical_chain_tip = Some(block);
            }
        }

        Ok(())
    }

    fn process_new_pox_anchor(&mut self, block_id: &StacksBlockId) -> Result<(), ()> {
        // Ensure that the chain of anchored blocks (up to block_id) has been processed  
        let ordered_missing_anchored_blocks = self.pox_db.get_ordered_missing_anchors(block_id);
        for block_id in ordered_missing_anchored_blocks.iter() {
            match self.chain_state_db.is_block_processed(&block_id) {
                Ok(is_processed) => {
                    if is_processed {
                        PoxDB::process_anchor(&block_id, &self.chain_state_db)?;
                        let canonical_bhh = self.pox_db.get_reward_set_start_for(&block_id);
                        // Retrieve the corresponding block
                        let canonical_block = self.burnchain_blocks_db.get_burnchain_block(canonical_bhh)?;
                        self.canonical_burnchain_chain_tip = Some(canonical_block); 
                        self.canonical_pox_id = Some(self.pox_db.get_canonical_pox_id(&block_id.burnchain_header_hash));
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
    fn process_block(&self, block: &StacksBlock) -> Result<bool, ()> {
        unimplemented!()
    }

    fn discover_new_pox_anchor(&mut self, block_id: &StacksBlockId) -> Result<(), ()> {
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
