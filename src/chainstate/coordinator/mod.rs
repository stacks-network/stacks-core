use std::thread;
use std::sync::{mpsc, Arc, Mutex};
use std::process;

use burnchains::BurnchainHeaderHash;
use chainstate::burn::{BlockHeaderHash, BlockSnapshot as BurnchainBlock};
use chainstate::stacks::StacksBlock;

#[derive(Debug, Clone)]
struct PoxIdentifier;

#[derive(Debug, Clone)]
pub struct SortitionIdentifier (
    BurnchainHeaderHash,
    PoxIdentifier
);

#[derive(Debug, Clone)]
pub struct StacksBlockIdentifier {
    burnchain_header_hash: BurnchainHeaderHash,
    header_hash: BlockHeaderHash,
    pox_identifier: PoxIdentifier,
}

struct ChainStateDB;
impl ChainStateDB {

    pub fn stubbed() -> ChainStateDB {
        ChainStateDB {}
    }

    pub fn is_block_processed(&self, block_id: &StacksBlockIdentifier) -> Result<bool, ()> {
        unimplemented!()
    }
}

struct BurnchainDB;
impl BurnchainDB {

    pub fn stubbed() -> BurnchainDB {
        BurnchainDB {}
    }

    pub fn get_canonical_chain_tip(&self) -> BurnchainBlock {
        unimplemented!()
    }

    pub fn get_burnchain_block(&self, burnchain_header_hash: &BurnchainHeaderHash) -> Result<BurnchainBlock, ()> {
        unimplemented!()
    }
}

struct BlocksDB;
impl BlocksDB {

    pub fn stubbed() -> BlocksDB {
        BlocksDB {}
    }

    pub fn get_blocks_ready_to_process(&self, sortition_id: &SortitionIdentifier, sortition_db: &SortitionDB) -> Option<Vec<StacksBlock>> {
        unimplemented!()
    }
}

struct PoxDB;
impl PoxDB {

    pub fn stubbed() -> PoxDB {
        PoxDB {}
    }

    pub fn get_canonical_pox_id(&self, burnchain_header_hash: &BurnchainHeaderHash) -> PoxIdentifier {
        unimplemented!()
    }

    pub fn get_ordered_missing_anchors(&self) -> Vec<StacksBlockIdentifier> {
        unimplemented!()
    }

    pub fn process_anchor(block: &StacksBlockIdentifier, chain_state: &ChainStateDB) -> Result<(), ()> {
        unimplemented!()
    }

    pub fn get_reward_set_start_for(&self, block: &StacksBlockIdentifier) -> u64 {
        unimplemented!()
    }
}

struct SortitionDB;
impl SortitionDB {

    pub fn stubbed() -> SortitionDB {
        SortitionDB {}
    }
  
    pub fn get_sortition_id(&self, burnchain_header_hash: &BurnchainHeaderHash, pox_id: &PoxIdentifier) -> Result<SortitionIdentifier, ()> {
        unimplemented!()
    }

    pub fn is_sortition_processed(&self, burnchain_header_hash: &BurnchainHeaderHash, pox_id: &PoxIdentifier) -> Result<bool, ()> {
        unimplemented!()
    }
    
    pub fn evaluate_sortition(burnchain_block: &BurnchainBlock, pox_id: &PoxIdentifier, pox_db: &PoxDB) -> Result<SortitionIdentifier, ()> {
        unimplemented!()
    }

    pub fn is_stacks_block_in_sortition_set(sortition_id: &SortitionIdentifier, block_to_check: &BlockHeaderHash) -> Result<bool, ()> {
        unimplemented!()
    }
 
    pub fn latest_stacks_blocks_processed(sortition_id: &SortitionIdentifier) -> Result<u64, ()> {
        unimplemented!()
    }
}

struct ChainsCoordinator {
    canonical_burnchain_chain_tip: Option<BurnchainBlock>,
    canonical_chain_tip: Option<StacksBlock>,
    canonical_pox_id: Option<PoxIdentifier>,
    blocks_db: BlocksDB,
    burnchain_db: BurnchainDB,
    chain_state_db: ChainStateDB,
    pox_db: PoxDB, 
    sortition_db: SortitionDB,
}

impl ChainsCoordinator {

    pub fn new() -> ChainsCoordinator {
        
        let blocks_db = BlocksDB::stubbed();
        let burnchain_db = BurnchainDB::stubbed();
        let chain_state_db = ChainStateDB::stubbed();
        let pox_db = PoxDB::stubbed(); 
        let sortition_db = SortitionDB::stubbed();
            
        ChainsCoordinator {
            canonical_burnchain_chain_tip: None,
            canonical_chain_tip: None,
            canonical_pox_id: None,
            blocks_db,
            burnchain_db,
            chain_state_db,
            pox_db, 
            sortition_db
        }
    }

    pub fn handle_new_burnchain_block(&mut self) {
        // Retrieve canonical burnchain chain tip from the BurnchainDB
        let canonical_burnchain_tip = self.burnchain_db.get_canonical_chain_tip();
        
        // Early return: this block has already been processed
        match self.canonical_burnchain_chain_tip {
            Some(ref current) if current.burn_header_hash == canonical_burnchain_tip.burn_header_hash => return,
            _ => {}
        }

        // Retrieve canonical pox id (<=> reward cycle id)
        let pox_id = self.pox_db.get_canonical_pox_id(&canonical_burnchain_tip.burn_header_hash);

        // Retrieve all the direct ancestors of this block with an unprocessed sortition 
        let mut parent_bhh = canonical_burnchain_tip.burn_header_hash.clone();
        let mut sortitions_to_process = vec![canonical_burnchain_tip];

        while match self.sortition_db.is_sortition_processed(&parent_bhh, &pox_id) {
            Ok(ref is_processed)  => !is_processed,
            _ => false
        } {
            if let Ok(block) = self.burnchain_db.get_burnchain_block(&parent_bhh) {
                parent_bhh = block.parent_burn_header_hash.clone();
                sortitions_to_process.push(block);
            } else {
                break;
            }
        }

        for unprocessed_block in sortitions_to_process.drain(..) {
            let sortition_id = match SortitionDB::evaluate_sortition(&unprocessed_block, &pox_id, &self.pox_db) {
                Ok(sortition_id) => sortition_id,
                Err(e) => {
                    error!("ChainsCoordinator: unable to retrieve sortition");
                    continue
                }
            };

            while let Some(blocks_ready_to_process) = self.blocks_db.get_blocks_ready_to_process(&sortition_id, &self.sortition_db) {
                // todo(ludo): I think I'm supposed to use `SortitionDB::latest_stacks_blocks_processed`
                for block in blocks_ready_to_process {
                    match self.process_block(&block) {
                        Some(is_pox_anchor) if is_pox_anchor == true => {
                            self.process_new_pox_anchor();
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    pub fn handle_new_block(&mut self) {
        // Rebuild sortition id
        let sortition_id = match (&self.canonical_pox_id, &self.canonical_burnchain_chain_tip) {
            (Some(pox_id), Some(burnchain_block)) => SortitionIdentifier(burnchain_block.burn_header_hash.clone(), pox_id.clone()),
            (_, _) => {
                // todo(ludo): handle this case
                return;
            }
        };

        while let Some(blocks_ready_to_process) = self.blocks_db.get_blocks_ready_to_process(&sortition_id, &self.sortition_db) {
            // todo(ludo): I think I'm supposed to use `SortitionDB::latest_stacks_blocks_processed`
            for block in blocks_ready_to_process {
                match self.process_block(&block) {
                    Some(is_pox_anchor) if is_pox_anchor == true => {
                        self.process_new_pox_anchor();
                    }
                    _ => {}
                }
                self.canonical_chain_tip = Some(block);
            }
        }
    }

    fn process_new_pox_anchor(&mut self) {
        let ordered_missing_anchored_blocks = self.pox_db.get_ordered_missing_anchors();
        for block_id in ordered_missing_anchored_blocks.iter() {
            match self.chain_state_db.is_block_processed(&block_id) {
                Ok(is_processed) if is_processed == true => {
                    PoxDB::process_anchor(&block_id, &self.chain_state_db);
                    // self.canonical_burn_header = self.pox_db.get_reward_set_start_for(&block_id);
                    // todo(ludo): adapt the following lines.
                    // self.canon_burn_header = self.pox_db.get_reward_set_start_for(block) 
                    // todo(ludo): block_id is a construct based on the pox_id, why do we need to fetch it from the DB?
                    self.canonical_pox_id = Some(self.pox_db.get_canonical_pox_id(&block_id.burnchain_header_hash));
                    self.canonical_chain_tip = None;
                    // start processing from the beginning of the new PoX reward set
                    return self.handle_new_burnchain_block()    
                },
                _ => {}
            }
        }
        self.discover_new_pox_anchor();
    }

    fn process_block(&self, block: &StacksBlock) -> Option<bool> {
        unimplemented!()
    }

    fn discover_new_pox_anchor(&mut self) {
        unimplemented!()
    }
}

pub enum ChainsEvent {
    BlockDiscovered,
    BurnchainBlockDiscovered,
}

pub struct ChainsEventsObserver {
    event_tx: Option<mpsc::Sender<ChainsEvent>>,
}

impl ChainsEventsObserver {

    pub fn new() -> ChainsEventsObserver {
        ChainsEventsObserver {
            event_tx: None
        }
    }

    pub fn spawn_chains_coordinator(&mut self) -> mpsc::Sender<ChainsEvent> {
        if let Some(ref event_tx) = self.event_tx {
            error!("ChainsCoordinator is already processing chains events");
            return event_tx.clone();
        }

        let (event_tx, event_rx) = mpsc::channel();
        self.event_tx = Some(event_tx.clone());

        thread::spawn(move || {
            let mut chains_coordinator = ChainsCoordinator::new();
            loop {
                if let Ok(event) = event_rx.recv() {
                    match event {
                        ChainsEvent::BlockDiscovered => chains_coordinator.handle_new_block(),
                        ChainsEvent::BurnchainBlockDiscovered => chains_coordinator.handle_new_burnchain_block(),
                    }                
                } else {
                    error!("ChainsEventsObserver stopped receiving events");
                    break;
                }
            }
        });
        event_tx
    }
}

fn main() {
    let mut chains_events_observer = ChainsEventsObserver::new();
    let chains_event_tx = chains_events_observer.spawn_chains_coordinator();

    // We can now, from any thread, notify the coordinator to update the different DBs, with the following events, 
    // and be sure that the processing of these events will happen sequentially on the same thread.
    chains_event_tx
        .send(ChainsEvent::BlockDiscovered)
        .expect("Unable to transmit ChainsEvent::BlockDiscovered");
    chains_event_tx
        .send(ChainsEvent::BurnchainBlockDiscovered)
        .expect("Unable to transmit ChainsEvent::BurnchainBlockDiscovered");;
}
