use std::cmp;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use stacks::burnchains::db::BurnchainDB;
use stacks::burnchains::events::NewBlock;
use stacks::burnchains::indexer::{
    BurnBlockIPC, BurnchainBlockDownloader, BurnchainBlockParser, BurnchainIndexer,
};
use stacks::burnchains::{Burnchain, BurnchainBlock, Error as BurnchainError, StacksHyperBlock};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::BlockstackOperationType;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::chainstate::stacks::index::ClarityMarfTrieId;
use stacks::core::StacksEpoch;
use stacks::types::chainstate::{BurnchainHeaderHash, StacksBlockId};
use stacks::util::hash::hex_bytes;
use stacks::util::sleep_ms;
use stacks::vm::types::QualifiedContractIdentifier;

use super::mock_events::BlockIPC;
use super::{BurnchainChannel, Error};
use crate::burnchains::mock_events::MockHeader;
use crate::operations::BurnchainOpSigner;
use crate::{BurnchainController, BurnchainTip, Config};

#[derive(Clone)]
pub struct L1Channel {
    blocks: Arc<Mutex<Vec<NewBlock>>>,
    minimum_recorded_height: Arc<Mutex<u64>>,
}

pub struct L1Controller {
    burnchain: Option<Burnchain>,
    config: Config,
    indexer: L1Indexer,

    db: Option<SortitionDB>,
    burnchain_db: Option<BurnchainDB>,

    should_keep_running: Option<Arc<AtomicBool>>,

    coordinator: CoordinatorChannels,
    chain_tip: Option<BurnchainTip>,
}

pub struct L1Indexer {
    /// This is the channel that new mocked L1 blocks are fed into
    incoming_channel: Arc<L1Channel>,
    /// This is the Layer 1 contract that is watched for hyperchain events.
    watch_contract: QualifiedContractIdentifier,
    blocks: Vec<NewBlock>,
    /// The lowest height that the indexer is holding. Defaults to 0,
    /// but after garbage collection, can increase.
    minimum_recorded_height: u64,
}

pub struct L1BlockDownloader {
    channel: Arc<L1Channel>,
}

impl L1Channel {
    /// Creates a channel with a single block with hash from `make_mock_byte_string`.
    pub fn single_block() -> L1Channel {
        L1Channel {
            blocks: Arc::new(Mutex::new(vec![NewBlock {
                block_height: 0,
                burn_block_time: 0,
                index_block_hash: StacksBlockId(make_mock_byte_string_for_first_l1_block()),
                parent_index_block_hash: StacksBlockId::sentinel(),
                events: vec![],
            }])),
            minimum_recorded_height: Arc::new(Mutex::new(0)),
        }
    }
}
lazy_static! {
    pub static ref STATIC_EVENTS_STREAM: Arc<L1Channel> = Arc::new(L1Channel::single_block());
    static ref NEXT_BURN_BLOCK: Arc<Mutex<u64>> = Arc::new(Mutex::new(1));
}

/// This outputs a hard-coded value for the hash of the first block created by the
/// Stacks L1 chain. For some reason, this seems stable.
fn make_mock_byte_string_for_first_l1_block() -> [u8; 32] {
    let mut bytes_1 = [0u8; 32];
    let bytes_vec = hex_bytes("55c9861be5cff984a20ce6d99d4aa65941412889bdc665094136429b84f8c2ee")
        .expect("hex value problem");
    bytes_1.copy_from_slice(&bytes_vec[0..32]);
    bytes_1
}

impl BurnchainChannel for L1Channel {
    fn push_block(&self, new_block: NewBlock) {
        let mut blocks = self.blocks.lock().unwrap();
        blocks.push(new_block)
    }

    fn get_block(&self, fetch_height: u64) -> Option<NewBlock> {
        let minimum_recorded_height = self.minimum_recorded_height.lock().unwrap();
        let blocks = self.blocks.lock().unwrap();

        let fetch_index = if fetch_height < *minimum_recorded_height {
            return None;
        } else {
            (fetch_height - *minimum_recorded_height) as usize
        };
        if fetch_index >= blocks.len() {
            return None;
        }

        let block = blocks[fetch_index].clone();
        Some(block)
    }

    fn fill_blocks(
        &self,
        into: &mut Vec<NewBlock>,
        start_block: u64,
        end_block: Option<u64>,
    ) -> Result<(), BurnchainError> {
        let minimum_recorded_height = self.minimum_recorded_height.lock().unwrap();
        let blocks = self.blocks.lock().unwrap();

        if start_block < *minimum_recorded_height {
            return Err(BurnchainError::DownloadError(
                "Start block before downloader has mocked data".into(),
            ));
        }
        let start_index = (start_block - *minimum_recorded_height) as usize;
        if let Some(end_block) = end_block {
            let end_index = std::cmp::min(
                (1 + end_block - *minimum_recorded_height) as usize,
                blocks.len(),
            );
            into.extend_from_slice(&blocks[start_index..end_index]);
        } else {
            into.extend_from_slice(&blocks[start_index..]);
        }
        Ok(())
    }

    fn highest_block(&self) -> u64 {
        let minimum_recorded_height = self.minimum_recorded_height.lock().unwrap();
        let blocks = self.blocks.lock().unwrap();

        *minimum_recorded_height + (blocks.len() as u64) - 1
    }
}

impl L1BlockDownloader {
    fn fill_blocks(
        &self,
        into: &mut Vec<NewBlock>,
        start_block: u64,
        end_block: Option<u64>,
    ) -> Result<(), BurnchainError> {
        self.channel.fill_blocks(into, start_block, end_block)
    }
}

impl L1Controller {
    pub fn new(config: Config, coordinator: CoordinatorChannels) -> L1Controller {
        let contract_identifier = config.burnchain.contract_identifier.clone();
        let indexer = L1Indexer::new(contract_identifier.clone());
        L1Controller {
            burnchain: None,
            config,
            indexer,
            db: None,
            burnchain_db: None,
            should_keep_running: Some(Arc::new(AtomicBool::new(true))),
            coordinator,
            chain_tip: None,
        }
    }

    fn receive_blocks(
        &mut self,
        block_for_sortitions: bool,
        target_block_height_opt: Option<u64>,
    ) -> Result<(BurnchainTip, u64), Error> {
        let coordinator_comms = self.coordinator.clone();
        let mut burnchain = self.get_burnchain();

        let (block_snapshot, burnchain_height) = loop {
            match burnchain.sync_with_indexer(
                &mut self.indexer,
                coordinator_comms.clone(),
                target_block_height_opt,
                None,
                self.should_keep_running.clone(),
            ) {
                Ok(x) => {
                    // initialize the dbs...
                    self.sortdb_mut();

                    // wait for the chains coordinator to catch up with us
                    if block_for_sortitions {
                        self.wait_for_sortitions(Some(x.block_height))?;
                    }

                    // NOTE: This is the latest _sortition_ on the canonical sortition history, not the latest burnchain block!
                    let sort_tip =
                        SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn())
                            .expect("Sortition DB error.");

                    let snapshot = self
                        .sortdb_ref()
                        .get_sortition_result(&sort_tip.sortition_id)
                        .expect("Sortition DB error.")
                        .expect("BUG: no data for the canonical chain tip");

                    let burnchain_height = self
                        .indexer
                        .get_highest_header_height()
                        .map_err(Error::IndexerError)?;
                    break (snapshot, burnchain_height);
                }
                Err(e) => {
                    // keep trying
                    error!("Unable to sync with burnchain: {}", e);
                    match e {
                        BurnchainError::CoordinatorClosed => return Err(Error::CoordinatorClosed),
                        BurnchainError::TrySyncAgain => {
                            // try again immediately
                            continue;
                        }
                        BurnchainError::BurnchainPeerBroken => {
                            // remote burnchain peer broke, and produced a shorter blockchain fork.
                            // just keep trying
                            sleep_ms(5000);
                            continue;
                        }
                        _ => {
                            // delay and try again
                            sleep_ms(5000);
                            continue;
                        }
                    }
                }
            }
        };

        let burnchain_tip = BurnchainTip {
            block_snapshot,
            received_at: Instant::now(),
        };

        self.chain_tip = Some(burnchain_tip.clone());
        debug!("Done receiving blocks");

        Ok((burnchain_tip, burnchain_height))
    }

    fn should_keep_running(&self) -> bool {
        match self.should_keep_running {
            Some(ref should_keep_running) => should_keep_running.load(Ordering::SeqCst),
            _ => true,
        }
    }
}

impl BurnchainController for L1Controller {
    fn start(
        &mut self,
        target_block_height_opt: Option<u64>,
    ) -> Result<(BurnchainTip, u64), Error> {
        self.receive_blocks(
            false,
            target_block_height_opt.map_or_else(|| Some(1), |x| Some(x)),
        )
    }
    fn get_channel(&self) -> Arc<dyn BurnchainChannel> {
        STATIC_EVENTS_STREAM.clone()
    }
    fn submit_operation(
        &mut self,
        _operation: BlockstackOperationType,
        _op_signer: &mut BurnchainOpSigner,
        _attempt: u64,
    ) -> bool {
        // todo(issue #29)
        false
    }

    fn sync(&mut self, target_block_height_opt: Option<u64>) -> Result<(BurnchainTip, u64), Error> {
        self.receive_blocks(true, target_block_height_opt)
    }

    fn get_chain_tip(&self) -> BurnchainTip {
        self.chain_tip.as_ref().unwrap().clone()
    }

    fn get_headers_height(&self) -> u64 {
        self.indexer.get_headers_height().unwrap()
    }

    fn sortdb_ref(&self) -> &SortitionDB {
        self.db
            .as_ref()
            .expect("BUG: did not instantiate the burn DB")
    }

    fn sortdb_mut(&mut self) -> &mut SortitionDB {
        let burnchain = self.get_burnchain();

        let (db, burnchain_db) = burnchain.open_db(true).unwrap();
        self.db = Some(db);
        self.burnchain_db = Some(burnchain_db);

        match self.db {
            Some(ref mut sortdb) => sortdb,
            None => unreachable!(),
        }
    }

    fn connect_dbs(&mut self) -> Result<(), Error> {
        let burnchain = self.get_burnchain();
        burnchain.connect_db(
            &self.indexer,
            true,
            self.indexer.get_first_block_header_hash()?,
            self.indexer.get_first_block_header_timestamp()?,
        )?;
        Ok(())
    }

    fn get_stacks_epochs(&self) -> Vec<StacksEpoch> {
        self.indexer.get_stacks_epochs()
    }

    fn get_burnchain(&self) -> Burnchain {
        match &self.burnchain {
            Some(burnchain) => burnchain.clone(),
            None => {
                let working_dir = self.config.get_burn_db_path();
                Burnchain::new(&working_dir, "mockstack", "hyperchain").unwrap_or_else(|e| {
                    error!("Failed to instantiate burnchain: {}", e);
                    panic!()
                })
            }
        }
    }

    fn wait_for_sortitions(&mut self, height_to_wait: Option<u64>) -> Result<BurnchainTip, Error> {
        loop {
            let canonical_burnchain_tip = self
                .burnchain_db
                .as_ref()
                .expect("BurnchainDB not opened")
                .get_canonical_chain_tip()
                .unwrap();
            let canonical_sortition_tip =
                SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn()).unwrap();
            if canonical_burnchain_tip.block_height == canonical_sortition_tip.block_height {
                let _ = self
                    .sortdb_ref()
                    .get_sortition_result(&canonical_sortition_tip.sortition_id)
                    .expect("Sortition DB error.")
                    .expect("BUG: no data for the canonical chain tip");
                return Ok(BurnchainTip {
                    block_snapshot: canonical_sortition_tip,
                    received_at: Instant::now(),
                });
            } else if let Some(height_to_wait) = height_to_wait {
                if canonical_sortition_tip.block_height >= height_to_wait {
                    let _ = self
                        .sortdb_ref()
                        .get_sortition_result(&canonical_sortition_tip.sortition_id)
                        .expect("Sortition DB error.")
                        .expect("BUG: no data for the canonical chain tip");

                    return Ok(BurnchainTip {
                        block_snapshot: canonical_sortition_tip,
                        received_at: Instant::now(),
                    });
                }
            }
            if !self.should_keep_running() {
                return Err(Error::CoordinatorClosed);
            }
            // yield some time
            sleep_ms(100);
        }
    }

    #[cfg(test)]
    fn bootstrap_chain(&mut self, blocks_count: u64) {
        todo!()
    }
}

pub struct L1Parser {
    watch_contract: QualifiedContractIdentifier,
}

impl BurnchainBlockDownloader for L1BlockDownloader {
    type B = BlockIPC;

    fn download(&mut self, header: &MockHeader) -> Result<BlockIPC, BurnchainError> {
        let block = self.channel.get_block(header.height).ok_or_else(|| {
            warn!("Failed to mock download height = {}", header.height);
            BurnchainError::BurnchainPeerBroken
        })?;

        Ok(BlockIPC(block))
    }
}

impl BurnchainBlockParser for L1Parser {
    type B = BlockIPC;

    fn parse(&mut self, block: &BlockIPC) -> Result<BurnchainBlock, BurnchainError> {
        Ok(BurnchainBlock::StacksHyperBlock(
            StacksHyperBlock::from_new_block_event(&self.watch_contract, block.block()),
        ))
    }
}

impl L1Indexer {
    pub fn new(watch_contract: QualifiedContractIdentifier) -> L1Indexer {
        L1Indexer {
            incoming_channel: STATIC_EVENTS_STREAM.clone(),
            watch_contract,
            blocks: vec![],
            minimum_recorded_height: 0,
        }
    }
}

impl BurnchainIndexer for L1Indexer {
    type P = L1Parser;
    type B = BlockIPC;
    type D = L1BlockDownloader;

    fn connect(&mut self) -> Result<(), BurnchainError> {
        Ok(())
    }

    fn get_first_block_height(&self) -> u64 {
        0
    }

    fn get_first_block_header_hash(&self) -> Result<BurnchainHeaderHash, BurnchainError> {
        Ok(BurnchainHeaderHash(
            make_mock_byte_string_for_first_l1_block(),
        ))
    }

    fn get_first_block_header_timestamp(&self) -> Result<u64, BurnchainError> {
        Ok(0)
    }

    fn get_stacks_epochs(&self) -> Vec<StacksEpoch> {
        stacks::core::STACKS_EPOCHS_REGTEST.to_vec()
    }

    fn get_headers_path(&self) -> String {
        "".into()
    }

    fn get_headers_height(&self) -> Result<u64, BurnchainError> {
        if self.blocks.len() == 0 {
            Err(BurnchainError::MissingHeaders)
        } else {
            Ok(self.minimum_recorded_height + (self.blocks.len() as u64) - 1)
        }
    }

    fn get_highest_header_height(&self) -> Result<u64, BurnchainError> {
        Ok(self.incoming_channel.highest_block())
    }

    fn find_chain_reorg(&mut self) -> Result<u64, BurnchainError> {
        // No reorgs in the current version of the mock event stream
        self.get_headers_height()
    }

    fn sync_headers(
        &mut self,
        start_height: u64,
        end_height: Option<u64>,
    ) -> Result<u64, BurnchainError> {
        if let Some(end_height) = end_height.as_ref() {
            if end_height <= &start_height {
                return Ok(*end_height);
            }
        }

        let d = self.downloader();
        let start_fill = match self.get_headers_height() {
            Ok(height) => height + 1,
            Err(_) => 0,
        };
        d.fill_blocks(&mut self.blocks, start_fill, end_height)?;

        self.get_headers_height()
    }

    fn drop_headers(&mut self, new_height: u64) -> Result<(), BurnchainError> {
        if new_height < self.minimum_recorded_height {
            return Err(BurnchainError::BurnchainPeerBroken);
        }

        let drop_index = new_height - self.minimum_recorded_height;
        self.blocks.truncate(drop_index as usize);
        Ok(())
    }

    fn read_headers(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<Vec<MockHeader>, BurnchainError> {
        if start_block < self.minimum_recorded_height {
            return Err(BurnchainError::MissingHeaders);
        }
        if end_block < start_block {
            return Err(BurnchainError::BurnchainPeerBroken);
        }
        let start_index = (start_block - self.minimum_recorded_height) as usize;
        let end_index = cmp::min(
            self.blocks.len(),
            (end_block - self.minimum_recorded_height) as usize,
        );
        let headers = self.blocks[start_index..end_index]
            .iter()
            .map(|b| MockHeader::from(b))
            .collect();
        Ok(headers)
    }

    fn downloader(&self) -> L1BlockDownloader {
        L1BlockDownloader {
            channel: self.incoming_channel.clone(),
        }
    }

    fn parser(&self) -> L1Parser {
        L1Parser {
            watch_contract: self.watch_contract.clone(),
        }
    }
}
