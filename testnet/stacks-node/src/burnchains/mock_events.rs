use std::cmp;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use stacks::burnchains::db::BurnchainDB;
use stacks::burnchains::events::{ContractEvent, NewBlockTxEvent};
use stacks::burnchains::events::{NewBlock, TxEventType};
use stacks::burnchains::indexer::{
    BurnBlockIPC, BurnHeaderIPC, BurnchainBlockDownloader, BurnchainBlockParser, BurnchainIndexer,
};
use stacks::burnchains::{
    Burnchain, BurnchainBlock, Error as BurnchainError, StacksHyperBlock, Txid,
};

use stacks::burnchains;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::{BlockstackOperationType, LeaderBlockCommitOp};
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::chainstate::stacks::index::ClarityMarfTrieId;
use stacks::core::StacksEpoch;
use stacks::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksBlockId};
use stacks::util::sleep_ms;
use stacks::vm::types::{QualifiedContractIdentifier, TupleData};
use stacks::vm::Value as ClarityValue;

use crate::operations::BurnchainOpSigner;
use crate::{BurnchainController, BurnchainTip, Config};

use super::{BurnchainChannel, Error};

#[derive(Clone)]
pub struct MockChannel {
    blocks: Arc<Mutex<Vec<NewBlock>>>,
    minimum_recorded_height: Arc<Mutex<u64>>,
}

pub struct MockController {
    /// This is the simulated contract identifier
    contract_identifier: QualifiedContractIdentifier,
    burnchain: Option<Burnchain>,
    config: Config,
    indexer: MockIndexer,

    db: Option<SortitionDB>,
    burnchain_db: Option<BurnchainDB>,

    should_keep_running: Option<Arc<AtomicBool>>,

    coordinator: CoordinatorChannels,
    chain_tip: Option<BurnchainTip>,

    /// This will be a unique number for the next burn block. Starts at 1
    next_burn_block: Arc<Mutex<u64>>,
    next_commit: Arc<Mutex<Option<BlockHeaderHash>>>,
}

pub struct MockIndexer {
    /// This is the channel that new mocked L1 blocks are fed into
    incoming_channel: Arc<MockChannel>,
    /// This is the Layer 1 contract that is watched for hyperchain events.
    watch_contract: QualifiedContractIdentifier,
    blocks: Vec<NewBlock>,
    /// The lowest height that the indexer is holding. Defaults to 0,
    /// but after garbage collection, can increase.
    minimum_recorded_height: u64,
}

pub struct MockBlockDownloader {
    channel: Arc<MockChannel>,
}

lazy_static! {
    static ref MOCK_EVENTS_STREAM: Arc<MockChannel> = Arc::new(MockChannel {
        blocks: Arc::new(Mutex::new(vec![NewBlock {
            block_height: 0,
            burn_block_time: 0,
            index_block_hash: StacksBlockId(make_mock_byte_string(0)),
            parent_index_block_hash: StacksBlockId::sentinel(),
            events: vec![],
        }])),
        minimum_recorded_height: Arc::new(Mutex::new(0)),
    });
    static ref NEXT_BURN_BLOCK: Arc<Mutex<u64>> = Arc::new(Mutex::new(1));
    static ref NEXT_COMMIT: Arc<Mutex<Option<BlockHeaderHash>>> = Arc::new(Mutex::new(None));
}

fn make_mock_byte_string(from: u64) -> [u8; 32] {
    let mut output = [1; 32];
    output[0..8].copy_from_slice(&from.to_be_bytes());
    output
}

impl BurnchainChannel for MockChannel {
    fn push_block(&self, new_block: NewBlock) -> Result<(), stacks::burnchains::Error> {
        let mut blocks = self.blocks.lock().unwrap();
        blocks.push(new_block);
        Ok(())
    }
}

impl MockChannel {
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
    ) -> Result<(), burnchains::Error> {
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

impl MockBlockDownloader {
    fn fill_blocks(
        &self,
        into: &mut Vec<NewBlock>,
        start_block: u64,
        end_block: Option<u64>,
    ) -> Result<(), BurnchainError> {
        self.channel.fill_blocks(into, start_block, end_block)
    }
}

impl MockController {
    pub fn new(config: Config, coordinator: CoordinatorChannels) -> MockController {
        let contract_identifier = config.burnchain.contract_identifier.clone();
        let indexer = MockIndexer::new(contract_identifier.clone());
        MockController {
            contract_identifier,
            burnchain: None,
            config,
            indexer,
            db: None,
            burnchain_db: None,
            should_keep_running: Some(Arc::new(AtomicBool::new(true))),
            coordinator,
            chain_tip: None,
            next_burn_block: NEXT_BURN_BLOCK.clone(),
            next_commit: NEXT_COMMIT.clone(),
        }
    }

    /// Produce the next mocked layer-1 block. If `next_commit` is staged,
    /// this mocked block will contain that commitment.
    pub fn next_block(&mut self) {
        let mut next_burn_block = self.next_burn_block.lock().unwrap();
        let mut next_commit = self.next_commit.lock().unwrap();

        let tx_event = next_commit.take().map(|next_commit| {
            let mocked_txid = Txid(next_commit.0.clone());
            let topic = "print".into();
            let contract_identifier = self.contract_identifier.clone();
            let value = TupleData::from_data(vec![
                (
                    "event".into(),
                    ClarityValue::string_ascii_from_bytes("block-commit".as_bytes().to_vec())
                        .unwrap(),
                ),
                (
                    "block-commit".into(),
                    ClarityValue::buff_from(next_commit.0.to_vec()).unwrap(),
                ),
            ])
            .expect("Should be a legal Clarity tuple")
            .into();

            let contract_event = Some(ContractEvent {
                topic,
                contract_identifier,
                value,
            });

            NewBlockTxEvent {
                txid: mocked_txid,
                event_index: 0,
                committed: true,
                event_type: TxEventType::ContractEvent,
                contract_event,
            }
        });

        let parent_index_block_hash = StacksBlockId(make_mock_byte_string(*next_burn_block - 1));

        let index_block_hash = StacksBlockId(make_mock_byte_string(*next_burn_block));

        let new_block = NewBlock {
            block_height: *next_burn_block,
            burn_block_time: *next_burn_block,
            index_block_hash,
            parent_index_block_hash,
            events: tx_event.into_iter().collect(),
        };

        *next_burn_block += 1;

        info!("Layer 1 block mined");

        MOCK_EVENTS_STREAM.push_block(new_block);
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

impl BurnchainController for MockController {
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
        MOCK_EVENTS_STREAM.clone()
    }
    fn submit_operation(
        &mut self,
        operation: BlockstackOperationType,
        _op_signer: &mut BurnchainOpSigner,
        _attempt: u64,
    ) -> bool {
        match operation {
            BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
                block_header_hash,
                ..
            }) => {
                let mut next_commit = self.next_commit.lock().unwrap();
                if let Some(prior_commit) = next_commit.replace(block_header_hash) {
                    warn!("Mocknet controller replaced a staged commit"; "prior_commit" => %prior_commit);
                }

                true
            }
            BlockstackOperationType::DepositFt(_op) => {
                debug!("Submitted deposit ft operation");
                true
            }
            BlockstackOperationType::DepositNft(_op) => {
                debug!("Submitted deposit nft operation");
                true
            }
            BlockstackOperationType::WithdrawFt(_op) => {
                debug!("Submitted withdraw ft operation");
                true
            }
            BlockstackOperationType::WithdrawNft(_op) => {
                debug!("Submitted withdraw nft operation");
                true
            }
        }
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
                Burnchain::populate_with_default_values(&working_dir, "mockstack", "hyperchain")
                    .unwrap_or_else(|e| {
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
    fn bootstrap_chain(&mut self, _blocks_count: u64) {
        todo!()
    }
}

pub struct MockParser {
    watch_contract: QualifiedContractIdentifier,
}

#[derive(Clone, Debug)]
pub struct MockHeader {
    pub height: u64,
    pub index_hash: StacksBlockId,
    pub parent_index_hash: StacksBlockId,
    pub time_stamp: u64,
}
#[derive(Clone, Debug)]
pub struct BlockIPC(pub NewBlock);

impl BurnHeaderIPC for MockHeader {
    type H = Self;

    fn height(&self) -> u64 {
        self.height
    }

    fn header(&self) -> Self::H {
        self.clone()
    }

    fn header_hash(&self) -> [u8; 32] {
        self.index_hash.0.clone()
    }
    fn parent_header_hash(&self) -> [u8; 32] {
        self.parent_index_hash.0.clone()
    }
    fn time_stamp(&self) -> u64 {
        self.time_stamp
    }
}

impl From<&NewBlock> for MockHeader {
    fn from(b: &NewBlock) -> Self {
        MockHeader {
            index_hash: b.index_block_hash.clone(),
            parent_index_hash: b.parent_index_block_hash.clone(),
            height: b.block_height,
            time_stamp: b.burn_block_time,
        }
    }
}

impl BurnBlockIPC for BlockIPC {
    type H = MockHeader;
    type B = NewBlock;

    fn height(&self) -> u64 {
        self.0.block_height
    }

    fn header(&self) -> Self::H {
        MockHeader::from(&self.0)
    }

    fn block(&self) -> Self::B {
        self.0.clone()
    }
}

impl BurnchainBlockDownloader for MockBlockDownloader {
    type B = BlockIPC;

    fn download(&mut self, header: &MockHeader) -> Result<BlockIPC, BurnchainError> {
        let block = self.channel.get_block(header.height).ok_or_else(|| {
            warn!("Failed to mock download height = {}", header.height);
            BurnchainError::BurnchainPeerBroken
        })?;

        Ok(BlockIPC(block))
    }
}

impl BurnchainBlockParser for MockParser {
    type B = BlockIPC;

    fn parse(&mut self, block: &BlockIPC) -> Result<BurnchainBlock, BurnchainError> {
        Ok(BurnchainBlock::StacksHyperBlock(
            StacksHyperBlock::from_new_block_event(&self.watch_contract, block.block()),
        ))
    }
}

impl MockIndexer {
    pub fn new(watch_contract: QualifiedContractIdentifier) -> MockIndexer {
        MockIndexer {
            incoming_channel: MOCK_EVENTS_STREAM.clone(),
            watch_contract,
            blocks: vec![],
            minimum_recorded_height: 0,
        }
    }
}

impl BurnchainIndexer for MockIndexer {
    type P = MockParser;
    type B = BlockIPC;
    type D = MockBlockDownloader;

    fn connect(&mut self, _readwrite: bool) -> Result<(), BurnchainError> {
        Ok(())
    }

    fn get_channel(&self) -> Arc<(dyn BurnchainChannel + 'static)> {
        todo!()
    }

    fn get_first_block_height(&self) -> u64 {
        0
    }

    fn get_first_block_header_hash(&self) -> Result<BurnchainHeaderHash, BurnchainError> {
        Ok(BurnchainHeaderHash(make_mock_byte_string(0)))
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

    fn downloader(&self) -> MockBlockDownloader {
        MockBlockDownloader {
            channel: self.incoming_channel.clone(),
        }
    }

    fn parser(&self) -> MockParser {
        MockParser {
            watch_contract: self.watch_contract.clone(),
        }
    }
}
