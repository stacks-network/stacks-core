use std::cmp;
use std::convert::TryInto;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use stacks::address::AddressHashMode;
use stacks::burnchains::db::BurnchainDB;
use stacks::burnchains::events::NewBlock;
use stacks::burnchains::indexer::{
    BurnBlockIPC, BurnchainBlockDownloader, BurnchainBlockParser, BurnchainIndexer,
};
use stacks::burnchains::{
    Burnchain, BurnchainBlock, Error as BurnchainError, StacksHyperBlock, Txid,
};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::{BlockstackOperationType, LeaderBlockCommitOp};
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::chainstate::stacks::index::ClarityMarfTrieId;
use stacks::chainstate::stacks::{
    StacksPrivateKey, StacksPublicKey, StacksTransaction, StacksTransactionSigner, TransactionAuth,
    TransactionContractCall, TransactionPostConditionMode, TransactionSpendingCondition,
    TransactionVersion,
};
use stacks::clarity::vm::Value as ClarityValue;
use stacks::codec::StacksMessageCodec;
use stacks::core::StacksEpoch;
use stacks::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksAddress, StacksBlockId,
};
use stacks::util::hash::hex_bytes;
use stacks::util::sleep_ms;
use stacks::vm::types::QualifiedContractIdentifier;
use stacks::vm::ClarityName;

use super::db_indexer::DBBurnchainIndexer;
use super::mock_events::BlockIPC;
use super::{BurnchainChannel, Error};
use crate::burnchains::mock_events::MockHeader;
use crate::config::BurnchainConfig;
use crate::operations::BurnchainOpSigner;
use crate::{BurnchainController, BurnchainTip, Config};

#[derive(Clone)]
pub struct L1Channel {
    blocks: Arc<Mutex<Vec<NewBlock>>>,
    minimum_recorded_height: Arc<Mutex<u64>>,
}

pub struct L1Controller {
    burnchain: Burnchain,
    config: Config,
    indexer: DBBurnchainIndexer,

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

/// Represents the returned JSON
///  from the L1 /v2/accounts endpoint
#[derive(Deserialize)]
struct RpcAccountResponse {
    nonce: u64,
    #[allow(dead_code)]
    balance: String,
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
    fn push_block(&self, new_block: NewBlock) -> Result<(), stacks::burnchains::Error> {
        let mut blocks = self.blocks.lock().unwrap();
        blocks.push(new_block);
        Ok(())
    }
}

impl L1Channel {
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

/// Build a `Burnchain` from values in `config`. Call `Burnchain::new`, which sets defaults
/// and then override the "first block" information using `config`.
pub fn burnchain_from_config(
    burn_db_path: &String,
    config: &BurnchainConfig,
) -> Result<Burnchain, BurnchainError> {
    let mut burnchain = Burnchain::new(&burn_db_path, &config.chain, &config.mode)?;
    burnchain.first_block_hash = BurnchainHeaderHash::from_hex(&config.first_burn_header_hash)
        .expect(&format!(
            "Could not parse BurnchainHeaderHash: {}",
            &config.first_burn_header_hash
        ));
    burnchain.first_block_height = config.first_burn_header_height;
    burnchain.first_block_timestamp = config.first_burn_header_timestamp as u32;

    Ok(burnchain)
}

impl L1Controller {
    pub fn new(config: Config, coordinator: CoordinatorChannels) -> Result<L1Controller, Error> {
        let indexer = DBBurnchainIndexer::new(
            &config.get_chainstate_path_str(),
            config.burnchain.clone(),
            true,
        )?;
        let burnchain = burnchain_from_config(&config.get_burn_db_path(), &config.burnchain)?;
        Ok(L1Controller {
            burnchain,
            config,
            indexer,
            db: None,
            burnchain_db: None,
            should_keep_running: Some(Arc::new(AtomicBool::new(true))),
            coordinator,
            chain_tip: None,
        })
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

    fn l1_rpc_interface(&self) -> String {
        self.config.burnchain.get_rpc_url()
    }

    fn l1_get_nonce(&self, address: &StacksAddress) -> Result<u64, Error> {
        let url = format!(
            "{}/v2/accounts/{}?proof=0",
            self.l1_rpc_interface(),
            address
        );
        let response_json: RpcAccountResponse = reqwest::blocking::get(url)?.json()?;
        Ok(response_json.nonce)
    }

    fn l1_submit_tx(&self, tx: StacksTransaction) -> Result<Txid, Error> {
        let client = reqwest::blocking::Client::new();
        let url = format!("{}/v2/transactions", self.l1_rpc_interface());
        let res = client
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .body(tx.serialize_to_vec())
            .send()?;

        if res.status().is_success() {
            let res: String = res.json().unwrap();
            Txid::from_hex(&res).map_err(|e| Error::RPCError(e.to_string()))
        } else {
            Err(Error::RPCError(res.text()?))
        }
    }

    fn l1_addr_from_signer(&self, signer: &BurnchainOpSigner) -> StacksAddress {
        let hash_mode = AddressHashMode::SerializeP2PKH;
        let addr_version = if self.config.burnchain.is_mainnet() {
            hash_mode.to_version_mainnet()
        } else {
            hash_mode.to_version_testnet()
        };
        StacksAddress::from_public_keys(addr_version, &hash_mode, 1, &vec![signer.get_public_key()])
            .unwrap()
    }

    fn make_mine_contract_call(
        &self,
        sender: &StacksPrivateKey,
        sender_nonce: u64,
        tx_fee: u64,
        commit_to: BlockHeaderHash,
    ) -> Result<StacksTransaction, Error> {
        let QualifiedContractIdentifier {
            issuer: contract_addr,
            name: contract_name,
        } = self.config.burnchain.contract_identifier.clone();
        let version = if self.config.burnchain.is_mainnet() {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };
        let committed_block = commit_to.as_bytes().to_vec();
        let payload = TransactionContractCall {
            address: contract_addr.into(),
            contract_name,
            function_name: ClarityName::from("commit-block"),
            function_args: vec![
                ClarityValue::buff_from(committed_block).map_err(|_| Error::BadCommitment)?
            ],
        };

        let mut sender_spending_condition = TransactionSpendingCondition::new_singlesig_p2pkh(
            StacksPublicKey::from_private(sender),
        )
        .expect("Failed to create p2pkh spending condition from public key.");
        sender_spending_condition.set_nonce(sender_nonce);
        sender_spending_condition.set_tx_fee(tx_fee);
        let auth = TransactionAuth::Standard(sender_spending_condition);

        let mut unsigned_tx = StacksTransaction::new(version, auth, payload.into());
        unsigned_tx.anchor_mode = self.config.burnchain.anchor_mode.clone();
        unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;
        unsigned_tx.chain_id = self.config.burnchain.chain_id;

        let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
        tx_signer.sign_origin(sender).unwrap();

        Ok(tx_signer
            .get_tx()
            .expect("Failed to get signed transaction from signer"))
    }

    fn submit_commit_operation(
        &self,
        op: LeaderBlockCommitOp,
        op_signer: &mut BurnchainOpSigner,
        attempt: u64,
    ) -> bool {
        // todo: think about enabling replace-by-nonce?
        if attempt > 1 {
            return false;
        }
        // step 1: figure out the miner's nonce
        let miner_address = self.l1_addr_from_signer(op_signer);
        let nonce = match self.l1_get_nonce(&miner_address) {
            Ok(x) => x,
            Err(e) => {
                error!("Failed to obtain miner nonce: {}", e);
                return false;
            }
        };

        // step 2: fee estimate (todo: #issue)
        let fee = 100_000;
        let contract_call = match self.make_mine_contract_call(
            op_signer.get_sk(),
            nonce,
            fee,
            op.block_header_hash,
        ) {
            Ok(x) => x,
            Err(e) => {
                error!("Failed to construct contract call operation: {}", e);
                return false;
            }
        };

        match self.l1_submit_tx(contract_call) {
            Ok(x) => {
                info!("Submitted miner commitment L1 transaction"; "txid" => %x);
                true
            }
            Err(e) => {
                error!("Failed to submit miner commitment L1 transaction: {}", e);
                false
            }
        }
    }
}

impl BurnchainController for L1Controller {
    fn start(
        &mut self,
        target_block_height_opt: Option<u64>,
    ) -> Result<(BurnchainTip, u64), Error> {
        self.indexer.connect(true)?;
        self.receive_blocks(
            false,
            target_block_height_opt.map_or_else(|| Some(1), |x| Some(x)),
        )
    }
    fn get_channel(&self) -> Arc<dyn BurnchainChannel> {
        self.indexer.get_channel()
    }

    fn submit_operation(
        &mut self,
        operation: BlockstackOperationType,
        op_signer: &mut BurnchainOpSigner,
        attempt: u64,
    ) -> bool {
        info!("Submitting operation: {}", operation);

        match operation {
            BlockstackOperationType::LeaderBlockCommit(op) => {
                self.submit_commit_operation(op, op_signer, attempt)
            }
            BlockstackOperationType::DepositFt(_op) => {
                debug!("Submitting deposit ft operation to be implemented.");
                true
            }
            BlockstackOperationType::DepositNft(_op) => {
                debug!("Submitting deposit nft operation to be implemented.");
                true
            }
            BlockstackOperationType::WithdrawFt(_op) => {
                debug!("Submitting withdraw ft operation to be implemented.");
                true
            }
            BlockstackOperationType::WithdrawNft(_op) => {
                debug!("Submitting withdraw nft operation to be implemented.");
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

        self.indexer.connect(true)?;
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
        self.burnchain.clone()
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
