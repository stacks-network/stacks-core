use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::ConsensusHash;
use stacks::codec::StacksMessageCodec;
use stacks::net::{AccountEntryResponse, ContractSrcResponse, RPCPeerInfoData};
use stacks::types::chainstate::{BlockHeaderHash, StacksAddress};
use stacks::util::get_epoch_time_secs;
use stacks::util::hash::Hash160;
use stacks::vm::types::QualifiedContractIdentifier;
use stacks::{
    chainstate::stacks::{
        StacksBlock, StacksBlockHeader, StacksPrivateKey, StacksPublicKey, StacksTransaction,
    },
    net::RPCPoxInfoData,
};

use crate::burnchains::mock_events::{reset_static_burnblock_simulator_channel, MockController};
use crate::neon;
use crate::tests::l1_observer_test::MOCKNET_PRIVATE_KEY_1;
use crate::tests::{
    make_contract_call, make_contract_publish, make_stacks_transfer, to_addr, SK_1, SK_2, SK_3,
};
use crate::{Config, ConfigFile, Keychain};
use std::convert::TryInto;

pub fn mockstack_test_conf() -> (Config, StacksAddress) {
    let mut conf = super::new_test_conf();

    let keychain = Keychain::default(conf.node.seed.clone());

    conf.node.miner = true;
    conf.node.wait_time_for_microblocks = 500;
    conf.burnchain.burn_fee_cap = 20000;
    conf.burnchain.chain = "mockstack".into();
    conf.burnchain.mode = "hyperchain".into();
    conf.burnchain.username = Some("neon-tester".into());
    conf.burnchain.password = Some("neon-tester-pass".into());
    conf.burnchain.peer_host = "127.0.0.1".into();
    conf.burnchain.local_mining_public_key =
        Some(keychain.generate_op_signer().get_public_key().to_hex());
    conf.burnchain.commit_anchor_block_within = 0;
    conf.burnchain.contract_identifier = QualifiedContractIdentifier::transient();

    conf.burnchain.poll_time_secs = 1;
    conf.node.pox_sync_sample_secs = 0;

    conf.miner.min_tx_fee = 1;
    conf.miner.first_attempt_time_ms = i64::max_value() as u64;
    conf.miner.subsequent_attempt_time_ms = i64::max_value() as u64;

    conf.burnchain.first_burn_header_hash =
        "0000000000000000000000000000000000000000000000000000000000000001".to_string();
    conf.burnchain.first_burn_header_height = 1;

    let miner_account = keychain.origin_address(conf.is_mainnet()).unwrap();

    (conf, miner_account)
}

pub mod test_observer {
    use std::convert::Infallible;
    use std::sync::Mutex;
    use std::thread;

    use tokio;
    use warp;
    use warp::Filter;

    use crate::event_dispatcher::{MinedBlockEvent, MinedMicroblockEvent};

    pub const EVENT_OBSERVER_PORT: u16 = 60303;

    lazy_static! {
        pub static ref NEW_BLOCKS: Mutex<Vec<serde_json::Value>> = Mutex::new(Vec::new());
        pub static ref MINED_BLOCKS: Mutex<Vec<MinedBlockEvent>> = Mutex::new(Vec::new());
        pub static ref MINED_MICROBLOCKS: Mutex<Vec<MinedMicroblockEvent>> = Mutex::new(Vec::new());
        pub static ref NEW_MICROBLOCKS: Mutex<Vec<serde_json::Value>> = Mutex::new(Vec::new());
        pub static ref BURN_BLOCKS: Mutex<Vec<serde_json::Value>> = Mutex::new(Vec::new());
        pub static ref MEMTXS: Mutex<Vec<String>> = Mutex::new(Vec::new());
        pub static ref MEMTXS_DROPPED: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
        pub static ref ATTACHMENTS: Mutex<Vec<serde_json::Value>> = Mutex::new(Vec::new());
    }

    async fn handle_burn_block(
        burn_block: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        let mut blocks = BURN_BLOCKS.lock().unwrap();
        blocks.push(burn_block);
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_block(block: serde_json::Value) -> Result<impl warp::Reply, Infallible> {
        let mut blocks = NEW_BLOCKS.lock().unwrap();
        blocks.push(block);
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_microblocks(
        microblocks: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        let mut microblock_events = NEW_MICROBLOCKS.lock().unwrap();
        microblock_events.push(microblocks);
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_mined_block(block: serde_json::Value) -> Result<impl warp::Reply, Infallible> {
        let mut mined_blocks = MINED_BLOCKS.lock().unwrap();
        // assert that the mined transaction events have string-y txids
        block
            .as_object()
            .expect("Expected JSON object for mined block event")
            .get("tx_events")
            .expect("Expected tx_events key in mined block event")
            .as_array()
            .expect("Expected tx_events key to be an array in mined block event")
            .iter()
            .for_each(|txevent| {
                let txevent_obj = txevent.as_object().expect("TransactionEvent should be object");
                let inner_obj = if let Some(inner_obj) = txevent_obj.get("Success") {
                    inner_obj
                } else if let Some(inner_obj) = txevent_obj.get("ProcessingError") {
                    inner_obj
                } else if let Some(inner_obj) = txevent_obj.get("Skipped") {
                    inner_obj
                } else {
                    panic!("TransactionEvent object should have one of Success, ProcessingError, or Skipped")
                };
                inner_obj
                    .as_object()
                    .expect("TransactionEvent should be an object")
                    .get("txid")
                    .expect("Should have txid key")
                    .as_str()
                    .expect("Expected txid to be a string");
            });

        mined_blocks.push(serde_json::from_value(block).unwrap());
        Ok(warp::http::StatusCode::OK)
    }

    /// Called by the process listening to events on a mined microblock event. The event is added
    /// to the mutex-guarded vector `MINED_MICROBLOCKS`.
    async fn handle_mined_microblock(
        tx_event: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        let mut mined_txs = MINED_MICROBLOCKS.lock().unwrap();
        mined_txs.push(serde_json::from_value(tx_event).unwrap());
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_mempool_txs(txs: serde_json::Value) -> Result<impl warp::Reply, Infallible> {
        let new_rawtxs = txs
            .as_array()
            .unwrap()
            .into_iter()
            .map(|x| x.as_str().unwrap().to_string());
        let mut memtxs = MEMTXS.lock().unwrap();
        for new_tx in new_rawtxs {
            memtxs.push(new_tx);
        }
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_mempool_drop_txs(
        txs: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        let dropped_txids = txs
            .get("dropped_txids")
            .unwrap()
            .as_array()
            .unwrap()
            .into_iter()
            .map(|x| x.as_str().unwrap().to_string());
        let reason = txs.get("reason").unwrap().as_str().unwrap().to_string();

        let mut memtxs = MEMTXS_DROPPED.lock().unwrap();
        for new_tx in dropped_txids {
            memtxs.push((new_tx, reason.clone()));
        }
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_attachments(
        attachments: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        let new_attachments = attachments.as_array().unwrap();
        let mut attachments = ATTACHMENTS.lock().unwrap();
        for new_attachment in new_attachments {
            attachments.push(new_attachment.clone());
        }
        Ok(warp::http::StatusCode::OK)
    }

    pub fn get_memtxs() -> Vec<String> {
        MEMTXS.lock().unwrap().clone()
    }

    pub fn get_memtx_drops() -> Vec<(String, String)> {
        MEMTXS_DROPPED.lock().unwrap().clone()
    }

    pub fn get_blocks() -> Vec<serde_json::Value> {
        NEW_BLOCKS.lock().unwrap().clone()
    }

    pub fn get_microblocks() -> Vec<serde_json::Value> {
        NEW_MICROBLOCKS.lock().unwrap().clone()
    }

    pub fn get_burn_blocks() -> Vec<serde_json::Value> {
        BURN_BLOCKS.lock().unwrap().clone()
    }

    pub fn get_attachments() -> Vec<serde_json::Value> {
        ATTACHMENTS.lock().unwrap().clone()
    }

    pub fn get_mined_blocks() -> Vec<MinedBlockEvent> {
        MINED_BLOCKS.lock().unwrap().clone()
    }

    pub fn get_mined_microblocks() -> Vec<MinedMicroblockEvent> {
        MINED_MICROBLOCKS.lock().unwrap().clone()
    }

    /// each path here should correspond to one of the paths listed in `event_dispatcher.rs`
    async fn serve() {
        let new_blocks = warp::path!("new_block")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_block);
        let mempool_txs = warp::path!("new_mempool_tx")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_mempool_txs);
        let mempool_drop_txs = warp::path!("drop_mempool_tx")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_mempool_drop_txs);
        let new_burn_blocks = warp::path!("new_burn_block")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_burn_block);
        let new_attachments = warp::path!("attachments" / "new")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_attachments);
        let new_microblocks = warp::path!("new_microblocks")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_microblocks);
        let mined_blocks = warp::path!("mined_block")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_mined_block);
        let mined_microblocks = warp::path!("mined_microblock")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_mined_microblock);

        info!("Spawning warp server");
        warp::serve(
            new_blocks
                .or(mempool_txs)
                .or(mempool_drop_txs)
                .or(new_burn_blocks)
                .or(new_attachments)
                .or(new_microblocks)
                .or(mined_blocks)
                .or(mined_microblocks),
        )
        .run(([127, 0, 0, 1], EVENT_OBSERVER_PORT))
        .await
    }

    pub fn spawn() {
        clear();
        thread::spawn(|| {
            let rt = tokio::runtime::Runtime::new().expect("Failed to initialize tokio");
            rt.block_on(serve());
        });
    }

    pub fn clear() {
        ATTACHMENTS.lock().unwrap().clear();
        BURN_BLOCKS.lock().unwrap().clear();
        NEW_BLOCKS.lock().unwrap().clear();
        MEMTXS.lock().unwrap().clear();
        MEMTXS_DROPPED.lock().unwrap().clear();
        MINED_BLOCKS.lock().unwrap().clear();
    }
}

const PANIC_TIMEOUT_SECS: u64 = 15;
/// Create a `btc_controller` block, specifying parent as `specify_parent`.
/// Wait for `blocks_processed` to be incremented, AND wait for the number of snapshots
/// in `sortition_db` to be icremented.
/// Panic on timeout.
pub fn next_block_and_wait(
    btc_controller: &mut MockController,
    specify_parent: Option<u64>,
    blocks_processed: &Arc<AtomicU64>,
    sortition_db: &SortitionDB,
) -> u64 {
    let initial_blocks_processed = blocks_processed.load(Ordering::SeqCst);
    let initial_all_snapshots = sortition_db
        .count_snapshots()
        .expect("")
        .expect("Couldn't count snap shots.");
    info!(
        "next_block_and_wait: Issuing block at {}, waiting for bump ({})",
        get_epoch_time_secs(),
        initial_blocks_processed
    );
    let created_block = btc_controller.next_block(specify_parent);
    let start = Instant::now();
    while blocks_processed.load(Ordering::SeqCst) <= initial_blocks_processed {
        if start.elapsed() > Duration::from_secs(PANIC_TIMEOUT_SECS) {
            panic!("Timed out waiting for block to process, trying to continue test");
        }
        thread::sleep(Duration::from_millis(100));
    }
    while sortition_db
        .count_snapshots()
        .expect("")
        .expect("Couldn't count snap shots.")
        <= initial_all_snapshots
    {
        info!("next_block_and_wait: Waiting for SNAPSHOTS!");
        if start.elapsed() > Duration::from_secs(PANIC_TIMEOUT_SECS) {
            panic!("Timed out waiting for snapshots.");
        }
        thread::sleep(Duration::from_millis(100));
    }
    info!(
        "next_block_and_wait: Block bumped at {} ({})",
        get_epoch_time_secs(),
        blocks_processed.load(Ordering::SeqCst)
    );
    let final_all_snapshots = sortition_db
        .count_snapshots()
        .expect("")
        .expect("Couldn't count snap shots.");
    info!(
        "next_block_and_wait: final_all_snapshots {} ({})",
        get_epoch_time_secs(),
        final_all_snapshots
    );
    created_block
}

pub fn wait_for_runloop(blocks_processed: &Arc<AtomicU64>) {
    let start = Instant::now();
    while blocks_processed.load(Ordering::SeqCst) == 0 {
        if start.elapsed() > Duration::from_secs(PANIC_TIMEOUT_SECS) {
            panic!("Timed out waiting for run loop to start");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Wait for at least one microblock to be mined, up to a given timeout (in seconds).
/// Returns true if the microblock was mined; false if we timed out.
pub fn wait_for_microblocks(microblocks_processed: &Arc<AtomicU64>, timeout: u64) -> bool {
    let mut current = microblocks_processed.load(Ordering::SeqCst);
    let start = Instant::now();
    info!("Waiting for next microblock (current = {})", &current);
    loop {
        let now = microblocks_processed.load(Ordering::SeqCst);
        if now == 0 && current != 0 {
            // wrapped around -- a new epoch started
            info!(
                "New microblock epoch started while waiting (originally {})",
                current
            );
            current = 0;
        }

        if now > current {
            break;
        }

        if start.elapsed() > Duration::from_secs(timeout) {
            warn!("Timed out waiting for microblocks to process ({})", timeout);
            return false;
        }

        thread::sleep(Duration::from_millis(100));
    }
    info!("Next microblock acknowledged");
    return true;
}

/// returns Some(Txid string) on success, None on failure
pub fn submit_tx_fallible(http_origin: &str, tx: &Vec<u8>) -> Option<String> {
    let client = reqwest::blocking::Client::new();
    let path = format!("{}/v2/transactions", http_origin);
    let res = client
        .post(&path)
        .header("Content-Type", "application/octet-stream")
        .body(tx.clone())
        .send()
        .unwrap();
    if res.status().is_success() {
        let res: String = res.json().unwrap();
        assert_eq!(
            res,
            StacksTransaction::consensus_deserialize(&mut &tx[..])
                .unwrap()
                .txid()
                .to_string()
        );
        Some(res)
    } else {
        eprintln!("{}", res.text().unwrap());
        None
    }
}

/// returns Txid string
pub fn submit_tx(http_origin: &str, tx: &Vec<u8>) -> String {
    submit_tx_fallible(http_origin, tx).expect("Failed to submit transaction")
}

pub fn get_chain_info(conf: &Config) -> RPCPeerInfoData {
    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    let client = reqwest::blocking::Client::new();

    // get the canonical chain tip
    let path = format!("{}/v2/info", &http_origin);
    let tip_info = client
        .get(&path)
        .send()
        .unwrap()
        .json::<RPCPeerInfoData>()
        .unwrap();

    tip_info
}

fn get_tip_anchored_block(conf: &Config) -> (ConsensusHash, StacksBlock) {
    let tip_info = get_chain_info(conf);

    // get the canonical chain tip
    let stacks_tip = tip_info.stacks_tip;
    let stacks_tip_consensus_hash = tip_info.stacks_tip_consensus_hash;

    let stacks_id_tip =
        StacksBlockHeader::make_index_block_hash(&stacks_tip_consensus_hash, &stacks_tip);

    // get the associated anchored block
    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    let client = reqwest::blocking::Client::new();
    let path = format!("{}/v2/blocks/{}", &http_origin, &stacks_id_tip);
    let block_bytes = client.get(&path).send().unwrap().bytes().unwrap();
    let block = StacksBlock::consensus_deserialize(&mut block_bytes.as_ref()).unwrap();

    (stacks_tip_consensus_hash, block)
}

fn find_microblock_privkey(
    conf: &Config,
    pubkey_hash: &Hash160,
    max_tries: u64,
) -> Option<StacksPrivateKey> {
    let mut keychain = Keychain::default(conf.node.seed.clone());
    for ix in 0..max_tries {
        // the first rotation occurs at 203.
        let privk = keychain.rotate_microblock_keypair(203 + ix);
        let pubkh = Hash160::from_node_public_key(&StacksPublicKey::from_private(&privk));
        if pubkh == *pubkey_hash {
            return Some(privk);
        }
    }
    return None;
}

/// Returns true iff `b` is within `0.1%` of `a`.
fn is_close_f64(a: f64, b: f64) -> bool {
    let error = (a - b).abs() / a.abs();
    error < 0.001
}

#[test]
#[ignore]
/// Simple test for the mock backend: test that the hyperchain miner
/// is capable of producing blocks
fn mockstack_integration_test() {
    reset_static_burnblock_simulator_channel();
    let (mut conf, miner_account) = mockstack_test_conf();
    let prom_bind = format!("{}:{}", "127.0.0.1", 6000);
    conf.node.prometheus_bind = Some(prom_bind.clone());

    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();

    let burnchain = Burnchain::new(
        &conf.get_burn_db_path(),
        &conf.burnchain.chain,
        &conf.burnchain.mode,
    )
    .unwrap();

    let mut btc_regtest_controller = MockController::new(conf, channel.clone());

    thread::spawn(move || run_loop.start(None, 0));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);
    btc_regtest_controller.next_block(None);
    // btc_regtest_controller.next_block(None);

    let (sortition_db, _) = burnchain.open_db(true).unwrap();

    // first block wakes up the run loop
    next_block_and_wait(
        &mut btc_regtest_controller,
        None,
        &blocks_processed,
        &sortition_db,
    );

    // first block will hold our VRF registration
    next_block_and_wait(
        &mut btc_regtest_controller,
        None,
        &blocks_processed,
        &sortition_db,
    );

    // second block will be the first mined Stacks block
    next_block_and_wait(
        &mut btc_regtest_controller,
        None,
        &blocks_processed,
        &sortition_db,
    );

    // let's query the miner's account nonce:

    eprintln!("Miner account: {}", miner_account);

    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.balance, 0);
    assert_eq!(account.nonce, 1);

    // query for prometheus metrics
    #[cfg(feature = "monitoring_prom")]
    {
        let prom_http_origin = format!("http://{}", prom_bind);
        let client = reqwest::blocking::Client::new();
        let res = client
            .get(&prom_http_origin)
            .send()
            .unwrap()
            .text()
            .unwrap();
        assert!(res.contains("stacks_node_computed_miner_commitment_high 0"));
        assert!(res.contains("stacks_node_computed_miner_commitment_low 1"));
        assert!(res.contains("stacks_node_computed_relative_miner_score 100"));
        assert!(res.contains("stacks_node_miner_current_median_commitment_high 0"));
        assert!(res.contains("stacks_node_miner_current_median_commitment_low 1"));
        assert!(res.contains("stacks_node_active_miners_total 1"));
    }

    channel.stop_chains_coordinator();
}

/// Test that we can set a "first burn block" far in the future and then listen until we hear it.
#[test]
#[ignore]
fn mockstack_wait_for_first_block() {
    reset_static_burnblock_simulator_channel();
    let (mut conf, miner_account) = mockstack_test_conf();
    let prom_bind = format!("{}:{}", "127.0.0.1", 6000);
    conf.node.prometheus_bind = Some(prom_bind.clone());
    conf.burnchain.first_burn_header_hash =
        "0000000000000000000000000000000000000000000000000000000000000010".to_string();
    conf.burnchain.first_burn_header_height = 16;

    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();
    let burnchain = Burnchain::new(
        &conf.get_burn_db_path(),
        &conf.burnchain.chain,
        &conf.burnchain.mode,
    )
    .unwrap();
    let mut btc_regtest_controller = MockController::new(conf, channel.clone());

    thread::spawn(move || run_loop.start(None, 0));

    wait_for_runloop(&blocks_processed);

    let (sortition_db, _) = burnchain.open_db(true).unwrap();

    // Walk up 16 + 1 blocks.
    btc_regtest_controller.next_block(None);
    for i in 0..16 {
        btc_regtest_controller.next_block(None);
    }

    next_block_and_wait(
        &mut btc_regtest_controller,
        None,
        &blocks_processed,
        &sortition_db,
    );

    channel.stop_chains_coordinator();
}

fn get_balance<F: std::fmt::Display>(http_origin: &str, account: &F) -> u128 {
    get_account(http_origin, account).balance
}

#[derive(Debug)]
pub struct Account {
    pub balance: u128,
    pub nonce: u64,
}

pub fn get_account<F: std::fmt::Display>(http_origin: &str, account: &F) -> Account {
    let client = reqwest::blocking::Client::new();
    let path = format!("{}/v2/accounts/{}?proof=0", http_origin, account);
    let res = client
        .get(&path)
        .send()
        .unwrap()
        .json::<AccountEntryResponse>()
        .unwrap();
    info!("Account response: {:#?}", res);
    Account {
        balance: u128::from_str_radix(&res.balance[2..], 16).unwrap(),
        nonce: res.nonce,
    }
}

fn get_pox_info(http_origin: &str) -> RPCPoxInfoData {
    let client = reqwest::blocking::Client::new();
    let path = format!("{}/v2/pox", http_origin);
    client
        .get(&path)
        .send()
        .unwrap()
        .json::<RPCPoxInfoData>()
        .unwrap()
}

fn get_chain_tip(http_origin: &str) -> (ConsensusHash, BlockHeaderHash) {
    let client = reqwest::blocking::Client::new();
    let path = format!("{}/v2/info", http_origin);
    let res = client
        .get(&path)
        .send()
        .unwrap()
        .json::<serde_json::Value>()
        .unwrap();
    (
        ConsensusHash::from_hex(
            res.get("stacks_tip_consensus_hash")
                .unwrap()
                .as_str()
                .unwrap(),
        )
        .unwrap(),
        BlockHeaderHash::from_hex(res.get("stacks_tip").unwrap().as_str().unwrap()).unwrap(),
    )
}

fn get_chain_tip_height(http_origin: &str) -> u64 {
    let client = reqwest::blocking::Client::new();
    let path = format!("{}/v2/info", http_origin);
    let res = client
        .get(&path)
        .send()
        .unwrap()
        .json::<RPCPeerInfoData>()
        .unwrap();

    res.stacks_tip_height
}

fn get_contract_src(
    http_origin: &str,
    contract_addr: StacksAddress,
    contract_name: String,
    use_latest_tip: bool,
) -> Result<String, String> {
    let client = reqwest::blocking::Client::new();
    let query_string = if use_latest_tip {
        "?tip=latest".to_string()
    } else {
        "".to_string()
    };
    let path = format!(
        "{}/v2/contracts/source/{}/{}{}",
        http_origin, contract_addr, contract_name, query_string
    );
    let res = client.get(&path).send().unwrap();

    if res.status().is_success() {
        let contract_src_res = res.json::<ContractSrcResponse>().unwrap();
        Ok(contract_src_res.source)
    } else {
        let err_str = res.text().unwrap();
        Err(err_str)
    }
}

const FAUCET_CONTRACT: &'static str = "
  (define-public (spout)
    (let ((recipient tx-sender))
      (print (as-contract (stx-transfer? u1 .faucet recipient)))))
";

/// Test the node's RPC interface using a faucet contract, issuing
/// several transfers and contract calls, and check that the RPC interface
/// processes the blocks
#[test]
#[ignore]
fn faucet_test() {
    reset_static_burnblock_simulator_channel();
    let (mut conf, miner_account) = mockstack_test_conf();

    let contract_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
    let sk_2 = StacksPrivateKey::from_hex(SK_2).unwrap();
    let sk_3 = StacksPrivateKey::from_hex(SK_3).unwrap();
    let addr_2 = to_addr(&sk_2);
    let addr_3 = to_addr(&sk_3);

    let addr_3_init_balance = 100000;
    let addr_2_init_balance = 1000;

    conf.add_initial_balance(addr_3.to_string(), addr_3_init_balance);
    conf.add_initial_balance(addr_2.to_string(), addr_2_init_balance);
    conf.add_initial_balance(to_addr(&contract_sk).to_string(), 3000);

    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    let burnchain = Burnchain::new(
        &conf.get_burn_db_path(),
        &conf.burnchain.chain,
        &conf.burnchain.mode,
    )
    .unwrap();
    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();

    let mut btc_regtest_controller = MockController::new(conf, channel.clone());

    thread::spawn(move || run_loop.start(None, 0));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    let (sortition_db, _) = burnchain.open_db(true).unwrap();

    btc_regtest_controller.next_block(None);
    btc_regtest_controller.next_block(None);

    // first block wakes up the run loop
    next_block_and_wait(
        &mut btc_regtest_controller,
        None,
        &blocks_processed,
        &sortition_db,
    );

    // first block will hold our VRF registration
    next_block_and_wait(
        &mut btc_regtest_controller,
        None,
        &blocks_processed,
        &sortition_db,
    );

    // second block will be the first mined Stacks block
    next_block_and_wait(
        &mut btc_regtest_controller,
        None,
        &blocks_processed,
        &sortition_db,
    );

    // let's query the miner's account nonce:

    eprintln!("Miner account: {}", miner_account);

    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.balance, 0);
    assert!(account.nonce >= 1);

    eprintln!("Tenure in 1 started!");

    let contract_identifier = QualifiedContractIdentifier::parse(&format!(
        "{}.{}",
        to_addr(&contract_sk).to_string(),
        "faucet"
    ))
    .unwrap();

    let xfer_to_faucet_tx =
        make_stacks_transfer(&sk_3, 0, 1000, &contract_identifier.clone().into(), 1000);
    let _xfer_to_faucet_txid = submit_tx(&http_origin, &xfer_to_faucet_tx);

    next_block_and_wait(
        &mut btc_regtest_controller,
        None,
        &blocks_processed,
        &sortition_db,
    );

    let publish_tx = make_contract_publish(&contract_sk, 0, 1000, "faucet", FAUCET_CONTRACT);
    let _publish_txid = submit_tx(&http_origin, &publish_tx);

    next_block_and_wait(
        &mut btc_regtest_controller,
        None,
        &blocks_processed,
        &sortition_db,
    );
    next_block_and_wait(
        &mut btc_regtest_controller,
        None,
        &blocks_processed,
        &sortition_db,
    );

    let publish_dup_tx = make_contract_publish(&contract_sk, 1, 1000, "faucet", FAUCET_CONTRACT);
    assert!(
        submit_tx_fallible(&http_origin, &publish_dup_tx).is_none(),
        "Duplicate contract publish should not be allowed"
    );

    let contract_call_tx = make_contract_call(
        &sk_2,
        0,
        1000,
        &to_addr(&contract_sk),
        "faucet",
        "spout",
        &[],
    );
    let _contract_call_txid = submit_tx(&http_origin, &contract_call_tx);

    next_block_and_wait(
        &mut btc_regtest_controller,
        None,
        &blocks_processed,
        &sortition_db,
    );
    next_block_and_wait(
        &mut btc_regtest_controller,
        None,
        &blocks_processed,
        &sortition_db,
    );

    assert_eq!(
        get_balance(&http_origin, &addr_3) as u64,
        addr_3_init_balance - 1000 - 1000
    );
    assert_eq!(
        get_balance(&http_origin, &addr_2) as u64,
        addr_2_init_balance - 1000 + 1
    );
    assert_eq!(
        get_balance(&http_origin, &contract_identifier) as u64,
        1000 - 1
    );

    channel.stop_chains_coordinator();
}

/// Create burnchain fork, and see that the hyper-chain miner can continue to call.
/// Does not exercise contract calls.
#[test]
#[ignore]
fn no_contract_calls_forking_integration_test() {
    reset_static_burnblock_simulator_channel();

    let (mut conf, miner_account) = mockstack_test_conf();
    let prom_bind = format!("{}:{}", "127.0.0.1", 6000);
    conf.node.prometheus_bind = Some(prom_bind.clone());
    conf.node.miner = true;

    let user_addr = to_addr(&MOCKNET_PRIVATE_KEY_1);
    conf.add_initial_balance(user_addr.to_string(), 10000000);

    test_observer::spawn();
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    let burnchain = Burnchain::new(
        &conf.get_burn_db_path(),
        &conf.burnchain.chain,
        &conf.burnchain.mode,
    )
    .unwrap();

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();
    let l2_rpc_origin = format!("http://{}", &conf.node.rpc_bind);

    let mut btc_regtest_controller = MockController::new(conf, channel.clone());

    test_observer::spawn();
    let termination_switch = run_loop.get_termination_switch();
    let run_loop_thread = thread::spawn(move || run_loop.start(None, 0));

    // btc_regtest_controller.next_block(None);
    wait_for_runloop(&blocks_processed);
    let (sortition_db, _) = burnchain.open_db(true).unwrap();

    btc_regtest_controller.next_block(None);

    next_block_and_wait(
        &mut btc_regtest_controller,
        None,
        &blocks_processed,
        &sortition_db,
    );
    assert_l2_l1_tip_heights(&sortition_db, 0, 2);

    next_block_and_wait(
        &mut btc_regtest_controller,
        None,
        &blocks_processed,
        &sortition_db,
    );
    assert_l2_l1_tip_heights(&sortition_db, 0, 3);

    let common_ancestor = next_block_and_wait(
        &mut btc_regtest_controller,
        None,
        &blocks_processed,
        &sortition_db,
    );
    assert_l2_l1_tip_heights(&sortition_db, 1, 4);

    for i in 0..2 {
        next_block_and_wait(
            &mut btc_regtest_controller,
            None,
            &blocks_processed,
            &sortition_db,
        );
        assert_l2_l1_tip_heights(&sortition_db, 2 + i, 5 + i);
    }

    let mut cursor = common_ancestor;
    for i in 0..3 {
        cursor = btc_regtest_controller.next_block(Some(cursor));
    }

    cursor = next_block_and_wait(
        &mut btc_regtest_controller,
        Some(cursor),
        &blocks_processed,
        &sortition_db,
    );
    assert_l2_l1_tip_heights(&sortition_db, 1, 8);

    next_block_and_wait(
        &mut btc_regtest_controller,
        Some(cursor),
        &blocks_processed,
        &sortition_db,
    );
    assert_l2_l1_tip_heights(&sortition_db, 2, 9);

    termination_switch.store(false, Ordering::SeqCst);
    run_loop_thread.join().expect("Failed to join run loop.");
}

/// Look up the chain tip, and assert the L2 and L1 tip heights.
fn assert_l2_l1_tip_heights(sortition_db: &SortitionDB, l2_height: u64, l1_height: u64) {
    let tip_snapshot = SortitionDB::get_canonical_burn_chain_tip(&sortition_db.conn())
        .expect("Could not read from SortitionDB.");
    assert_eq!(l2_height, tip_snapshot.canonical_stacks_tip_height);
    assert_eq!(l1_height, tip_snapshot.block_height);
}
