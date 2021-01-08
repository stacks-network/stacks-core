use super::{
    make_contract_call, make_contract_publish, make_contract_publish_microblock_only,
    make_microblock, make_stacks_transfer_mblock_only, to_addr, ADDR_4, SK_1, SK_2,
};
use stacks::burnchains::{Address, Burnchain, PoxConstants};
use stacks::chainstate::burn::ConsensusHash;
use stacks::chainstate::stacks::{
    db::StacksChainState, StacksAddress, StacksBlock, StacksBlockHeader, StacksPrivateKey,
    StacksPublicKey, StacksTransaction, TransactionPayload,
};
use stacks::core;
use stacks::net::StacksMessageCodec;
use stacks::util::secp256k1::Secp256k1PublicKey;
use stacks::vm::execute;
use stacks::vm::types::PrincipalData;
use stacks::vm::Value;

use stacks::vm::database::ClarityDeserializable;

use super::bitcoin_regtest::BitcoinCoreController;
use crate::{
    burnchains::bitcoin_regtest_controller::UTXO, config::EventKeyType,
    config::EventObserverConfig, config::InitialBalance, config::TESTNET_CHAIN_ID, neon,
    operations::BurnchainOpSigner, BitcoinRegtestController, BurnchainController, Config,
    ConfigFile, Keychain,
};
use stacks::net::{
    AccountEntryResponse, GetAttachmentResponse, PostTransactionRequestBody, RPCPeerInfoData,
};
use stacks::util::hash::Hash160;
use stacks::util::hash::{bytes_to_hex, hex_bytes};
use stacks::util::sleep_ms;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{env, thread};

use stacks::burnchains::bitcoin::address::{BitcoinAddress, BitcoinAddressType};
use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::burnchains::{BurnchainHeaderHash, Txid};
use stacks::chainstate::burn::operations::{BlockstackOperationType, PreStxOp, TransferStxOp};

fn neon_integration_test_conf() -> (Config, StacksAddress) {
    let mut conf = super::new_test_conf();

    let keychain = Keychain::default(conf.node.seed.clone());

    conf.node.miner = true;
    conf.node.wait_time_for_microblocks = 500;
    conf.burnchain.burn_fee_cap = 20000;

    conf.burnchain.mode = "neon".into();
    conf.burnchain.username = Some("neon-tester".into());
    conf.burnchain.password = Some("neon-tester-pass".into());
    conf.burnchain.peer_host = "127.0.0.1".into();
    conf.burnchain.local_mining_public_key =
        Some(keychain.generate_op_signer().get_public_key().to_hex());
    conf.burnchain.commit_anchor_block_within = 0;

    // test to make sure config file parsing is correct
    let magic_bytes = Config::from_config_file(ConfigFile::xenon())
        .burnchain
        .magic_bytes;
    assert_eq!(magic_bytes.as_bytes(), &['X' as u8, '4' as u8]);
    conf.burnchain.magic_bytes = magic_bytes;
    conf.burnchain.poll_time_secs = 1;
    conf.node.pox_sync_sample_secs = 1;

    let miner_account = keychain.origin_address().unwrap();

    (conf, miner_account)
}

mod test_observer {
    use std::convert::Infallible;
    use std::sync::Mutex;
    use std::thread;
    use tokio;
    use warp;
    use warp::Filter;

    pub const EVENT_OBSERVER_PORT: u16 = 50303;

    lazy_static! {
        pub static ref NEW_BLOCKS: Mutex<Vec<serde_json::Value>> = Mutex::new(Vec::new());
        pub static ref BURN_BLOCKS: Mutex<Vec<serde_json::Value>> = Mutex::new(Vec::new());
        pub static ref MEMTXS: Mutex<Vec<String>> = Mutex::new(Vec::new());
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

    pub fn get_blocks() -> Vec<serde_json::Value> {
        NEW_BLOCKS.lock().unwrap().clone()
    }

    pub fn get_burn_blocks() -> Vec<serde_json::Value> {
        BURN_BLOCKS.lock().unwrap().clone()
    }

    pub fn get_attachments() -> Vec<serde_json::Value> {
        ATTACHMENTS.lock().unwrap().clone()
    }

    async fn serve() {
        let new_blocks = warp::path!("new_block")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_block);
        let mempool_txs = warp::path!("new_mempool_tx")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_mempool_txs);
        let new_burn_blocks = warp::path!("new_burn_block")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_burn_block);
        let new_attachments = warp::path!("attachments" / "new")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_attachments);

        info!("Spawning warp server");
        warp::serve(
            new_blocks
                .or(mempool_txs)
                .or(new_burn_blocks)
                .or(new_attachments),
        )
        .run(([127, 0, 0, 1], EVENT_OBSERVER_PORT))
        .await
    }

    pub fn spawn() {
        clear();
        thread::spawn(|| {
            let mut rt = tokio::runtime::Runtime::new().expect("Failed to initialize tokio");
            rt.block_on(serve());
        });
    }

    pub fn clear() {
        ATTACHMENTS.lock().unwrap().clear();
        BURN_BLOCKS.lock().unwrap().clear();
        NEW_BLOCKS.lock().unwrap().clear();
        MEMTXS.lock().unwrap().clear();
    }
}

const PANIC_TIMEOUT_SECS: u64 = 600;
fn next_block_and_wait(
    btc_controller: &mut BitcoinRegtestController,
    blocks_processed: &Arc<AtomicU64>,
) {
    let current = blocks_processed.load(Ordering::SeqCst);
    eprintln!("Issuing block, waiting for bump");
    btc_controller.build_next_block(1);
    let start = Instant::now();
    while blocks_processed.load(Ordering::SeqCst) <= current {
        if start.elapsed() > Duration::from_secs(PANIC_TIMEOUT_SECS) {
            error!("Timed out waiting for block to process, trying to continue test");
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_runloop(blocks_processed: &Arc<AtomicU64>) {
    let start = Instant::now();
    while blocks_processed.load(Ordering::SeqCst) == 0 {
        if start.elapsed() > Duration::from_secs(PANIC_TIMEOUT_SECS) {
            panic!("Timed out waiting for run loop to start");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn submit_tx(http_origin: &str, tx: &Vec<u8>) {
    let client = reqwest::blocking::Client::new();
    let path = format!("{}/v2/transactions", http_origin);
    let res = client
        .post(&path)
        .header("Content-Type", "application/octet-stream")
        .body(tx.clone())
        .send()
        .unwrap();
    eprintln!("{:#?}", res);
    if res.status().is_success() {
        let res: String = res.json().unwrap();
        assert_eq!(
            res,
            StacksTransaction::consensus_deserialize(&mut &tx[..])
                .unwrap()
                .txid()
                .to_string()
        );
    } else {
        eprintln!("{}", res.text().unwrap());
        panic!("");
    }
}

fn get_tip_anchored_block(conf: &Config) -> (ConsensusHash, StacksBlock) {
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
    let stacks_tip = tip_info.stacks_tip;
    let stacks_tip_consensus_hash =
        ConsensusHash::from_hex(&tip_info.stacks_tip_consensus_hash).unwrap();

    let stacks_id_tip =
        StacksBlockHeader::make_index_block_hash(&stacks_tip_consensus_hash, &stacks_tip);

    // get the associated anchored block
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

#[test]
#[ignore]
fn bitcoind_integration_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let (conf, miner_account) = neon_integration_test_conf();

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::new(conf.clone(), None);
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf);
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();

    thread::spawn(move || run_loop.start(0, None));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // let's query the miner's account nonce:

    eprintln!("Miner account: {}", miner_account);

    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.balance, 0);
    assert_eq!(account.nonce, 1);

    channel.stop_chains_coordinator();
}

fn get_balance<F: std::fmt::Display>(http_origin: &str, account: &F) -> u128 {
    get_account(http_origin, account).balance
}

struct Account {
    balance: u128,
    nonce: u64,
}

fn get_account<F: std::fmt::Display>(http_origin: &str, account: &F) -> Account {
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

#[test]
#[ignore]
fn liquid_ustx_integration() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    // the contract that we'll test the costs of
    let caller_src = "
    (define-public (execute)
       (ok stx-liquid-supply))
    ";

    let spender_sk = StacksPrivateKey::new();
    let spender_addr = to_addr(&spender_sk);
    let spender_princ: PrincipalData = spender_addr.into();

    let (mut conf, _miner_account) = neon_integration_test_conf();

    test_observer::spawn();

    conf.events_observers.push(EventObserverConfig {
        endpoint: format!("localhost:{}", test_observer::EVENT_OBSERVER_PORT),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let spender_bal = 10_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);

    conf.initial_balances.push(InitialBalance {
        address: spender_princ.clone(),
        amount: spender_bal,
    });

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let burnchain_config = Burnchain::regtest(&conf.get_burn_db_path());

    let mut btc_regtest_controller = BitcoinRegtestController::with_burnchain(
        conf.clone(),
        None,
        Some(burnchain_config.clone()),
    );
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();
    let _client = reqwest::blocking::Client::new();
    let channel = run_loop.get_coordinator_channel().unwrap();

    thread::spawn(move || run_loop.start(0, Some(burnchain_config)));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let _sort_height = channel.get_sortitions_processed();

    let publish = make_contract_publish(&spender_sk, 0, 1000, "caller", caller_src);

    submit_tx(&http_origin, &publish);

    // mine 1 burn block for the miner to issue the next block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    // mine next burn block for the miner to win
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let call_tx = make_contract_call(
        &spender_sk,
        1,
        1000,
        &spender_addr,
        "caller",
        "execute",
        &[],
    );

    submit_tx(&http_origin, &call_tx);

    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // clear and mine another burnchain block, so that the new winner is seen by the observer
    //   (the observer is logically "one block behind" the miner
    test_observer::clear();
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let mut blocks = test_observer::get_blocks();
    // should have produced 1 new block
    assert_eq!(blocks.len(), 1);
    let block = blocks.pop().unwrap();
    let transactions = block.get("transactions").unwrap().as_array().unwrap();
    eprintln!("{}", transactions.len());
    let mut tested = false;
    for tx in transactions.iter() {
        let raw_tx = tx.get("raw_tx").unwrap().as_str().unwrap();
        if raw_tx == "0x00" {
            continue;
        }
        let tx_bytes = hex_bytes(&raw_tx[2..]).unwrap();
        let parsed = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
        if let TransactionPayload::ContractCall(contract_call) = parsed.payload {
            eprintln!("{}", contract_call.function_name.as_str());
            if contract_call.function_name.as_str() == "execute" {
                let raw_result = tx.get("raw_result").unwrap().as_str().unwrap();
                let parsed = <Value as ClarityDeserializable<Value>>::deserialize(&raw_result[2..]);
                let liquid_ustx = parsed.expect_result_ok().expect_u128();
                assert!(liquid_ustx > 0, "Should be more liquid ustx than 0");
                tested = true;
            }
        }
    }
    assert!(tested, "Should have found a contract call tx");
}

#[test]
#[ignore]
fn stx_transfer_btc_integration_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let spender_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
    let spender_stx_addr: StacksAddress = to_addr(&spender_sk);
    let spender_addr: PrincipalData = spender_stx_addr.clone().into();
    let _spender_btc_addr = BitcoinAddress::from_bytes(
        BitcoinNetworkType::Regtest,
        BitcoinAddressType::PublicKeyHash,
        &spender_stx_addr.bytes.0,
    )
    .unwrap();

    let spender_2_sk = StacksPrivateKey::from_hex(SK_2).unwrap();
    let spender_2_stx_addr: StacksAddress = to_addr(&spender_2_sk);
    let spender_2_addr: PrincipalData = spender_2_stx_addr.clone().into();

    let (mut conf, _miner_account) = neon_integration_test_conf();

    conf.initial_balances.push(InitialBalance {
        address: spender_addr.clone(),
        amount: 100300,
    });

    conf.initial_balances.push(InitialBalance {
        address: spender_2_addr.clone(),
        amount: 100300,
    });

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::new(conf.clone(), None);
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();

    thread::spawn(move || run_loop.start(0, None));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // let's query the spender's account:
    assert_eq!(get_balance(&http_origin, &spender_addr), 100300);

    // okay, let's send a pre-stx op.
    let pre_stx_op = PreStxOp {
        output: spender_stx_addr.clone(),
        // to be filled in
        txid: Txid([0u8; 32]),
        vtxindex: 0,
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash([0u8; 32]),
    };

    let mut miner_signer = Keychain::default(conf.node.seed.clone()).generate_op_signer();

    assert!(
        btc_regtest_controller.submit_operation(
            BlockstackOperationType::PreStx(pre_stx_op),
            &mut miner_signer,
            1
        ),
        "Pre-stx operation should submit successfully"
    );

    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    // let's fire off our transfer op.
    let recipient_sk = StacksPrivateKey::new();
    let recipient_addr = to_addr(&recipient_sk);
    let transfer_stx_op = TransferStxOp {
        sender: spender_stx_addr.clone(),
        recipient: recipient_addr.clone(),
        transfered_ustx: 100_000,
        memo: vec![],
        // to be filled in
        txid: Txid([0u8; 32]),
        vtxindex: 0,
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash([0u8; 32]),
    };

    let mut spender_signer = BurnchainOpSigner::new(spender_sk.clone(), false);

    assert!(
        btc_regtest_controller.submit_operation(
            BlockstackOperationType::TransferStx(transfer_stx_op),
            &mut spender_signer,
            1
        ),
        "Transfer operation should submit successfully"
    );
    // should be elected in the same block as the transfer, so balances should be unchanged.
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    assert_eq!(get_balance(&http_origin, &spender_addr), 100300);
    assert_eq!(get_balance(&http_origin, &recipient_addr), 0);

    // this block should process the transfer
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    assert_eq!(get_balance(&http_origin, &spender_addr), 300);
    assert_eq!(get_balance(&http_origin, &recipient_addr), 100_000);
    assert_eq!(get_balance(&http_origin, &spender_2_addr), 100_300);

    // now let's do a pre-stx-op and a transfer op in the same burnchain block...
    // NOTE: bitcoind really doesn't want to return the utxo from the first op for some reason,
    //    so we have to get a little creative...

    // okay, let's send a pre-stx op.
    let pre_stx_op = PreStxOp {
        output: spender_2_stx_addr.clone(),
        // to be filled in
        txid: Txid([0u8; 32]),
        vtxindex: 0,
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash([0u8; 32]),
    };

    let mut miner_signer = Keychain::default(conf.node.seed.clone()).generate_op_signer();

    let pre_stx_tx = btc_regtest_controller
        .submit_manual(
            BlockstackOperationType::PreStx(pre_stx_op),
            &mut miner_signer,
            None,
        )
        .expect("Pre-stx operation should submit successfully");

    let transfer_stx_utxo = UTXO {
        txid: pre_stx_tx.txid(),
        vout: 1,
        script_pub_key: pre_stx_tx.output[1].script_pubkey.clone(),
        amount: pre_stx_tx.output[1].value,
    };

    // let's fire off our transfer op.
    let transfer_stx_op = TransferStxOp {
        sender: spender_2_stx_addr.clone(),
        recipient: recipient_addr.clone(),
        transfered_ustx: 100_000,
        memo: vec![],
        // to be filled in
        txid: Txid([0u8; 32]),
        vtxindex: 0,
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash([0u8; 32]),
    };

    let mut spender_signer = BurnchainOpSigner::new(spender_2_sk.clone(), false);

    btc_regtest_controller
        .submit_manual(
            BlockstackOperationType::TransferStx(transfer_stx_op),
            &mut spender_signer,
            Some(transfer_stx_utxo),
        )
        .expect("Transfer operation should submit successfully");

    // should be elected in the same block as the transfer, so balances should be unchanged.
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    assert_eq!(get_balance(&http_origin, &spender_addr), 300);
    assert_eq!(get_balance(&http_origin, &recipient_addr), 100_000);
    assert_eq!(get_balance(&http_origin, &spender_2_addr), 100_300);

    // should process the transfer
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    assert_eq!(get_balance(&http_origin, &spender_addr), 300);
    assert_eq!(get_balance(&http_origin, &recipient_addr), 200_000);
    assert_eq!(get_balance(&http_origin, &spender_2_addr), 300);

    channel.stop_chains_coordinator();
}

#[test]
#[ignore]
fn bitcoind_forking_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let (conf, miner_account) = neon_integration_test_conf();

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::new(conf.clone(), None);
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf);
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();

    thread::spawn(move || run_loop.start(0, None));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let mut sort_height = channel.get_sortitions_processed();
    eprintln!("Sort height: {}", sort_height);

    while sort_height < 210 {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        sort_height = channel.get_sortitions_processed();
        eprintln!("Sort height: {}", sort_height);
    }
    // let's query the miner's account nonce:

    eprintln!("Miner account: {}", miner_account);

    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.balance, 0);
    assert_eq!(account.nonce, 7);

    // okay, let's figure out the burn block we want to fork away.
    let burn_header_hash_to_fork = btc_regtest_controller.get_block_hash(206);
    btc_regtest_controller.invalidate_block(&burn_header_hash_to_fork);
    btc_regtest_controller.build_next_block(5);

    thread::sleep(Duration::from_secs(5));
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.balance, 0);
    assert_eq!(account.nonce, 2);

    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.balance, 0);
    // but we're able to keep on mining
    assert_eq!(account.nonce, 3);

    channel.stop_chains_coordinator();
}

#[test]
#[ignore]
fn microblock_integration_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let spender_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
    let spender_addr: PrincipalData = to_addr(&spender_sk).into();

    let (mut conf, miner_account) = neon_integration_test_conf();

    conf.initial_balances.push(InitialBalance {
        address: spender_addr.clone(),
        amount: 100300,
    });

    conf.node.mine_microblocks = true;
    conf.node.wait_time_for_microblocks = 30000;

    test_observer::spawn();

    conf.events_observers.push(EventObserverConfig {
        endpoint: format!("localhost:{}", test_observer::EVENT_OBSERVER_PORT),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::new(conf.clone(), None);
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();
    let client = reqwest::blocking::Client::new();

    let channel = run_loop.get_coordinator_channel().unwrap();

    thread::spawn(move || run_loop.start(0, None));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // let's query the miner's account nonce:

    info!("Miner account: {}", miner_account);
    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.balance, 0);
    assert_eq!(account.nonce, 1);

    // and our spender
    let account = get_account(&http_origin, &spender_addr);
    assert_eq!(account.balance, 100300);
    assert_eq!(account.nonce, 0);

    // okay, let's push a transaction that is marked microblock only!
    let recipient = StacksAddress::from_string(ADDR_4).unwrap();
    let tx = make_stacks_transfer_mblock_only(&spender_sk, 0, 1000, &recipient.into(), 1000);
    submit_tx(&http_origin, &tx);

    info!("Try to mine a microblock-only tx");

    // now let's mine a couple blocks, and then check the sender's nonce.
    // this one wakes up our node, so that it'll mine a microblock _and_ an anchor block.
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    // this one will contain the sortition from above anchor block,
    //    which *should* have also confirmed the microblock.
    info!("Wait for second block");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // I guess let's push another block for good measure?
    info!("Wait for third block");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    info!("Test microblock");

    // microblock must have bumped our nonce
    // and our spender
    let account = get_account(&http_origin, &spender_addr);
    assert_eq!(account.nonce, 1);

    // push another transaction that is marked microblock only
    let recipient = StacksAddress::from_string(ADDR_4).unwrap();
    let unconfirmed_tx_bytes =
        make_stacks_transfer_mblock_only(&spender_sk, 1, 1000, &recipient.into(), 1000);
    let unconfirmed_tx =
        StacksTransaction::consensus_deserialize(&mut &unconfirmed_tx_bytes[..]).unwrap();

    // TODO (hack) instantiate the sortdb in the burnchain
    let _ = btc_regtest_controller.sortdb_mut();

    // put it into a microblock
    let microblock = {
        let (consensus_hash, stacks_block) = get_tip_anchored_block(&conf);
        let tip_hash =
            StacksBlockHeader::make_index_block_hash(&consensus_hash, &stacks_block.block_hash());
        let privk =
            find_microblock_privkey(&conf, &stacks_block.header.microblock_pubkey_hash, 1024)
                .unwrap();
        let (mut chainstate, _) =
            StacksChainState::open(false, TESTNET_CHAIN_ID, &conf.get_chainstate_path()).unwrap();

        chainstate
            .reload_unconfirmed_state(&btc_regtest_controller.sortdb_ref().index_conn(), tip_hash)
            .unwrap();

        make_microblock(
            &privk,
            &mut chainstate,
            &btc_regtest_controller.sortdb_ref().index_conn(),
            consensus_hash,
            stacks_block,
            vec![unconfirmed_tx],
        )
    };

    let mut microblock_bytes = vec![];
    microblock
        .consensus_serialize(&mut microblock_bytes)
        .unwrap();

    // post it
    let path = format!("{}/v2/microblocks", &http_origin);
    let res: String = client
        .post(&path)
        .header("Content-Type", "application/octet-stream")
        .body(microblock_bytes.clone())
        .send()
        .unwrap()
        .json()
        .unwrap();

    assert_eq!(res, format!("{}", &microblock.block_hash()));

    eprintln!("\n\nBegin testing\nmicroblock: {:?}\n\n", &microblock);

    let account = get_account(&http_origin, &spender_addr);
    assert_eq!(account.nonce, 1);
    assert_eq!(account.balance, 98300);

    let path = format!("{}/v2/info", &http_origin);
    let tip_info = client
        .get(&path)
        .send()
        .unwrap()
        .json::<RPCPeerInfoData>()
        .unwrap();
    assert!(tip_info.stacks_tip_height >= 3);

    eprintln!(
        "{:#?}",
        client
            .get(&path)
            .send()
            .unwrap()
            .json::<serde_json::Value>()
            .unwrap()
    );

    let memtx_events = test_observer::get_memtxs();
    assert_eq!(memtx_events.len(), 1);
    assert_eq!(&memtx_events[0], &format!("0x{}", &bytes_to_hex(&tx)));

    // let's make sure the returned blocks all point at each other.
    let blocks_observed = test_observer::get_blocks();
    // we at least mined 5 blocks
    assert!(
        blocks_observed.len() >= 3,
        "Blocks observed {} should be >= 3",
        blocks_observed.len()
    );
    assert_eq!(blocks_observed.len() as u64, tip_info.stacks_tip_height);

    let burn_blocks_observed = test_observer::get_burn_blocks();
    let burn_blocks_with_burns: Vec<_> = burn_blocks_observed
        .into_iter()
        .filter(|block| block.get("burn_amount").unwrap().as_u64().unwrap() > 0)
        .collect();
    assert!(
        burn_blocks_with_burns.len() >= 3,
        "Burn block sortitions {} should be >= 3",
        burn_blocks_with_burns.len()
    );
    for burn_block in burn_blocks_with_burns {
        eprintln!("{}", burn_block);
    }

    let mut prior = None;
    for block in blocks_observed.iter() {
        let parent_index_hash = block
            .get("parent_index_block_hash")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let my_index_hash = block
            .get("index_block_hash")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        if let Some(ref previous_index_hash) = prior {
            assert_eq!(&parent_index_hash, previous_index_hash);
        }

        // make sure we have a burn_block_hash, burn_block_height and miner_txid

        let _burn_block_hash = block.get("burn_block_hash").unwrap().as_str().unwrap();

        let _burn_block_height = block.get("burn_block_height").unwrap().as_u64().unwrap();

        let _miner_txid = block.get("miner_txid").unwrap().as_str().unwrap();

        prior = Some(my_index_hash);
    }

    // we can query unconfirmed state from the microblock we announced
    let path = format!(
        "{}/v2/accounts/{}?proof=0&tip={}",
        &http_origin, &spender_addr, &tip_info.unanchored_tip
    );
    eprintln!("{:?}", &path);

    let res = client
        .get(&path)
        .send()
        .unwrap()
        .json::<AccountEntryResponse>()
        .unwrap();
    eprintln!("{:#?}", res);
    assert_eq!(res.nonce, 2);
    assert_eq!(u128::from_str_radix(&res.balance[2..], 16).unwrap(), 96300);

    // limited by chaining
    for next_nonce in 2..5 {
        // verify that the microblock miner can automatically pick up transactions
        debug!(
            "Try to send unconfirmed tx from {} to {}",
            &spender_addr, &recipient
        );
        let unconfirmed_tx_bytes = make_stacks_transfer_mblock_only(
            &spender_sk,
            next_nonce,
            1000,
            &recipient.into(),
            1000,
        );

        let path = format!("{}/v2/transactions", &http_origin);
        let res = client
            .post(&path)
            .header("Content-Type", "application/octet-stream")
            .body(unconfirmed_tx_bytes.clone())
            .send()
            .unwrap();
        eprintln!("{:#?}", res);
        if res.status().is_success() {
            let res: String = res.json().unwrap();
            assert_eq!(
                res,
                StacksTransaction::consensus_deserialize(&mut &unconfirmed_tx_bytes[..])
                    .unwrap()
                    .txid()
                    .to_string()
            );
        } else {
            eprintln!("{}", res.text().unwrap());
            panic!("");
        }

        // wait at least two p2p refreshes
        // so it can produce the microblock
        for i in 0..30 {
            debug!(
                "wait {} more seconds for microblock miner to find our transaction...",
                30 - i
            );
            sleep_ms(1000);
        }

        // we can query _new_ unconfirmed state from the microblock we announced
        let path = format!(
            "{}/v2/accounts/{}?proof=0&tip={}",
            &http_origin, &spender_addr, &tip_info.unanchored_tip
        );
        let res_text = client.get(&path).send().unwrap().text().unwrap();

        eprintln!("text of {}\n{}", &path, &res_text);

        let res = client
            .get(&path)
            .send()
            .unwrap()
            .json::<AccountEntryResponse>()
            .unwrap();
        eprintln!("{:?}", &path);
        eprintln!("{:#?}", res);

        // advanced!
        assert_eq!(res.nonce, next_nonce + 1);
        assert_eq!(
            u128::from_str_radix(&res.balance[2..], 16).unwrap(),
            (96300 - 2000 * (next_nonce - 1)) as u128
        );
    }

    test_observer::clear();
    channel.stop_chains_coordinator();
}

#[test]
#[ignore]
fn size_check_integration_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    // used to specify how long to wait in between blocks.
    //   we could _probably_ add a hook to the neon node that
    //   would remove some of the need for this
    let mut giant_contract = "(define-public (f) (ok 1))".to_string();
    for _i in 0..(1024 * 1024 + 500) {
        giant_contract.push_str(" ");
    }

    let spender_sks: Vec<_> = (0..10)
        .into_iter()
        .map(|_| StacksPrivateKey::new())
        .collect();
    let spender_addrs: Vec<PrincipalData> = spender_sks.iter().map(|x| to_addr(x).into()).collect();
    // make a bunch of txs that will only fit one per block.
    let txs: Vec<_> = spender_sks
        .iter()
        .enumerate()
        .map(|(ix, spender_sk)| {
            if ix % 2 == 0 {
                make_contract_publish(spender_sk, 0, 1049230, "large-0", &giant_contract)
            } else {
                let tx = make_contract_publish_microblock_only(
                    spender_sk,
                    0,
                    1049230,
                    "large-0",
                    &giant_contract,
                );
                let parsed_tx = StacksTransaction::consensus_deserialize(&mut &tx[..]).unwrap();
                debug!("Mine transaction {} in a microblock", &parsed_tx.txid());
                tx
            }
        })
        .collect();

    let (mut conf, miner_account) = neon_integration_test_conf();

    for spender_addr in spender_addrs.iter() {
        conf.initial_balances.push(InitialBalance {
            address: spender_addr.clone(),
            amount: 1049230,
        });
    }

    conf.node.mine_microblocks = true;
    conf.node.wait_time_for_microblocks = 30000;
    conf.node.microblock_frequency = 1000;

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::new(conf.clone(), None);
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf);
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();

    thread::spawn(move || run_loop.start(0, None));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // let's query the miner's account nonce:
    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.nonce, 1);
    assert_eq!(account.balance, 0);
    // and our potential spenders:

    for spender_addr in spender_addrs.iter() {
        let account = get_account(&http_origin, &spender_addr);
        assert_eq!(account.nonce, 0);
        assert_eq!(account.balance, 1049230);
    }

    for tx in txs.iter() {
        // okay, let's push a bunch of transactions that can only fit one per block!
        submit_tx(&http_origin, tx);
    }

    sleep_ms(60_000);

    // now let's mine a couple blocks, and then check the sender's nonce.
    //  at the end of mining three blocks, there should be _two_ transactions from the microblock
    //  only set that got mined (since the block before this one was empty, a microblock can
    //  be added),
    //  and _two_ transactions from the two anchor blocks that got mined (and processed)
    //
    // this one wakes up our node, so that it'll mine a microblock _and_ an anchor block.
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    // this one will contain the sortition from above anchor block,
    //    which *should* have also confirmed the microblock.
    sleep_ms(60_000);

    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // let's figure out how many micro-only and anchor-only txs got accepted
    //   by examining our account nonces:
    let mut micro_block_txs = 0;
    let mut anchor_block_txs = 0;
    for (ix, spender_addr) in spender_addrs.iter().enumerate() {
        let res = get_account(&http_origin, &spender_addr);
        if res.nonce == 1 {
            if ix % 2 == 0 {
                anchor_block_txs += 1;
            } else {
                micro_block_txs += 1;
            }
        } else if res.nonce != 0 {
            panic!("Spender address nonce incremented past 1");
        }
    }

    eprintln!(
        "anchor_block_txs: {}, micro_block_txs: {}",
        anchor_block_txs, micro_block_txs
    );

    assert_eq!(anchor_block_txs, 2);
    assert_eq!(micro_block_txs, 2);

    test_observer::clear();
    channel.stop_chains_coordinator();
}

#[test]
#[ignore]
fn pox_integration_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let spender_sk = StacksPrivateKey::new();
    let spender_addr: PrincipalData = to_addr(&spender_sk).into();

    let spender_2_sk = StacksPrivateKey::new();
    let spender_2_addr: PrincipalData = to_addr(&spender_2_sk).into();

    let spender_3_sk = StacksPrivateKey::new();
    let spender_3_addr: PrincipalData = to_addr(&spender_3_sk).into();

    let pox_pubkey = Secp256k1PublicKey::from_hex(
        "02f006a09b59979e2cb8449f58076152af6b124aa29b948a3714b8d5f15aa94ede",
    )
    .unwrap();
    let pox_pubkey_hash = bytes_to_hex(
        &Hash160::from_node_public_key(&pox_pubkey)
            .to_bytes()
            .to_vec(),
    );

    let pox_2_pubkey = Secp256k1PublicKey::from_private(&StacksPrivateKey::new());
    let pox_2_pubkey_hash = bytes_to_hex(
        &Hash160::from_node_public_key(&pox_2_pubkey)
            .to_bytes()
            .to_vec(),
    );

    let (mut conf, miner_account) = neon_integration_test_conf();

    test_observer::spawn();

    conf.events_observers.push(EventObserverConfig {
        endpoint: format!("localhost:{}", test_observer::EVENT_OBSERVER_PORT),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let first_bal = 6_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let second_bal = 2_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let third_bal = 2_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let stacked_bal = 1_000_000_000 * (core::MICROSTACKS_PER_STACKS as u128);

    conf.initial_balances.push(InitialBalance {
        address: spender_addr.clone(),
        amount: first_bal,
    });

    conf.initial_balances.push(InitialBalance {
        address: spender_2_addr.clone(),
        amount: second_bal,
    });

    conf.initial_balances.push(InitialBalance {
        address: spender_3_addr.clone(),
        amount: third_bal,
    });

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let mut burnchain_config = Burnchain::regtest(&conf.get_burn_db_path());

    // reward cycle length = 15, so 10 reward cycle slots + 5 prepare-phase burns
    let reward_cycle_len = 15;
    let prepare_phase_len = 5;
    let pox_constants = PoxConstants::new(
        reward_cycle_len,
        prepare_phase_len,
        4 * prepare_phase_len / 5,
        5,
        15,
        (16 * reward_cycle_len - 1).into(),
        (17 * reward_cycle_len).into(),
    );
    burnchain_config.pox_constants = pox_constants.clone();

    let mut btc_regtest_controller = BitcoinRegtestController::with_burnchain(
        conf.clone(),
        None,
        Some(burnchain_config.clone()),
    );
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();
    let client = reqwest::blocking::Client::new();
    let channel = run_loop.get_coordinator_channel().unwrap();

    thread::spawn(move || run_loop.start(0, Some(burnchain_config)));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let sort_height = channel.get_sortitions_processed();

    // let's query the miner's account nonce:
    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.balance, 0);
    assert_eq!(account.nonce, 1);

    // and our potential spenders:
    let account = get_account(&http_origin, &spender_addr);
    assert_eq!(account.balance, first_bal as u128);
    assert_eq!(account.nonce, 0);

    let tx = make_contract_call(
        &spender_sk,
        0,
        260,
        &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
        "pox",
        "stack-stx",
        &[
            Value::UInt(stacked_bal),
            execute(&format!(
                "{{ hashbytes: 0x{}, version: 0x00 }}",
                pox_pubkey_hash
            ))
            .unwrap()
            .unwrap(),
            Value::UInt(sort_height as u128),
            Value::UInt(6),
        ],
    );

    // okay, let's push that stacking transaction!
    submit_tx(&http_origin, &tx);

    let mut sort_height = channel.get_sortitions_processed();
    eprintln!("Sort height: {}", sort_height);
    test_observer::clear();

    // now let's mine until the next reward cycle starts ...
    while sort_height < ((14 * pox_constants.reward_cycle_length) + 1).into() {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        sort_height = channel.get_sortitions_processed();
        eprintln!("Sort height: {}", sort_height);
    }

    let blocks_observed = test_observer::get_blocks();
    assert!(
        blocks_observed.len() >= 2,
        "Blocks observed {} should be >= 2",
        blocks_observed.len()
    );

    // look up the return value of our stacking operation...
    let mut tested = false;
    for block in blocks_observed.iter() {
        if tested {
            break;
        }
        let transactions = block.get("transactions").unwrap().as_array().unwrap();
        for tx in transactions.iter() {
            let raw_tx = tx.get("raw_tx").unwrap().as_str().unwrap();
            if raw_tx == "0x00" {
                continue;
            }
            let tx_bytes = hex_bytes(&raw_tx[2..]).unwrap();
            let parsed = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
            if let TransactionPayload::ContractCall(contract_call) = parsed.payload {
                eprintln!("{}", contract_call.function_name.as_str());
                if contract_call.function_name.as_str() == "stack-stx" {
                    let raw_result = tx.get("raw_result").unwrap().as_str().unwrap();
                    let parsed =
                        <Value as ClarityDeserializable<Value>>::deserialize(&raw_result[2..]);
                    // should unlock at height 300 (we're in reward cycle 13, lockup starts in reward cycle
                    // 14, and goes for 6 blocks, so we unlock in reward cycle 20, which with a reward
                    // cycle length of 15 blocks, is a burnchain height of 300)
                    assert_eq!(parsed.to_string(),
                               format!("(ok (tuple (lock-amount u1000000000000000) (stacker {}) (unlock-burn-height u300)))",
                                       &spender_addr));
                    tested = true;
                }
            }
        }
    }

    assert!(tested, "Should have observed stack-stx transaction");

    // let's stack with spender 2 and spender 3...

    // now let's have sender_2 and sender_3 stack to pox addr 2 in
    //  two different txs, and make sure that they sum together in the reward set.

    let tx = make_contract_call(
        &spender_2_sk,
        0,
        260,
        &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
        "pox",
        "stack-stx",
        &[
            Value::UInt(stacked_bal / 2),
            execute(&format!(
                "{{ hashbytes: 0x{}, version: 0x00 }}",
                pox_2_pubkey_hash
            ))
            .unwrap()
            .unwrap(),
            Value::UInt(sort_height as u128),
            Value::UInt(6),
        ],
    );

    // okay, let's push that stacking transaction!
    submit_tx(&http_origin, &tx);

    let tx = make_contract_call(
        &spender_3_sk,
        0,
        260,
        &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
        "pox",
        "stack-stx",
        &[
            Value::UInt(stacked_bal / 2),
            execute(&format!(
                "{{ hashbytes: 0x{}, version: 0x00 }}",
                pox_2_pubkey_hash
            ))
            .unwrap()
            .unwrap(),
            Value::UInt(sort_height as u128),
            Value::UInt(6),
        ],
    );

    submit_tx(&http_origin, &tx);

    // mine until the end of the current reward cycle.
    sort_height = channel.get_sortitions_processed();
    while sort_height < ((15 * pox_constants.reward_cycle_length) - 1).into() {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        sort_height = channel.get_sortitions_processed();
        eprintln!("Sort height: {}", sort_height);
    }

    // we should have received _no_ Bitcoin commitments, because the pox participation threshold
    //   was not met!
    let utxos = btc_regtest_controller.get_all_utxos(&pox_pubkey);
    eprintln!("Got UTXOs: {}", utxos.len());
    assert_eq!(
        utxos.len(),
        0,
        "Should have received no outputs during PoX reward cycle"
    );

    // before sunset
    // mine until the end of the next reward cycle,
    //   the participation threshold now should be met.
    while sort_height < ((16 * pox_constants.reward_cycle_length) - 1).into() {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        sort_height = channel.get_sortitions_processed();
        eprintln!("Sort height: {}", sort_height);
    }

    // we should have received _seven_ Bitcoin commitments, because our commitment was 7 * threshold
    let utxos = btc_regtest_controller.get_all_utxos(&pox_pubkey);

    eprintln!("Got UTXOs: {}", utxos.len());
    assert_eq!(
        utxos.len(),
        7,
        "Should have received three outputs during PoX reward cycle"
    );

    // we should have received _three_ Bitcoin commitments to pox_2_pubkey, because our commitment was 3 * threshold
    //   note: that if the reward set "summing" isn't implemented, this recipient would only have received _2_ slots,
    //         because each `stack-stx` call only received enough to get 1 slot individually.
    let utxos = btc_regtest_controller.get_all_utxos(&pox_2_pubkey);

    eprintln!("Got UTXOs: {}", utxos.len());
    assert_eq!(
        utxos.len(),
        7,
        "Should have received three outputs during PoX reward cycle"
    );

    // get the canonical chain tip
    let path = format!("{}/v2/info", &http_origin);
    let tip_info = client
        .get(&path)
        .send()
        .unwrap()
        .json::<RPCPeerInfoData>()
        .unwrap();

    eprintln!("Stacks tip is now {}", tip_info.stacks_tip_height);
    assert_eq!(tip_info.stacks_tip_height, 36);

    // now let's mine into the sunset
    while sort_height < ((17 * pox_constants.reward_cycle_length) - 1).into() {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        sort_height = channel.get_sortitions_processed();
        eprintln!("Sort height: {}", sort_height);
    }

    // get the canonical chain tip
    let path = format!("{}/v2/info", &http_origin);
    let tip_info = client
        .get(&path)
        .send()
        .unwrap()
        .json::<RPCPeerInfoData>()
        .unwrap();

    eprintln!("Stacks tip is now {}", tip_info.stacks_tip_height);
    assert_eq!(tip_info.stacks_tip_height, 51);

    let utxos = btc_regtest_controller.get_all_utxos(&pox_2_pubkey);

    // should receive more rewards during this cycle...
    eprintln!("Got UTXOs: {}", utxos.len());
    assert_eq!(
        utxos.len(),
        14,
        "Should have received more outputs during the sunsetting PoX reward cycle"
    );

    // and after sunset
    while sort_height < ((18 * pox_constants.reward_cycle_length) - 1).into() {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        sort_height = channel.get_sortitions_processed();
        eprintln!("Sort height: {}", sort_height);
    }

    let utxos = btc_regtest_controller.get_all_utxos(&pox_2_pubkey);

    // should *not* receive more rewards during the after sunset cycle...
    eprintln!("Got UTXOs: {}", utxos.len());
    assert_eq!(
        utxos.len(),
        14,
        "Should have received no more outputs after sunset PoX reward cycle"
    );

    // should have progressed the chain, though!
    // get the canonical chain tip
    let path = format!("{}/v2/info", &http_origin);
    let tip_info = client
        .get(&path)
        .send()
        .unwrap()
        .json::<RPCPeerInfoData>()
        .unwrap();

    eprintln!("Stacks tip is now {}", tip_info.stacks_tip_height);
    assert_eq!(tip_info.stacks_tip_height, 66);

    test_observer::clear();
    channel.stop_chains_coordinator();
}

enum Signal {
    BootstrapNodeReady,
    ReplicatingAttachmentsStartTest1,
    ReplicatingAttachmentsCheckTest1(u64),
    ReplicatingAttachmentsStartTest2,
    ReplicatingAttachmentsCheckTest2(u64),
}

#[test]
#[ignore]
fn atlas_integration_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let user_1 = StacksPrivateKey::new();
    let initial_balance_user_1 = InitialBalance {
        address: to_addr(&user_1).into(),
        amount: 1_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64),
    };

    // Prepare the config of the bootstrap node
    let (mut conf_bootstrap_node, _) = neon_integration_test_conf();
    let bootstrap_node_public_key = {
        let keychain = Keychain::default(conf_bootstrap_node.node.seed.clone());
        let mut pk = keychain.generate_op_signer().get_public_key();
        pk.set_compressed(true);
        pk.to_hex()
    };
    conf_bootstrap_node
        .initial_balances
        .push(initial_balance_user_1.clone());

    // Prepare the config of the follower node
    let (mut conf_follower_node, _) = neon_integration_test_conf();
    let bootstrap_node_url = format!(
        "{}@{}",
        bootstrap_node_public_key, conf_bootstrap_node.node.p2p_bind
    );
    conf_follower_node.node.set_bootstrap_node(
        Some(bootstrap_node_url),
        conf_follower_node.burnchain.chain_id,
        conf_follower_node.burnchain.peer_version,
    );
    conf_follower_node.node.miner = false;
    conf_follower_node
        .initial_balances
        .push(initial_balance_user_1.clone());
    conf_follower_node
        .events_observers
        .push(EventObserverConfig {
            endpoint: format!("localhost:{}", test_observer::EVENT_OBSERVER_PORT),
            events_keys: vec![EventKeyType::AnyEvent],
        });

    // Our 2 nodes will share the bitcoind node
    let mut btcd_controller = BitcoinCoreController::new(conf_bootstrap_node.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let (bootstrap_node_tx, bootstrap_node_rx) = mpsc::channel();
    let (follower_node_tx, follower_node_rx) = mpsc::channel();

    let bootstrap_node_thread = thread::spawn(move || {
        let burnchain_config = Burnchain::regtest(&conf_bootstrap_node.get_burn_db_path());

        let mut btc_regtest_controller = BitcoinRegtestController::with_burnchain(
            conf_bootstrap_node.clone(),
            None,
            Some(burnchain_config.clone()),
        );
        let http_origin = format!("http://{}", &conf_bootstrap_node.node.rpc_bind);

        btc_regtest_controller.bootstrap_chain(201);

        eprintln!("Chain bootstrapped...");

        let mut run_loop = neon::RunLoop::new(conf_bootstrap_node.clone());
        let blocks_processed = run_loop.get_blocks_processed_arc();
        let client = reqwest::blocking::Client::new();
        let channel = run_loop.get_coordinator_channel().unwrap();

        thread::spawn(move || run_loop.start(0, Some(burnchain_config)));

        // give the run loop some time to start up!
        wait_for_runloop(&blocks_processed);

        // first block wakes up the run loop
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

        // first block will hold our VRF registration
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

        // second block will be the first mined Stacks block
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

        // Let's setup the follower now.
        follower_node_tx
            .send(Signal::BootstrapNodeReady)
            .expect("Unable to send signal");

        match bootstrap_node_rx.recv() {
            Ok(Signal::ReplicatingAttachmentsStartTest1) => {
                println!("Follower node is ready...");
            }
            _ => panic!("Bootstrap node could nod boot. Aborting test."),
        };

        // Let's publish a (1) namespace-preorder, (2) namespace-reveal and (3) name-import in this mempool

        // (define-public (namespace-preorder (hashed-salted-namespace (buff 20))
        //                            (stx-to-burn uint))
        let namespace = "passport";
        let salt = "some-salt";
        let salted_namespace = format!("{}{}", namespace, salt);
        let hashed_namespace = Hash160::from_data(salted_namespace.as_bytes());
        let tx_1 = make_contract_call(
            &user_1,
            0,
            260,
            &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
            "bns",
            "namespace-preorder",
            &[
                Value::buff_from(hashed_namespace.to_bytes().to_vec()).unwrap(),
                Value::UInt(1000),
            ],
        );

        let path = format!("{}/v2/transactions", &http_origin);
        let res = client
            .post(&path)
            .header("Content-Type", "application/octet-stream")
            .body(tx_1.clone())
            .send()
            .unwrap();
        eprintln!("{:#?}", res);
        if res.status().is_success() {
            let res: String = res.json().unwrap();
            assert_eq!(
                res,
                StacksTransaction::consensus_deserialize(&mut &tx_1[..])
                    .unwrap()
                    .txid()
                    .to_string()
            );
        } else {
            eprintln!("{}", res.text().unwrap());
            panic!("");
        }

        // (define-public (namespace-reveal (namespace (buff 20))
        //                                  (namespace-salt (buff 20))
        //                                  (p-func-base uint)
        //                                  (p-func-coeff uint)
        //                                  (p-func-b1 uint)
        //                                  (p-func-b2 uint)
        //                                  (p-func-b3 uint)
        //                                  (p-func-b4 uint)
        //                                  (p-func-b5 uint)
        //                                  (p-func-b6 uint)
        //                                  (p-func-b7 uint)
        //                                  (p-func-b8 uint)
        //                                  (p-func-b9 uint)
        //                                  (p-func-b10 uint)
        //                                  (p-func-b11 uint)
        //                                  (p-func-b12 uint)
        //                                  (p-func-b13 uint)
        //                                  (p-func-b14 uint)
        //                                  (p-func-b15 uint)
        //                                  (p-func-b16 uint)
        //                                  (p-func-non-alpha-discount uint)
        //                                  (p-func-no-vowel-discount uint)
        //                                  (lifetime uint)
        //                                  (namespace-import principal))
        let tx_2 = make_contract_call(
            &user_1,
            1,
            1000,
            &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
            "bns",
            "namespace-reveal",
            &[
                Value::buff_from(namespace.as_bytes().to_vec()).unwrap(),
                Value::buff_from(salt.as_bytes().to_vec()).unwrap(),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1),
                Value::UInt(1000),
                Value::Principal(initial_balance_user_1.address.clone()),
            ],
        );

        let path = format!("{}/v2/transactions", &http_origin);
        let res = client
            .post(&path)
            .header("Content-Type", "application/octet-stream")
            .body(tx_2.clone())
            .send()
            .unwrap();
        eprintln!("{:#?}", res);
        if res.status().is_success() {
            let res: String = res.json().unwrap();
            assert_eq!(
                res,
                StacksTransaction::consensus_deserialize(&mut &tx_2[..])
                    .unwrap()
                    .txid()
                    .to_string()
            );
        } else {
            eprintln!("{}", res.text().unwrap());
            panic!("");
        }

        // (define-public (name-import (namespace (buff 20))
        //                             (name (buff 48))
        //                             (zonefile-hash (buff 20)))
        let zonefile_hex = "facade00";
        let hashed_zonefile = Hash160::from_data(&hex_bytes(zonefile_hex).unwrap());
        let tx_3 = make_contract_call(
            &user_1,
            2,
            500,
            &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
            "bns",
            "name-import",
            &[
                Value::buff_from(namespace.as_bytes().to_vec()).unwrap(),
                Value::buff_from("johndoe".as_bytes().to_vec()).unwrap(),
                Value::Principal(to_addr(&user_1).into()),
                Value::buff_from(hashed_zonefile.as_bytes().to_vec()).unwrap(),
            ],
        );

        let body = {
            let content = PostTransactionRequestBody {
                tx: bytes_to_hex(&tx_3),
                attachment: Some(zonefile_hex.to_string()),
            };
            serde_json::to_vec(&json!(content)).unwrap()
        };

        let path = format!("{}/v2/transactions", &http_origin);
        let res = client
            .post(&path)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .unwrap();
        eprintln!("{:#?}", res);
        if !res.status().is_success() {
            eprintln!("{}", res.text().unwrap());
            panic!("");
        }

        // From there, let's mine these transaction, and build an extra block.
        let mut sort_height = channel.get_sortitions_processed();
        eprintln!("=> Sort height: {}", sort_height);
        let few_blocks = sort_height + 1 + 1;

        // now let's mine until the next reward cycle starts ...
        while sort_height < few_blocks {
            next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
            sort_height = channel.get_sortitions_processed();
            eprintln!("Sort height: {}", sort_height);
        }

        // Then check that the follower is correctly replicating the attachment
        follower_node_tx
            .send(Signal::ReplicatingAttachmentsCheckTest1(sort_height))
            .expect("Unable to send signal");

        match bootstrap_node_rx.recv() {
            Ok(Signal::ReplicatingAttachmentsStartTest2) => {
                println!("Follower node is ready...");
            }
            _ => panic!("Bootstrap node could nod boot. Aborting test."),
        };

        // From there, let's mine these transaction, and build an extra block.
        let mut sort_height = channel.get_sortitions_processed();
        eprintln!("=> Sort height: {}", sort_height);
        let few_blocks = sort_height + 1 + 1;

        while sort_height < few_blocks {
            next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
            sort_height = channel.get_sortitions_processed();
            eprintln!("Sort height: {}", sort_height);
        }

        // Poll GET v2/attachments/<attachment-hash>
        for i in 1..10 {
            let mut attachments_did_sync = false;
            let mut timeout = 120;
            while attachments_did_sync != true {
                let zonefile_hex = hex_bytes(&format!("facade0{}", i)).unwrap();
                let hashed_zonefile = Hash160::from_data(&zonefile_hex);
                let path = format!(
                    "{}/v2/attachments/{}",
                    &http_origin,
                    hashed_zonefile.to_hex()
                );
                let res = client
                    .get(&path)
                    .header("Content-Type", "application/json")
                    .send()
                    .unwrap();
                eprintln!("{:#?}", res);
                if res.status().is_success() {
                    let attachment_response: GetAttachmentResponse = res.json().unwrap();
                    assert_eq!(attachment_response.attachment.content, zonefile_hex);
                    attachments_did_sync = true;
                } else {
                    timeout -= 1;
                    if timeout == 0 {
                        panic!("Failed syncing 9 attachments between 2 neon runloops within 60s - Something is wrong");
                    }
                    eprintln!("Attachment {} not sync'd yet", bytes_to_hex(&zonefile_hex));
                    thread::sleep(Duration::from_millis(1000));
                }
            }
        }

        // Then check that the follower is correctly replicating the attachment
        follower_node_tx
            .send(Signal::ReplicatingAttachmentsCheckTest2(sort_height))
            .expect("Unable to send signal");

        channel.stop_chains_coordinator();
    });

    // Start the attached observer
    test_observer::spawn();

    // The bootstrap node mined a few blocks and is ready, let's setup this node.
    match follower_node_rx.recv() {
        Ok(Signal::BootstrapNodeReady) => {
            println!("Booting follower node...");
        }
        _ => panic!("Bootstrap node could nod boot. Aborting test."),
    };

    let burnchain_config = Burnchain::regtest(&conf_follower_node.get_burn_db_path());
    let http_origin = format!("http://{}", &conf_follower_node.node.rpc_bind);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf_follower_node.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();
    let client = reqwest::blocking::Client::new();
    let channel = run_loop.get_coordinator_channel().unwrap();

    thread::spawn(move || run_loop.start(0, Some(burnchain_config)));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // Follower node is ready, the bootstrap node will now handover
    bootstrap_node_tx
        .send(Signal::ReplicatingAttachmentsStartTest1)
        .expect("Unable to send signal");

    // The bootstrap node published and mined a transaction that includes an attachment.
    // Lets observe the attachments replication kicking in.
    let target_height = match follower_node_rx.recv() {
        Ok(Signal::ReplicatingAttachmentsCheckTest1(target_height)) => target_height,
        _ => panic!("Bootstrap node could nod boot. Aborting test."),
    };

    let mut sort_height = channel.get_sortitions_processed();
    while sort_height < target_height {
        wait_for_runloop(&blocks_processed);
        sort_height = channel.get_sortitions_processed();
    }

    // Now wait for the node to sync the attachment
    let mut attachments_did_sync = false;
    let mut timeout = 60;
    while attachments_did_sync != true {
        let zonefile_hex = "facade00";
        let hashed_zonefile = Hash160::from_data(&hex_bytes(zonefile_hex).unwrap());
        let path = format!(
            "{}/v2/attachments/{}",
            &http_origin,
            hashed_zonefile.to_hex()
        );
        let res = client
            .get(&path)
            .header("Content-Type", "application/json")
            .send()
            .unwrap();
        eprintln!("{:#?}", res);
        if res.status().is_success() {
            eprintln!("Success syncing attachment - {}", res.text().unwrap());
            attachments_did_sync = true;
        } else {
            timeout -= 1;
            if timeout == 0 {
                panic!("Failed syncing 1 attachments between 2 neon runloops within 60s - Something is wrong");
            }
            eprintln!("Attachment {} not sync'd yet", zonefile_hex);
            thread::sleep(Duration::from_millis(1000));
        }
    }

    // Test 2: 9 transactions are posted to the follower.
    // We want to make sure that the miner is able to
    // 1) mine these transactions
    // 2) retrieve the attachments staged on the follower node.
    // 3) ensure that the follower is also instanciating the attachments after
    // executing the transactions, once mined.
    let namespace = "passport";
    for i in 1..10 {
        let user = StacksPrivateKey::new();
        let zonefile_hex = format!("facade0{}", i);
        let hashed_zonefile = Hash160::from_data(&hex_bytes(&zonefile_hex).unwrap());
        let name = format!("johndoe{}", i);
        let tx = make_contract_call(
            &user_1,
            2 + i,
            500,
            &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
            "bns",
            "name-import",
            &[
                Value::buff_from(namespace.as_bytes().to_vec()).unwrap(),
                Value::buff_from(name.as_bytes().to_vec()).unwrap(),
                Value::Principal(to_addr(&user).into()),
                Value::buff_from(hashed_zonefile.as_bytes().to_vec()).unwrap(),
            ],
        );

        let body = {
            let content = PostTransactionRequestBody {
                tx: bytes_to_hex(&tx),
                attachment: Some(zonefile_hex.to_string()),
            };
            serde_json::to_vec(&json!(content)).unwrap()
        };

        let path = format!("{}/v2/transactions", &http_origin);
        let res = client
            .post(&path)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .unwrap();
        eprintln!("{:#?}", res);
        if !res.status().is_success() {
            eprintln!("{}", res.text().unwrap());
            panic!("");
        }
    }

    bootstrap_node_tx
        .send(Signal::ReplicatingAttachmentsStartTest2)
        .expect("Unable to send signal");

    let target_height = match follower_node_rx.recv() {
        Ok(Signal::ReplicatingAttachmentsCheckTest2(target_height)) => target_height,
        _ => panic!("Bootstrap node could not boot. Aborting test."),
    };

    let mut sort_height = channel.get_sortitions_processed();
    while sort_height < target_height {
        wait_for_runloop(&blocks_processed);
        sort_height = channel.get_sortitions_processed();
    }

    // Poll GET v2/attachments/<attachment-hash>
    for i in 1..10 {
        let mut attachments_did_sync = false;
        let mut timeout = 60;
        while attachments_did_sync != true {
            let zonefile_hex = hex_bytes(&format!("facade0{}", i)).unwrap();
            let hashed_zonefile = Hash160::from_data(&zonefile_hex);
            let path = format!(
                "{}/v2/attachments/{}",
                &http_origin,
                hashed_zonefile.to_hex()
            );
            let res = client
                .get(&path)
                .header("Content-Type", "application/json")
                .send()
                .unwrap();
            eprintln!("{:#?}", res);
            if res.status().is_success() {
                let attachment_response: GetAttachmentResponse = res.json().unwrap();
                assert_eq!(attachment_response.attachment.content, zonefile_hex);
                attachments_did_sync = true;
            } else {
                timeout -= 1;
                if timeout == 0 {
                    panic!("Failed syncing 9 attachments between 2 neon runloops within 60s - Something is wrong");
                }
                eprintln!("Attachment {} not sync'd yet", bytes_to_hex(&zonefile_hex));
                thread::sleep(Duration::from_millis(1000));
            }
        }
    }

    // Ensure that we the attached sidecar was able to receive a total of 10 attachments
    assert_eq!(test_observer::get_attachments().len(), 10);
    test_observer::clear();
    channel.stop_chains_coordinator();

    bootstrap_node_thread.join().unwrap();
}
