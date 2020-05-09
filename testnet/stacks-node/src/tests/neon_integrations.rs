use super::{make_stacks_transfer_mblock_only, SK_1, ADDR_4, to_addr,
            make_contract_publish, make_contract_publish_microblock_only};
use stacks::burnchains::Address;
use stacks::chainstate::stacks::{
    StacksTransaction, StacksPrivateKey, StacksAddress };
use stacks::net::StacksMessageCodec;
use stacks::vm::types::PrincipalData;

use crate::{
    neon, Config, Keychain, config::InitialBalance, BitcoinRegtestController, BurnchainController,
};
use stacks::net::AccountEntryResponse;
use super::bitcoin_regtest::BitcoinCoreController;
use std::{thread, env};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};


fn neon_integration_test_conf() -> (Config, StacksAddress) {
    let mut conf = super::new_test_conf();

    let keychain = Keychain::default(conf.node.seed.clone());

    conf.node.miner = true;

    conf.burnchain.username = Some("neon-tester".into());
    conf.burnchain.password = Some("neon-tester-pass".into());
    conf.burnchain.peer_host = "127.0.0.1".into();
    conf.burnchain.local_mining_public_key = Some(keychain.generate_op_signer()
        .get_public_key().to_hex());
    conf.burnchain.commit_anchor_block_within = 0;

    let miner_account = keychain.origin_address().unwrap();

    (conf, miner_account)
}

const PANIC_TIMEOUT_SECS: u64 = 60;
fn next_block_and_wait(btc_controller: &mut BitcoinRegtestController, blocks_processed: &Arc<AtomicU64>) {
    let current = blocks_processed.load(Ordering::SeqCst);
    eprintln!("Issuing block, waiting for bump");
    btc_controller.build_next_block(1);
    let start = std::time::Instant::now();
    while blocks_processed.load(Ordering::SeqCst) <= current {
        if start.elapsed() > std::time::Duration::from_secs(PANIC_TIMEOUT_SECS) {
            panic!("Timed out waiting for block to process");
        }
        thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn wait_for_runloop(blocks_processed: &Arc<AtomicU64>) {
    let start = std::time::Instant::now();
    while blocks_processed.load(Ordering::SeqCst) == 0 {
        if start.elapsed() > std::time::Duration::from_secs(PANIC_TIMEOUT_SECS) {
            panic!("Timed out waiting for run loop to start");
        }
        thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[test]
#[ignore]
fn bitcoind_integration_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return
    }

    let (conf, miner_account) = neon_integration_test_conf();

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller.start_bitcoind().map_err(|_e| ()).expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::new(conf.clone());
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf);
    let blocks_processed = run_loop.get_blocks_processed_arc();
    let client = reqwest::blocking::Client::new();

    thread::spawn(move || {
        run_loop.start(0)
    });

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

    let path = format!("{}/v2/accounts/{}?proof=0",
                       &http_origin, &miner_account);
    eprintln!("Test: GET {}", path);
    let res = client.get(&path).send().unwrap().json::<AccountEntryResponse>().unwrap();
    eprintln!("Response: {:#?}", res);
    assert_eq!(u128::from_str_radix(&res.balance[2..], 16).unwrap(), 0);
    assert_eq!(res.nonce, 1);
}

#[test]
#[ignore]
fn microblock_integration_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return
    }

    let spender_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
    let spender_addr: PrincipalData = to_addr(&spender_sk).into();

    let (mut conf, miner_account) = neon_integration_test_conf();

    conf.initial_balances.push(InitialBalance { 
        address: spender_addr.clone(),
        amount: 100300
    });

    conf.node.mine_microblocks = true;

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller.start_bitcoind().map_err(|_e| ()).expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::new(conf.clone());
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf);
    let blocks_processed = run_loop.get_blocks_processed_arc();
    let client = reqwest::blocking::Client::new();

    thread::spawn(move || {
        run_loop.start(0)
    });

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

    let path = format!("{}/v2/accounts/{}?proof=0",
                       &http_origin, &miner_account);
    eprintln!("Test: GET {}", path);
    let res = client.get(&path).send().unwrap().json::<AccountEntryResponse>().unwrap();
    assert_eq!(u128::from_str_radix(&res.balance[2..], 16).unwrap(), 0);
    assert_eq!(res.nonce, 1);

    // and our spender

    let path = format!("{}/v2/accounts/{}?proof=0",
                       &http_origin, &spender_addr);
    let res = client.get(&path).send().unwrap().json::<AccountEntryResponse>().unwrap();
    assert_eq!(u128::from_str_radix(&res.balance[2..], 16).unwrap(), 100300);
    assert_eq!(res.nonce, 0);

    // okay, let's push a transaction that is marked microblock only!
    let recipient = StacksAddress::from_string(ADDR_4).unwrap();
    let tx = make_stacks_transfer_mblock_only(&spender_sk, 0, 1000, &recipient.into(), 1000);

    let path = format!("{}/v2/transactions", &http_origin);
    let res: String = client.post(&path)
        .header("Content-Type", "application/octet-stream")
        .body(tx.clone())
        .send()
        .unwrap()
        .json()
        .unwrap();

    assert_eq!(res, StacksTransaction::consensus_deserialize(&mut &tx[..]).unwrap().txid().to_string());

    // now let's mine a couple blocks, and then check the sender's nonce.
    // this one wakes up our node, so that it'll mine a microblock _and_ an anchor block.
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    // this one will contain the sortition from above anchor block,
    //    which *should* have also confirmed the microblock.
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);


    let path = format!("{}/v2/accounts/{}?proof=0",
                       &http_origin, &spender_addr);
    let res = client.get(&path).send().unwrap().json::<AccountEntryResponse>().unwrap();
    eprintln!("{:#?}", res);
    assert_eq!(res.nonce, 1);
    assert_eq!(u128::from_str_radix(&res.balance[2..], 16).unwrap(), 98300);
}

#[test]
#[ignore]
fn size_check_integration_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return
    }

    // used to specify how long to wait in between blocks.
    //   we could _probably_ add a hook to the neon node that
    //   would remove some of the need for this
    let mut giant_contract = "(define-public (f) (ok 1))".to_string();
    for _i in 0..(1024*1024 + 500) {
        giant_contract.push_str(" ");
    }

    let spender_sks: Vec<_> = (0..10).into_iter().map(|_| StacksPrivateKey::new()).collect();
    let spender_addrs: Vec<PrincipalData> =
        spender_sks.iter().map(|x| to_addr(x).into()).collect();
    // make a bunch of txs that will only fit one per block.
    let txs: Vec<_> = spender_sks.iter().enumerate().map(
        |(ix, spender_sk)| {
            if ix % 2 == 0 {
                make_contract_publish(spender_sk, 0, 1049230, "large-0",
                                      &giant_contract)
            } else {
                make_contract_publish_microblock_only(
                    spender_sk, 0, 1049230, "large-0",
                    &giant_contract)
            }
        }).collect();

    let (mut conf, miner_account) = neon_integration_test_conf();

    for spender_addr in spender_addrs.iter() {
        conf.initial_balances.push(InitialBalance { 
            address: spender_addr.clone(),
            amount: 1049230
        });
    }

    conf.node.mine_microblocks = true;

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller.start_bitcoind().map_err(|_e| ()).expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::new(conf.clone());
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf);
    let blocks_processed = run_loop.get_blocks_processed_arc();
    let client = reqwest::blocking::Client::new();

    thread::spawn(move || {
        run_loop.start(0)
    });

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

    let path = format!("{}/v2/accounts/{}?proof=0",
                       &http_origin, &miner_account);
    eprintln!("Test: GET {}", path);
    let res = client.get(&path).send().unwrap().json::<AccountEntryResponse>().unwrap();
    assert_eq!(u128::from_str_radix(&res.balance[2..], 16).unwrap(), 0);
    assert_eq!(res.nonce, 1);

    // and our potential spenders:

    for spender_addr in spender_addrs.iter() {
        let path = format!("{}/v2/accounts/{}?proof=0",
                           &http_origin, spender_addr);
        let res = client.get(&path).send().unwrap().json::<AccountEntryResponse>().unwrap();
        assert_eq!(u128::from_str_radix(&res.balance[2..], 16).unwrap(), 1049230);
        assert_eq!(res.nonce, 0);
    }

    for tx in txs.iter() {
        // okay, let's push a bunch of transactions that can only fit one per block!
        let path = format!("{}/v2/transactions", &http_origin);
        let res = client.post(&path)
            .header("Content-Type", "application/octet-stream")
            .body(tx.clone())
            .send()
            .unwrap();
        eprintln!("{:#?}", res);
        if res.status().is_success() {
            let res: String = res
                .json()
                .unwrap();
            assert_eq!(res, StacksTransaction::consensus_deserialize(&mut &tx[..]).unwrap().txid().to_string());
        } else {
            eprintln!("{}", res.text().unwrap());
            panic!("");
        }
    }

    // now let's mine a couple blocks, and then check the sender's nonce.
    //  at the end of mining three blocks, there should be _one_ transaction from the microblock
    //  only set that got mined (since the block before this one was empty, a microblock can
    //  be added),
    //  and _two_ transactions from the two anchor blocks that got mined (and processed)
    //
    // this one wakes up our node, so that it'll mine a microblock _and_ an anchor block.
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    // this one will contain the sortition from above anchor block,
    //    which *should* have also confirmed the microblock.
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // let's figure out how many micro-only and anchor-only txs got accepted
    //   by examining our account nonces:
    let mut micro_block_txs = 0;
    let mut anchor_block_txs = 0;
    for (ix, spender_addr) in spender_addrs.iter().enumerate() {
        let path = format!("{}/v2/accounts/{}?proof=0",
                           &http_origin, spender_addr);
        let res = client.get(&path).send().unwrap().json::<AccountEntryResponse>().unwrap();
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

    assert_eq!(anchor_block_txs, 2);
    assert_eq!(micro_block_txs, 1);
}
