use super::{make_stacks_transfer_mblock_only, SK_1, ADDR_4, to_addr};
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

#[test]
#[ignore]
fn bitcoind_integration_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return
    }

    // used to specify how long to wait in between blocks.
    //   we could _probably_ add a hook to the neon node that
    //   would remove some of the need for this
    let gap_ms = 5_000;

    let (conf, miner_account) = neon_integration_test_conf();

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller.start_bitcoind().map_err(|_e| ()).expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::new(conf.clone());
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    btc_regtest_controller.bootstrap_chain();

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf);
    let client = reqwest::blocking::Client::new();

    thread::spawn(move || {
        run_loop.start(0)
    });

    // give the run loop some time to start up!
    thread::sleep(std::time::Duration::from_millis(gap_ms));

    // first block wakes up the run loop
    btc_regtest_controller.build_next_block(1);
    eprintln!("== REGTEST BLOCK MINED == ");
    // give the run loop some time to figure things out!
    thread::sleep(std::time::Duration::from_millis(gap_ms));

    // first block will hold our VRF registration
    btc_regtest_controller.build_next_block(1);
    eprintln!("== REGTEST BLOCK MINED == ");
    // give the run loop some time to figure things out!
    thread::sleep(std::time::Duration::from_millis(gap_ms));

    // second block will be the first mined Stacks block
    btc_regtest_controller.build_next_block(1);
    eprintln!("== REGTEST BLOCK MINED == ");
    thread::sleep(std::time::Duration::from_millis(gap_ms));

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

    // used to specify how long to wait in between blocks.
    //   we could _probably_ add a hook to the neon node that
    //   would remove some of the need for this
    let gap_ms = 5_000;

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

    btc_regtest_controller.bootstrap_chain();

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf);
    let client = reqwest::blocking::Client::new();

    thread::spawn(move || {
        run_loop.start(0)
    });

    // give the run loop some time to start up!
    thread::sleep(std::time::Duration::from_millis(gap_ms));

    // first block wakes up the run loop
    btc_regtest_controller.build_next_block(1);
    eprintln!("== REGTEST BLOCK MINED == ");
    // give the run loop some time to figure things out!
    thread::sleep(std::time::Duration::from_millis(gap_ms));

    // first block will hold our VRF registration
    btc_regtest_controller.build_next_block(1);
    eprintln!("== REGTEST BLOCK MINED == ");
    // give the run loop some time to figure things out!
    thread::sleep(std::time::Duration::from_millis(gap_ms));

    // second block will be the first mined Stacks block
    btc_regtest_controller.build_next_block(1);
    eprintln!("== REGTEST BLOCK MINED == ");
    thread::sleep(std::time::Duration::from_millis(gap_ms));

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
    btc_regtest_controller.build_next_block(1);
    eprintln!("== REGTEST BLOCK MINED == ");
    thread::sleep(std::time::Duration::from_millis(gap_ms));
    // this one will contain the sortition from above anchor block,
    //    which *should* have also confirmed the microblock.
    btc_regtest_controller.build_next_block(1);
    eprintln!("== REGTEST BLOCK MINED == ");
    thread::sleep(std::time::Duration::from_millis(gap_ms));


    let path = format!("{}/v2/accounts/{}?proof=0",
                       &http_origin, &spender_addr);
    let res = client.get(&path).send().unwrap().json::<AccountEntryResponse>().unwrap();
    eprintln!("{:#?}", res);
    assert_eq!(u128::from_str_radix(&res.balance[2..], 16).unwrap(), 98300);
    assert_eq!(res.nonce, 1);

}
