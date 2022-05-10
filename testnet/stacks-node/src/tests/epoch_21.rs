use std::collections::HashMap;
use std::env;
use std::thread;

use stacks::burnchains::Burnchain;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::StacksBlockHeader;
use stacks::types::chainstate::StacksAddress;
use stacks::vm::types::PrincipalData;

use crate::config::Config;
use crate::config::EventKeyType;
use crate::config::EventObserverConfig;
use crate::config::InitialBalance;
use crate::neon;
use crate::neon::RunLoopCounter;
use crate::tests::bitcoin_regtest::BitcoinCoreController;
use crate::tests::neon_integrations::*;
use crate::tests::*;
use crate::BitcoinRegtestController;
use crate::BurnchainController;
use stacks::core;

use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::distribution::BurnSamplePoint;
use stacks::chainstate::burn::operations::BlockstackOperationType;
use stacks::chainstate::burn::operations::PreStxOp;
use stacks::chainstate::burn::operations::TransferStxOp;

use stacks::burnchains::bitcoin::address::{BitcoinAddress, BitcoinAddressType};
use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::burnchains::PoxConstants;
use stacks::burnchains::Txid;

use crate::stacks_common::types::Address;
use crate::stacks_common::util::hash::hex_bytes;

use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::util::secp256k1::Secp256k1PublicKey;

use stacks::chainstate::coordinator::comm::CoordinatorChannels;

use stacks::core::BURNCHAIN_TX_SEARCH_WINDOW;

use crate::burnchains::bitcoin_regtest_controller::UTXO;
use crate::operations::BurnchainOpSigner;
use crate::tests::neon_integrations::get_balance;
use crate::Keychain;

fn advance_to_2_1(
    mut initial_balances: Vec<InitialBalance>,
) -> (
    Config,
    BitcoinCoreController,
    BitcoinRegtestController,
    RunLoopCounter,
    CoordinatorChannels,
) {
    let epoch_2_05 = 210;
    let epoch_2_1 = 215;

    test_observer::spawn();

    let (mut conf, miner_account) = neon_integration_test_conf();

    conf.initial_balances.append(&mut initial_balances);
    conf.events_observers.push(EventObserverConfig {
        endpoint: format!("localhost:{}", test_observer::EVENT_OBSERVER_PORT),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let mut epochs = core::STACKS_EPOCHS_REGTEST.to_vec();
    epochs[1].end_height = epoch_2_05;
    epochs[2].start_height = epoch_2_05;
    epochs[2].end_height = epoch_2_1;
    epochs[3].start_height = epoch_2_1;

    conf.burnchain.epochs = Some(epochs);

    let mut burnchain_config = Burnchain::regtest(&conf.get_burn_db_path());

    let reward_cycle_len = 2000;
    let prepare_phase_len = 100;
    let pox_constants = PoxConstants::new(
        reward_cycle_len,
        prepare_phase_len,
        4 * prepare_phase_len / 5,
        5,
        15,
        u32::max_value(),
    );
    burnchain_config.pox_constants = pox_constants.clone();

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::with_burnchain(
        conf.clone(),
        None,
        Some(burnchain_config.clone()),
        None,
    );
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    // give one coinbase to the miner, and then burn the rest
    btc_regtest_controller.bootstrap_chain(1);

    let mining_pubkey = btc_regtest_controller.get_mining_pubkey().unwrap();
    btc_regtest_controller.set_mining_pubkey(
        "03dc62fe0b8964d01fc9ca9a5eec0e22e557a12cc656919e648f04e0b26fea5faa".to_string(),
    );

    // bitcoin chain starts at epoch 2.05 boundary, minus 5 blocks to go
    btc_regtest_controller.bootstrap_chain(epoch_2_05 - 6);

    // only one UTXO for our mining pubkey
    let utxos = btc_regtest_controller
        .get_all_utxos(&Secp256k1PublicKey::from_hex(&mining_pubkey).unwrap());
    assert_eq!(utxos.len(), 1);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();

    let runloop_burnchain = burnchain_config.clone();
    thread::spawn(move || run_loop.start(Some(runloop_burnchain), 0));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let tip_info = get_chain_info(&conf);
    assert_eq!(tip_info.burn_block_height, epoch_2_05 - 4);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // cross the epoch 2.05 boundary
    for _i in 0..3 {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    }

    let tip_info = get_chain_info(&conf);
    assert_eq!(tip_info.burn_block_height, epoch_2_05 + 1);

    // these should all succeed across the epoch 2.1 boundary
    for _i in 0..5 {
        let tip_info = get_chain_info(&conf);

        // this block is the epoch transition?
        let (chainstate, _) = StacksChainState::open(
            false,
            conf.burnchain.chain_id,
            &conf.get_chainstate_path_str(),
            None,
        )
        .unwrap();
        let res = StacksChainState::block_crosses_epoch_boundary(
            &chainstate.db(),
            &tip_info.stacks_tip_consensus_hash,
            &tip_info.stacks_tip,
        )
        .unwrap();
        debug!(
            "Epoch transition at {} ({}/{}) height {}: {}",
            &StacksBlockHeader::make_index_block_hash(
                &tip_info.stacks_tip_consensus_hash,
                &tip_info.stacks_tip
            ),
            &tip_info.stacks_tip_consensus_hash,
            &tip_info.stacks_tip,
            tip_info.burn_block_height,
            res
        );

        if tip_info.burn_block_height >= epoch_2_1 {
            if tip_info.burn_block_height == epoch_2_1 {
                assert!(res);
            }

            // pox-2 should be initialized now
            let _ = get_contract_src(
                &http_origin,
                StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
                "pox-2".to_string(),
                true,
            )
            .unwrap();
        } else {
            assert!(!res);

            // pox-2 should NOT be initialized
            let e = get_contract_src(
                &http_origin,
                StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
                "pox-2".to_string(),
                true,
            )
            .unwrap_err();
            eprintln!("No pox-2: {}", &e);
        }

        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    }

    let tip_info = get_chain_info(&conf);
    assert_eq!(tip_info.burn_block_height, epoch_2_1 + 1);

    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.nonce, 9);

    eprintln!("Begin Stacks 2.1");
    return (
        conf,
        btcd_controller,
        btc_regtest_controller,
        blocks_processed,
        channel,
    );
}

#[test]
#[ignore]
fn transition_fixes_utxo_chaining() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    // very simple test to verify that the miner will keep making valid (empty) blocks after the
    // transition.  Really tests that the block-commits are well-formed before and after the epoch
    // transition.
    let (conf, _btcd_controller, mut btc_regtest_controller, blocks_processed, coord_channel) =
        advance_to_2_1(vec![]);

    // post epoch 2.1 -- UTXO chaining should be fixed
    for i in 0..10 {
        let tip_info = get_chain_info(&conf);

        if i % 2 == 1 {
            std::env::set_var(
                "STX_TEST_LATE_BLOCK_COMMIT",
                format!("{}", tip_info.burn_block_height + 1),
            );
        }

        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    }

    let sortdb = btc_regtest_controller.sortdb_mut();
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let burn_sample: Vec<BurnSamplePoint> = sortdb
        .conn()
        .query_row(
            "SELECT data FROM snapshot_burn_distributions WHERE sortition_id = ?",
            &[tip.sortition_id],
            |row| {
                let data_str: String = row.get_unwrap(0);
                Ok(serde_json::from_str(&data_str).unwrap())
            },
        )
        .unwrap();

    // if UTXO linking is fixed, then our median burn will be int((20,000 + 1) / 2).
    // Otherwise, it will be 1.
    assert_eq!(burn_sample.len(), 1);
    assert_eq!(burn_sample[0].burns, 10_000);

    test_observer::clear();
    coord_channel.stop_chains_coordinator();
}

#[test]
#[ignore]
fn transition_adds_burn_block_height() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    // very simple test to verify that after the 2.1 transition, get-burn-block-info? works as
    // expected

    let spender_sk = StacksPrivateKey::new();
    let spender_addr = PrincipalData::from(to_addr(&spender_sk));
    let spender_addr_c32 = StacksAddress::from(to_addr(&spender_sk));

    let (conf, _btcd_controller, mut btc_regtest_controller, blocks_processed, coord_channel) =
        advance_to_2_1(vec![InitialBalance {
            address: spender_addr.clone(),
            amount: 200_000_000,
        }]);
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    // post epoch 2.1 -- we should be able to query any/all burnchain headers after the first
    // burnchain block height (not the genesis burnchain height, mind you, but the first burnchain
    // block height at which the Stacks blockchain begins).
    let contract = "
    (define-private (test-burn-headers-cls (height uint) (base uint))
        (begin
            (print { height: (+ base height), hash: (get-burn-block-info? header-hash (+ base height)) })
            base
        )
    )
    (define-public (test-burn-headers)
        (begin
            (fold test-burn-headers-cls
                (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 u20 u21 u22 u23 u24)
                u0
            )
            (fold test-burn-headers-cls
                (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 u20 u21 u22 u23 u24)
                u25
            )
            (fold test-burn-headers-cls
                (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 u20 u21 u22 u23 u24)
                u50
            )
            (fold test-burn-headers-cls
                (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 u20 u21 u22 u23 u24)
                u75
            )
            (fold test-burn-headers-cls
                (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 u20 u21 u22 u23 u24)
                u100
            )
            (fold test-burn-headers-cls
                (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 u20 u21 u22 u23 u24)
                u125
            )
            (fold test-burn-headers-cls
                (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 u20 u21 u22 u23 u24)
                u150
            )
            (fold test-burn-headers-cls
                (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 u20 u21 u22 u23 u24)
                u175
            )
            (fold test-burn-headers-cls
                (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 u20 u21 u22 u23 u24)
                u200
            )
            (fold test-burn-headers-cls
                (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 u20 u21 u22 u23 u24)
                u225
            )
            (ok u0)
        )
    )
    ";

    let tx = make_contract_publish(
        &spender_sk,
        0,
        (2 * contract.len()) as u64,
        "test-burn-headers",
        contract,
    );
    submit_tx(&http_origin, &tx);

    // mine it
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let tx = make_contract_call(
        &spender_sk,
        1,
        (2 * contract.len()) as u64,
        &spender_addr_c32,
        "test-burn-headers",
        "test-burn-headers",
        &[],
    );
    submit_tx(&http_origin, &tx);

    let cc_txid = StacksTransaction::consensus_deserialize(&mut &tx[..])
        .unwrap()
        .txid();

    // mine it
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // check it
    let mut header_hashes: HashMap<u64, Option<BurnchainHeaderHash>> = HashMap::new();
    let blocks = test_observer::get_blocks();
    for block in blocks {
        let transactions = block.get("transactions").unwrap().as_array().unwrap();
        let events = block.get("events").unwrap().as_array().unwrap();

        for tx in transactions.iter() {
            let raw_tx = tx.get("raw_tx").unwrap().as_str().unwrap();
            if raw_tx == "0x00" {
                continue;
            }
            let tx_bytes = hex_bytes(&raw_tx[2..]).unwrap();
            let parsed = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
            if parsed.txid() == cc_txid {
                // check events for this block
                for event in events.iter() {
                    if let Some(cev) = event.get("contract_event") {
                        // strip leading `0x`
                        eprintln!("{:#?}", &cev);
                        let clarity_serialized_value = hex_bytes(
                            &String::from_utf8(
                                cev.get("raw_value").unwrap().as_str().unwrap().as_bytes()[2..]
                                    .to_vec(),
                            )
                            .unwrap(),
                        )
                        .unwrap();
                        let clarity_value =
                            Value::deserialize_read(&mut &clarity_serialized_value[..], None)
                                .unwrap();
                        let pair = clarity_value.expect_tuple();
                        let height = pair.get("height").unwrap().clone().expect_u128() as u64;
                        let bhh_opt =
                            pair.get("hash")
                                .unwrap()
                                .clone()
                                .expect_optional()
                                .map(|inner_buff| {
                                    let buff_bytes_vec = inner_buff.expect_buff(32);
                                    let mut buff_bytes = [0u8; 32];
                                    buff_bytes.copy_from_slice(&buff_bytes_vec[0..32]);
                                    BurnchainHeaderHash(buff_bytes)
                                });

                        header_hashes.insert(height, bhh_opt);
                    }
                }
            }
        }
    }

    let sortdb = btc_regtest_controller.sortdb_mut();
    let all_snapshots = sortdb.get_all_snapshots().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

    // all block headers are accounted for
    for sn in all_snapshots.iter() {
        match header_hashes.get(&sn.block_height) {
            Some(Some(bhh)) => {
                assert_eq!(&sn.burn_header_hash, bhh);

                // only defined up to the tip
                assert!(sn.block_height < tip.block_height);
            }
            Some(None) => {
                // must exceed the tip
                assert!(sn.block_height >= tip.block_height);
            }
            None => {
                panic!("Missing header for {}", sn.block_height);
            }
        }
    }

    test_observer::clear();
    coord_channel.stop_chains_coordinator();
}

#[test]
#[ignore]
fn transition_fixes_bitcoin_rigidity() {
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

    let epoch_2_05 = 210;
    let epoch_2_1 = 215;

    test_observer::spawn();

    let (mut conf, miner_account) = neon_integration_test_conf();
    let mut initial_balances = vec![
        InitialBalance {
            address: spender_addr.clone(),
            amount: 100300,
        },
        InitialBalance {
            address: spender_2_addr.clone(),
            amount: 100300,
        },
    ];

    conf.initial_balances.append(&mut initial_balances);
    conf.events_observers.push(EventObserverConfig {
        endpoint: format!("localhost:{}", test_observer::EVENT_OBSERVER_PORT),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let mut epochs = core::STACKS_EPOCHS_REGTEST.to_vec();
    epochs[1].end_height = epoch_2_05;
    epochs[2].start_height = epoch_2_05;
    epochs[2].end_height = epoch_2_1;
    epochs[3].start_height = epoch_2_1;

    conf.burnchain.epochs = Some(epochs);

    let mut burnchain_config = Burnchain::regtest(&conf.get_burn_db_path());

    let reward_cycle_len = 2000;
    let prepare_phase_len = 100;
    let pox_constants = PoxConstants::new(
        reward_cycle_len,
        prepare_phase_len,
        4 * prepare_phase_len / 5,
        5,
        15,
        u32::max_value(),
    );
    burnchain_config.pox_constants = pox_constants.clone();

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::with_burnchain(
        conf.clone(),
        None,
        Some(burnchain_config.clone()),
        None,
    );
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    // bitcoin chain starts at epoch 2.05 boundary, minus 5 blocks to go
    btc_regtest_controller.bootstrap_chain(epoch_2_05 - 5);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();

    let runloop_burnchain = burnchain_config.clone();
    thread::spawn(move || run_loop.start(Some(runloop_burnchain), 0));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let tip_info = get_chain_info(&conf);
    assert_eq!(tip_info.burn_block_height, epoch_2_05 - 4);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // cross the epoch 2.05 boundary
    for _i in 0..3 {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    }

    let tip_info = get_chain_info(&conf);
    assert_eq!(tip_info.burn_block_height, epoch_2_05 + 1);

    // okay, let's send a pre-stx op for a transfer-stx op that will get mined before the 2.1 epoch
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

    // mine it
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // let's fire off our transfer op that will not land in a sortition pre-2.1
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

    // mine it without a sortition
    btc_regtest_controller.build_next_block(1);

    // these should all succeed across the epoch 2.1 boundary
    for i in 0..3 {
        let tip_info = get_chain_info(&conf);

        // this block is the epoch transition?
        let (chainstate, _) = StacksChainState::open(
            false,
            conf.burnchain.chain_id,
            &conf.get_chainstate_path_str(),
            None,
        )
        .unwrap();
        let res = StacksChainState::block_crosses_epoch_boundary(
            &chainstate.db(),
            &tip_info.stacks_tip_consensus_hash,
            &tip_info.stacks_tip,
        )
        .unwrap();
        debug!(
            "Epoch transition at {} ({}/{}) height {}: {}",
            &StacksBlockHeader::make_index_block_hash(
                &tip_info.stacks_tip_consensus_hash,
                &tip_info.stacks_tip
            ),
            &tip_info.stacks_tip_consensus_hash,
            &tip_info.stacks_tip,
            tip_info.burn_block_height,
            res
        );

        if tip_info.burn_block_height >= epoch_2_1 {
            if tip_info.burn_block_height == epoch_2_1 {
                assert!(res);
            }

            // pox-2 should be initialized now
            let _ = get_contract_src(
                &http_origin,
                StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
                "pox-2".to_string(),
                true,
            )
            .unwrap();
        } else {
            assert!(!res);

            // pox-2 should NOT be initialized
            let e = get_contract_src(
                &http_origin,
                StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
                "pox-2".to_string(),
                true,
            )
            .unwrap_err();
            eprintln!("No pox-2: {}", &e);
        }

        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    }

    let tip_info = get_chain_info(&conf);
    assert_eq!(tip_info.burn_block_height, epoch_2_1 + 1);

    // stx-transfer did not go through -- it fell in a block before 2.1
    assert_eq!(get_balance(&http_origin, &spender_addr), 100_300);
    assert_eq!(get_balance(&http_origin, &recipient_addr), 0);
    assert_eq!(get_balance(&http_origin, &spender_2_addr), 100_300);

    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.nonce, 8);

    eprintln!("Begin Stacks 2.1");

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

    // build a couple bitcoin blocks without a stacks block to mine it, up to the edge of the
    // window
    for _i in 0..BURNCHAIN_TX_SEARCH_WINDOW {
        btc_regtest_controller.build_next_block(1);
    }

    // this block should process the transfer, even though it was mined in a sortition-less block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
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
        confirmations: 0,
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

    // build a couple bitcoin blocks without a stacks block to mine it, up to the edge of the
    // window
    for _i in 0..BURNCHAIN_TX_SEARCH_WINDOW {
        btc_regtest_controller.build_next_block(1);
    }

    // should process the transfer
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    assert_eq!(get_balance(&http_origin, &spender_addr), 300);
    assert_eq!(get_balance(&http_origin, &recipient_addr), 200_000);
    assert_eq!(get_balance(&http_origin, &spender_2_addr), 300);

    // let's fire off another transfer op that will fall outside the window
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
        confirmations: 0,
    };

    let transfer_stx_op = TransferStxOp {
        sender: spender_stx_addr.clone(),
        recipient: recipient_addr.clone(),
        transfered_ustx: 123,
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

    // build a couple bitcoin blocks without a stacks block to mine it, up to the edge of the
    // window and then past it
    for _i in 0..(BURNCHAIN_TX_SEARCH_WINDOW + 1) {
        btc_regtest_controller.build_next_block(1);
    }

    // should NOT process the transfer
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    assert_eq!(get_balance(&http_origin, &spender_addr), 300);
    assert_eq!(get_balance(&http_origin, &recipient_addr), 200_000);
    assert_eq!(get_balance(&http_origin, &spender_2_addr), 300);

    test_observer::clear();
    channel.stop_chains_coordinator();
}
