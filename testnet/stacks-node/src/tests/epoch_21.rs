use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::thread;

use stacks::burnchains::Burnchain;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::StacksBlockHeader;
use stacks::types::chainstate::StacksAddress;

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
use stacks::chainstate::burn::operations::leader_block_commit::BURN_BLOCK_MINED_AT_MODULUS;
use stacks::chainstate::burn::operations::leader_block_commit::OUTPUTS_PER_COMMIT;
use stacks::chainstate::burn::operations::BlockstackOperationType;
use stacks::chainstate::burn::operations::LeaderBlockCommitOp;
use stacks::chainstate::burn::operations::PreStxOp;
use stacks::chainstate::burn::operations::TransferStxOp;

use stacks::chainstate::stacks::address::PoxAddress;

use stacks::burnchains::bitcoin::address::{
    BitcoinAddress, LegacyBitcoinAddressType, SegwitBitcoinAddress,
};
use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::burnchains::PoxConstants;
use stacks::burnchains::Txid;

use crate::stacks_common::address::AddressHashMode;
use crate::stacks_common::types::Address;
use crate::stacks_common::util::hash::{bytes_to_hex, hex_bytes};

use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::VRFSeed;
use stacks_common::util::hash::Hash160;
use stacks_common::util::hash::Sha256Sum;
use stacks_common::util::secp256k1::Secp256k1PublicKey;

use stacks::chainstate::coordinator::comm::CoordinatorChannels;

use stacks::clarity_cli::vm_execute as execute;

use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::ClarityVersion;
use stacks::core::BURNCHAIN_TX_SEARCH_WINDOW;

use crate::burnchains::bitcoin_regtest_controller::UTXO;
use crate::operations::BurnchainOpSigner;
use crate::Keychain;

const MINER_BURN_PUBLIC_KEY: &'static str =
    "03dc62fe0b8964d01fc9ca9a5eec0e22e557a12cc656919e648f04e0b26fea5faa";

fn advance_to_2_1(
    mut initial_balances: Vec<InitialBalance>,
    block_reward_recipient: Option<PrincipalData>,
    pox_constants: Option<PoxConstants>,
    segwit: bool,
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

    conf.burnchain.peer_host = "localhost".to_string();
    conf.initial_balances.append(&mut initial_balances);
    conf.miner.block_reward_recipient = block_reward_recipient;

    conf.events_observers.push(EventObserverConfig {
        endpoint: format!("localhost:{}", test_observer::EVENT_OBSERVER_PORT),
        events_keys: vec![EventKeyType::AnyEvent],
        include_data_events: false,
    });

    let mut epochs = core::STACKS_EPOCHS_REGTEST.to_vec();
    epochs[1].end_height = epoch_2_05;
    epochs[2].start_height = epoch_2_05;
    epochs[2].end_height = epoch_2_1;
    epochs[3].start_height = epoch_2_1;

    conf.burnchain.epochs = Some(epochs);

    conf.miner.segwit = segwit;

    let mut burnchain_config = Burnchain::regtest(&conf.get_burn_db_path());

    let reward_cycle_len = 2000;
    let prepare_phase_len = 100;
    let pox_constants = pox_constants.unwrap_or(PoxConstants::new(
        reward_cycle_len,
        prepare_phase_len,
        4 * prepare_phase_len / 5,
        5,
        15,
        u64::max_value() - 2,
        u64::max_value() - 1,
        u32::max_value(),
    ));
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
    // if segwit is supported, then give one coinbase to the segwit address as well as the legacy
    // address. This is needed to allow the miner to boot up into 2.1 through epochs 2.0 and 2.05.
    let mining_pubkey = if conf.miner.segwit {
        btc_regtest_controller.set_use_segwit(false);
        btc_regtest_controller.bootstrap_chain(1);

        btc_regtest_controller.set_use_segwit(conf.miner.segwit);
        btc_regtest_controller.bootstrap_chain(1);

        let mining_pubkey = btc_regtest_controller.get_mining_pubkey().unwrap();
        debug!("Mining pubkey is {}", &mining_pubkey);
        btc_regtest_controller.set_mining_pubkey(MINER_BURN_PUBLIC_KEY.to_string());

        mining_pubkey
    } else {
        btc_regtest_controller.bootstrap_chain(1);

        let mining_pubkey = btc_regtest_controller.get_mining_pubkey().unwrap();
        debug!("Mining pubkey is {}", &mining_pubkey);
        btc_regtest_controller.set_mining_pubkey(MINER_BURN_PUBLIC_KEY.to_string());

        btc_regtest_controller.bootstrap_chain(1);

        mining_pubkey
    };

    // bitcoin chain starts at epoch 2.05 boundary, minus 5 blocks to go
    btc_regtest_controller.bootstrap_chain(epoch_2_05 - 7);

    // only one UTXO for our mining pubkey (which is uncompressed, btw)
    // NOTE: if we're using segwit, then the mining pubkey will be compressed for the segwit UTXO
    // generation (i.e. it'll be treated as different from the uncompressed public key).
    let utxos = btc_regtest_controller
        .get_all_utxos(&Secp256k1PublicKey::from_hex(&mining_pubkey).unwrap());

    eprintln!(
        "UTXOs for {} (segwit={}): {:?}",
        &mining_pubkey, conf.miner.segwit, &utxos
    );
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
        advance_to_2_1(
            vec![InitialBalance {
                address: spender_addr.clone(),
                amount: 200_000_000,
            }],
            None,
            None,
            false,
        );
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
fn transition_adds_pay_to_alt_recipient_contract() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    // very simple test to verify that the miner will automatically start sending block rewards to
    // a contract in the config file when it mines after epoch 2.1.
    let target_contract_address =
        QualifiedContractIdentifier::parse("ST000000000000000000002AMW42H.bns").unwrap();
    let (conf, _btcd_controller, mut btc_regtest_controller, blocks_processed, coord_channel) =
        advance_to_2_1(
            vec![],
            Some(PrincipalData::Contract(target_contract_address.clone())),
            None,
            false,
        );

    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    let contract_account_before = get_account(&http_origin, &target_contract_address);

    for _i in 0..stacks_common::consts::MINER_REWARD_MATURITY + 1 {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    }

    let contract_account_after = get_account(&http_origin, &target_contract_address);

    assert!(contract_account_before.balance < contract_account_after.balance);

    test_observer::clear();
    coord_channel.stop_chains_coordinator();
}

#[test]
#[ignore]
fn transition_adds_pay_to_alt_recipient_principal() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    // very simple test to verify that the miner will automatically start sending block rewards to
    // an alternative principal in the config file when it mines after epoch 2.1.
    let target_principal_address =
        PrincipalData::parse("ST34CV1214XJF9S8WPT09TJNYJTM8GM4W6N7ZGKDF").unwrap();
    let (conf, _btcd_controller, mut btc_regtest_controller, blocks_processed, coord_channel) =
        advance_to_2_1(vec![], Some(target_principal_address.clone()), None, false);

    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    let alt_account_before = get_account(&http_origin, &target_principal_address);

    for _i in 0..stacks_common::consts::MINER_REWARD_MATURITY + 1 {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    }

    let alt_account_after = get_account(&http_origin, &target_principal_address);

    assert!(alt_account_before.balance < alt_account_after.balance);

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
    let _spender_btc_addr = BitcoinAddress::from_bytes_legacy(
        BitcoinNetworkType::Regtest,
        LegacyBitcoinAddressType::PublicKeyHash,
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
        include_data_events: false,
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
        (16 * reward_cycle_len - 1).into(),
        (17 * reward_cycle_len).into(),
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
        btc_regtest_controller
            .submit_operation(
                StacksEpochId::Epoch2_05,
                BlockstackOperationType::PreStx(pre_stx_op),
                &mut miner_signer,
                1
            )
            .is_some(),
        "Pre-stx operation should submit successfully"
    );

    // mine it
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // let's fire off a transfer op that will not land in the Stacks 2.1 epoch.  It should not be
    // applied, even though it's within 6 blocks of the next Stacks block, which will be in epoch
    // 2.1.  This verifies that the new burnchain consideration window only applies to sortitions
    // that happen in Stacks 2.1.
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
        btc_regtest_controller
            .submit_operation(
                StacksEpochId::Epoch2_05,
                BlockstackOperationType::TransferStx(transfer_stx_op),
                &mut spender_signer,
                1
            )
            .is_some(),
        "Transfer operation should submit successfully"
    );

    // mine it without a sortition
    btc_regtest_controller.build_next_block(1);

    // these should all succeed across the epoch 2.1 boundary
    for _i in 0..3 {
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
        btc_regtest_controller
            .submit_operation(
                StacksEpochId::Epoch21,
                BlockstackOperationType::PreStx(pre_stx_op),
                &mut miner_signer,
                1
            )
            .is_some(),
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
        btc_regtest_controller
            .submit_operation(
                StacksEpochId::Epoch2_05,
                BlockstackOperationType::TransferStx(transfer_stx_op),
                &mut spender_signer,
                1
            )
            .is_some(),
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
            StacksEpochId::Epoch21,
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
            StacksEpochId::Epoch21,
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
            StacksEpochId::Epoch21,
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
            StacksEpochId::Epoch21,
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

#[test]
#[ignore]
fn transition_adds_get_pox_addr_recipients() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    // very simple test to verify that when STX are stacked, the PoX address is recoverable from
    // `get-burn-block-info?`

    let reward_cycle_len = 10;
    let prepare_phase_len = 4;
    let v1_unlock_height = 220;
    let pox_constants = PoxConstants::new(
        reward_cycle_len,
        prepare_phase_len,
        4 * prepare_phase_len / 5,
        1,
        1,
        u64::max_value() - 2,
        u64::max_value() - 1,
        v1_unlock_height,
    );

    let mut spender_sks = vec![];
    let mut spender_addrs = vec![];
    let mut initial_balances = vec![];
    let mut expected_pox_addrs = HashSet::new();

    let stacked = 100_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);

    for _i in 0..7 {
        let spender_sk = StacksPrivateKey::new();
        let spender_addr: PrincipalData = to_addr(&spender_sk).into();

        spender_sks.push(spender_sk);
        spender_addrs.push(spender_addr.clone());
        initial_balances.push(InitialBalance {
            address: spender_addr.clone(),
            amount: stacked + 100_000,
        });
    }

    let pox_pubkey = Secp256k1PublicKey::from_hex(
        "02f006a09b59979e2cb8449f58076152af6b124aa29b948a3714b8d5f15aa94ede",
    )
    .unwrap();
    let pox_pubkey_hash = bytes_to_hex(
        &Hash160::from_node_public_key(&pox_pubkey)
            .to_bytes()
            .to_vec(),
    );

    let (conf, _btcd_controller, mut btc_regtest_controller, blocks_processed, coord_channel) =
        advance_to_2_1(initial_balances, None, Some(pox_constants.clone()), false);

    let mut sort_height = coord_channel.get_sortitions_processed();
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    let stack_sort_height = sort_height;

    // stack some STX to each standard PoX address variant
    for (i, addr_variant) in [
        AddressHashMode::SerializeP2PKH,
        AddressHashMode::SerializeP2SH,
        AddressHashMode::SerializeP2WPKH,
        AddressHashMode::SerializeP2WSH,
    ]
    .iter()
    .enumerate()
    {
        let spender_sk = spender_sks[i].clone();
        let pox_addr_tuple = execute(
            &format!(
                "{{ hashbytes: 0x{}, version: 0x{:02x} }}",
                pox_pubkey_hash,
                &(*addr_variant as u8)
            ),
            ClarityVersion::Clarity2,
        )
        .unwrap()
        .unwrap();
        let tx = make_contract_call(
            &spender_sk,
            0,
            300,
            &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
            "pox-2",
            "stack-stx",
            &[
                Value::UInt(stacked.into()),
                pox_addr_tuple.clone(),
                Value::UInt(sort_height as u128),
                Value::UInt(2),
            ],
        );

        submit_tx(&http_origin, &tx);
        expected_pox_addrs.insert(pox_addr_tuple);
    }

    // stack some STX to segwit addressses
    for i in 4..7 {
        let spender_sk = spender_sks[i].clone();
        let pubk = Secp256k1PublicKey::from_private(&spender_sk);
        let version = i as u8;
        let bytes = match i {
            4 => {
                // p2wpkh
                to_hex(&Hash160::from_node_public_key(&pubk).0)
            }
            _ => {
                // p2wsh or p2tr
                to_hex(&Sha256Sum::from_data(&pubk.to_bytes_compressed()).0)
            }
        };
        let pox_addr_tuple = execute(
            &format!("{{ hashbytes: 0x{}, version: 0x{:02x} }}", &bytes, &version),
            ClarityVersion::Clarity2,
        )
        .unwrap()
        .unwrap();
        let tx = make_contract_call(
            &spender_sk,
            0,
            300,
            &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
            "pox-2",
            "stack-stx",
            &[
                Value::UInt(stacked.into()),
                pox_addr_tuple.clone(),
                Value::UInt(sort_height as u128),
                Value::UInt(2),
            ],
        );

        submit_tx(&http_origin, &tx);
        expected_pox_addrs.insert(pox_addr_tuple);
    }

    let contract = "
    (define-private (get-pox-addrs-at (idx uint) (base uint))
        (let (
            (burn-height (+ base idx))
        )
            (print { burn-height: burn-height, pox-addrs: (get-burn-block-info? pox-addrs burn-height) })
            base
        )
    )
    (define-public (test-get-pox-addrs (start-burn-height uint))
        (ok (fold get-pox-addrs-at
            (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 u20 u21 u22 u23 u24)
            start-burn-height
        ))
    )
    ";

    let spender_addr_c32 = StacksAddress::from(to_addr(&spender_sks[0]));
    let contract_tx = make_contract_publish(
        &spender_sks[0],
        1,
        (2 * contract.len()) as u64,
        "test-get-pox-addrs",
        contract,
    );

    submit_tx(&http_origin, &contract_tx);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    eprintln!("Sort height: {}", sort_height);
    test_observer::clear();

    // mine through two reward cycles
    // now let's mine until the next reward cycle starts ...
    while sort_height
        < (stack_sort_height as u64) + (((2 * pox_constants.reward_cycle_length) + 1) as u64)
    {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        sort_height = coord_channel.get_sortitions_processed();
        eprintln!("Sort height: {}", sort_height);
    }

    let cc_tx = make_contract_call(
        &spender_sks[0],
        2,
        (2 * contract.len()) as u64,
        &spender_addr_c32,
        "test-get-pox-addrs",
        "test-get-pox-addrs",
        &[Value::UInt((stack_sort_height).into())],
    );
    let cc_txid = StacksTransaction::consensus_deserialize(&mut &cc_tx[..])
        .unwrap()
        .txid();

    submit_tx(&http_origin, &cc_tx);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // check result of test-get-pox-addrs
    let blocks = test_observer::get_blocks();
    let mut found_pox_addrs = HashSet::new();
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
                for (_i, event) in events.iter().enumerate() {
                    if let Some(cev) = event.get("contract_event") {
                        // strip leading `0x`
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
                        let burn_block_height =
                            pair.get("burn-height").unwrap().clone().expect_u128() as u64;
                        let pox_addr_tuples_opt =
                            pair.get("pox-addrs").unwrap().clone().expect_optional();

                        if let Some(pox_addr_tuples_list) = pox_addr_tuples_opt {
                            let pox_addrs_and_payout_tuple = pox_addr_tuples_list.expect_tuple();
                            let pox_addr_tuples = pox_addrs_and_payout_tuple
                                .get("addrs")
                                .unwrap()
                                .to_owned()
                                .expect_list();

                            let payout = pox_addrs_and_payout_tuple
                                .get("payout")
                                .unwrap()
                                .to_owned()
                                .expect_u128();

                            // NOTE: there's an even number of payouts here, so this works
                            eprintln!("payout at {} = {}", burn_block_height, &payout);

                            if Burnchain::static_is_in_prepare_phase(
                                0,
                                pox_constants.reward_cycle_length as u64,
                                pox_constants.prepare_length.into(),
                                burn_block_height,
                            ) {
                                // in prepare phase
                                eprintln!("{} in prepare phase", burn_block_height);
                                assert_eq!(payout, conf.burnchain.burn_fee_cap as u128);
                                assert_eq!(pox_addr_tuples.len(), 1);
                            } else {
                                // in reward phase
                                eprintln!("{} in reward phase", burn_block_height);
                                assert_eq!(
                                    payout,
                                    (conf.burnchain.burn_fee_cap / (OUTPUTS_PER_COMMIT as u64))
                                        as u128
                                );
                                assert_eq!(pox_addr_tuples.len(), 2);
                            }

                            for pox_addr_value in pox_addr_tuples.into_iter() {
                                let pox_addr =
                                    PoxAddress::try_from_pox_tuple(false, &pox_addr_value).expect(
                                        &format!("FATAL: invalid PoX tuple {:?}", &pox_addr_value),
                                    );
                                eprintln!("at {}: {:?}", burn_block_height, &pox_addr);
                                if !pox_addr.is_burn() {
                                    found_pox_addrs.insert(pox_addr);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    eprintln!("found pox addrs: {:?}", &found_pox_addrs);
    assert_eq!(found_pox_addrs.len(), 7);

    for addr in found_pox_addrs
        .into_iter()
        .map(|addr| Value::Tuple(addr.as_clarity_tuple().unwrap()))
    {
        eprintln!("Contains: {:?}", &addr);
        assert!(expected_pox_addrs.contains(&addr));
    }
}

#[test]
#[ignore]
fn transition_adds_mining_from_segwit() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let reward_cycle_len = 10;
    let prepare_phase_len = 4;
    let v1_unlock_height = 220;
    let pox_constants = PoxConstants::new(
        reward_cycle_len,
        prepare_phase_len,
        4 * prepare_phase_len / 5,
        1,
        1,
        u64::MAX,
        u64::MAX,
        v1_unlock_height,
    );

    let mut spender_sks = vec![];
    let mut spender_addrs = vec![];
    let mut initial_balances = vec![];

    let stacked = 100_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);

    for _i in 0..7 {
        let spender_sk = StacksPrivateKey::new();
        let spender_addr: PrincipalData = to_addr(&spender_sk).into();

        spender_sks.push(spender_sk);
        spender_addrs.push(spender_addr.clone());
        initial_balances.push(InitialBalance {
            address: spender_addr.clone(),
            amount: stacked + 100_000,
        });
    }

    let (conf, _btcd_controller, mut btc_regtest_controller, blocks_processed, _coord_channel) =
        advance_to_2_1(initial_balances, None, Some(pox_constants.clone()), true);

    let utxos = btc_regtest_controller
        .get_all_utxos(&Secp256k1PublicKey::from_hex(MINER_BURN_PUBLIC_KEY).unwrap());

    assert!(utxos.len() > 0);

    // all UTXOs should be segwit
    for utxo in utxos.iter() {
        let utxo_addr = BitcoinAddress::from_scriptpubkey(
            BitcoinNetworkType::Testnet,
            &utxo.script_pub_key.clone().into_bytes(),
        );
        if let Some(BitcoinAddress::Segwit(SegwitBitcoinAddress::P2WPKH(..))) = &utxo_addr {
        } else {
            panic!("UTXO address was {:?}", &utxo_addr);
        }
    }

    eprintln!("Wake up miner");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // mine a Stacks block
    let tip_info_before = get_chain_info(&conf);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    let tip_info_after = get_chain_info(&conf);

    // we were able to do so
    assert_eq!(
        tip_info_before.burn_block_height + 1,
        tip_info_after.burn_block_height
    );
    assert_eq!(
        tip_info_before.stacks_tip_height + 1,
        tip_info_after.stacks_tip_height
    );

    // that block-commit we just sent consumed a segwit p2wpkh utxo and emitted a segwit p2wpkh
    // utxo
    let sortdb = btc_regtest_controller.sortdb_mut();
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let commits =
        SortitionDB::get_block_commits_by_block(sortdb.conn(), &tip.sortition_id).unwrap();
    assert_eq!(commits.len(), 1);

    let txid = commits[0].txid.clone();
    let tx = btc_regtest_controller.get_raw_transaction(&txid);

    eprintln!("tx = {:?}", &tx);
    assert_eq!(tx.input[0].witness.len(), 2);
    let addr = BitcoinAddress::try_from_segwit(
        false,
        &tx.output
            .last()
            .as_ref()
            .unwrap()
            .script_pubkey
            .clone()
            .into_bytes(),
    );
    assert!(addr.is_some());
}

/// Verify that a sunset-in-progress will be halted by the epoch 2.1 transition
#[test]
#[ignore]
fn transition_removes_pox_sunset() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let spender_sk = StacksPrivateKey::new();
    let spender_addr: PrincipalData = to_addr(&spender_sk).into();
    let first_bal = 6_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);

    let pox_pubkey = Secp256k1PublicKey::from_hex(
        "02f006a09b59979e2cb8449f58076152af6b124aa29b948a3714b8d5f15aa94ede",
    )
    .unwrap();
    let pox_pubkey_hash = bytes_to_hex(
        &Hash160::from_node_public_key(&pox_pubkey)
            .to_bytes()
            .to_vec(),
    );

    let (mut conf, miner_account) = neon_integration_test_conf();

    test_observer::spawn();

    conf.events_observers.push(EventObserverConfig {
        endpoint: format!("localhost:{}", test_observer::EVENT_OBSERVER_PORT),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    conf.initial_balances.push(InitialBalance {
        address: spender_addr.clone(),
        amount: first_bal,
    });

    conf.node.mine_microblocks = false;
    conf.burnchain.max_rbf = 1000000;
    conf.node.wait_time_for_microblocks = 0;
    conf.node.microblock_frequency = 1_000;
    conf.miner.first_attempt_time_ms = 5_000;
    conf.miner.subsequent_attempt_time_ms = 10_000;
    conf.node.wait_time_for_blocks = 0;

    // reward cycle length = 15, so 10 reward cycle slots + 5 prepare-phase burns
    let first_sortition_height = 201;
    let reward_cycle_len = 15;
    let prepare_phase_len = 5;
    let sunset_start_rc = 16;
    let sunset_end_rc = 20;
    let epoch_21_rc = 18;

    let epoch_21 = epoch_21_rc * reward_cycle_len + 1;

    let mut epochs = core::STACKS_EPOCHS_REGTEST.to_vec();
    epochs[1].end_height = 1;
    epochs[2].start_height = 1;
    epochs[2].end_height = epoch_21;
    epochs[3].start_height = epoch_21;

    conf.burnchain.epochs = Some(epochs);

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let mut burnchain_config = Burnchain::regtest(&conf.get_burn_db_path());

    let pox_constants = PoxConstants::new(
        reward_cycle_len as u32,
        prepare_phase_len,
        4 * prepare_phase_len / 5,
        5,
        15,
        (sunset_start_rc * reward_cycle_len - 1).into(),
        (sunset_end_rc * reward_cycle_len).into(),
        (epoch_21 as u32) + 1,
    );
    burnchain_config.pox_constants = pox_constants.clone();

    let mut btc_regtest_controller = BitcoinRegtestController::with_burnchain(
        conf.clone(),
        None,
        Some(burnchain_config.clone()),
        None,
    );
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    btc_regtest_controller.bootstrap_chain(first_sortition_height);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();
    let channel = run_loop.get_coordinator_channel().unwrap();
    let thread_burnchain = burnchain_config.clone();

    thread::spawn(move || run_loop.start(Some(thread_burnchain), 0));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    stacks::util::sleep_ms(10_000);

    let sort_height = channel.get_sortitions_processed();

    // let's query the miner's account nonce:
    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.balance, 0);
    assert!(account.nonce >= 1);

    // and our potential spenders:
    let account = get_account(&http_origin, &spender_addr);
    assert_eq!(account.balance, first_bal as u128);
    assert_eq!(account.nonce, 0);

    let pox_info = get_pox_info(&http_origin);

    assert_eq!(
        &pox_info.contract_id,
        &format!("ST000000000000000000002AMW42H.pox")
    );
    assert_eq!(pox_info.current_cycle.is_pox_active, false);
    assert_eq!(pox_info.next_cycle.stacked_ustx, 0);

    let tx = make_contract_call(
        &spender_sk,
        0,
        260,
        &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
        "pox",
        "stack-stx",
        &[
            Value::UInt(first_bal as u128 - 260 * 3),
            execute(
                &format!("{{ hashbytes: 0x{}, version: 0x00 }}", pox_pubkey_hash),
                ClarityVersion::Clarity1,
            )
            .unwrap()
            .unwrap(),
            Value::UInt(sort_height as u128),
            Value::UInt(12),
        ],
    );

    // okay, let's push that stacking transaction!
    submit_tx(&http_origin, &tx);

    let mut sort_height = channel.get_sortitions_processed();
    eprintln!("Sort height pox-1: {}", sort_height);

    // advance to next reward cycle
    for _i in 0..(reward_cycle_len * 2 + 2) {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        sort_height = channel.get_sortitions_processed();
        eprintln!("Sort height pox-1: {} <= {}", sort_height, epoch_21);
    }

    // pox must activate
    let pox_info = get_pox_info(&http_origin);
    eprintln!("pox_info in pox-1 = {:?}", &pox_info);
    assert_eq!(pox_info.current_cycle.is_pox_active, true);
    assert_eq!(
        &pox_info.contract_id,
        &format!("ST000000000000000000002AMW42H.pox")
    );

    // advance to 2.1
    while sort_height <= epoch_21 + 1 {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        sort_height = channel.get_sortitions_processed();
        eprintln!("Sort height pox-1: {} <= {}", sort_height, epoch_21);
    }

    let pox_info = get_pox_info(&http_origin);

    // pox is still "active" despite unlock, because there's enough participation, and also even
    // though the v1 block height has passed, the pox-2 contract won't be managing reward sets
    // until the next reward cycle
    eprintln!("pox_info in pox-2 = {:?}", &pox_info);
    assert_eq!(pox_info.current_cycle.is_pox_active, true);
    assert_eq!(
        &pox_info.contract_id,
        &format!("ST000000000000000000002AMW42H.pox")
    );

    // re-stack
    let tx = make_contract_call(
        &spender_sk,
        1,
        260 * 2,
        &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
        "pox-2",
        "stack-stx",
        &[
            Value::UInt(first_bal as u128 - 260 * 3),
            execute(
                &format!("{{ hashbytes: 0x{}, version: 0x00 }}", pox_pubkey_hash),
                ClarityVersion::Clarity2,
            )
            .unwrap()
            .unwrap(),
            Value::UInt(sort_height as u128),
            Value::UInt(12),
        ],
    );

    // okay, let's push that stacking transaction!
    submit_tx(&http_origin, &tx);

    eprintln!("Try and confirm pox-2 stack-stx");

    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    sort_height = channel.get_sortitions_processed();
    eprintln!(
        "Sort height pox-1 to pox-2 with stack-stx to pox-2: {}",
        sort_height
    );

    let pox_info = get_pox_info(&http_origin);
    assert_eq!(pox_info.current_cycle.is_pox_active, true);

    // get pox back online
    while sort_height <= epoch_21 + reward_cycle_len {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        sort_height = channel.get_sortitions_processed();
        eprintln!("Sort height pox-2: {}", sort_height);
    }

    let pox_info = get_pox_info(&http_origin);
    eprintln!("pox_info = {:?}", &pox_info);
    assert_eq!(pox_info.current_cycle.is_pox_active, true);

    // first full reward cycle with pox-2
    assert_eq!(
        &pox_info.contract_id,
        &format!("ST000000000000000000002AMW42H.pox-2")
    );

    let burn_blocks = test_observer::get_burn_blocks();
    let mut pox_out_opt = None;
    for (i, block) in burn_blocks.into_iter().enumerate() {
        let recipients: Vec<(String, u64)> = block
            .get("reward_recipients")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|value| {
                let recipient: String = value
                    .get("recipient")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string();
                let amount = value.get("amt").unwrap().as_u64().unwrap();
                (recipient, amount)
            })
            .collect();

        if (i as u64) < (sunset_start_rc * reward_cycle_len) {
            // before sunset
            if recipients.len() >= 1 {
                for (_, amt) in recipients.into_iter() {
                    pox_out_opt = if let Some(pox_out) = pox_out_opt.clone() {
                        Some(std::cmp::max(amt, pox_out))
                    } else {
                        Some(amt)
                    };
                }
            }
        } else if (i as u64) >= (sunset_start_rc * reward_cycle_len) && (i as u64) + 1 < epoch_21 {
            // some sunset burn happened
            let pox_out = pox_out_opt.clone().unwrap();
            if recipients.len() >= 1 {
                for (_, amt) in recipients.into_iter() {
                    assert!(amt < pox_out);
                }
            }
        } else if (i as u64) + 1 >= epoch_21 {
            // no sunset burn happened
            let pox_out = pox_out_opt.clone().unwrap();
            if recipients.len() >= 1 {
                for (_, amt) in recipients.into_iter() {
                    // NOTE: odd number of reward cycles
                    if !burnchain_config.is_in_prepare_phase((i + 2) as u64) {
                        assert_eq!(amt, pox_out);
                    }
                }
            }
        }
    }

    test_observer::clear();
    channel.stop_chains_coordinator();
}

#[test]
#[ignore]
fn transition_empty_blocks() {
    // very simple test to verify that the miner will keep making valid (empty) blocks after the
    // transition.  Really tests that the block-commits are well-formed before and after the epoch
    // transition.
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let epoch_2_05 = 210;
    let epoch_2_1 = 215;

    let (mut conf, miner_account) = neon_integration_test_conf();

    let mut epochs = core::STACKS_EPOCHS_REGTEST.to_vec();
    epochs[1].end_height = epoch_2_05;
    epochs[2].start_height = epoch_2_05;
    epochs[2].end_height = epoch_2_1;
    epochs[3].start_height = epoch_2_1;

    conf.node.mine_microblocks = false;
    conf.burnchain.max_rbf = 1000000;
    conf.miner.first_attempt_time_ms = 5_000;
    conf.miner.subsequent_attempt_time_ms = 10_000;
    conf.node.wait_time_for_blocks = 0;

    conf.burnchain.epochs = Some(epochs);

    let keychain = Keychain::default(conf.node.seed.clone());

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

    thread::spawn(move || run_loop.start(None, 0));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let tip_info = get_chain_info(&conf);
    let key_block_ptr = tip_info.burn_block_height as u32;
    let key_vtxindex = 1; // nothing else here but the coinbase

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let burnchain = Burnchain::regtest(&conf.get_burn_db_path());
    let mut bitcoin_controller = BitcoinRegtestController::new_dummy(conf.clone());

    let mut crossed_21_boundary = false;

    // these should all succeed across the epoch boundary
    for _i in 0..15 {
        // also, make *huge* block-commits with invalid marker bytes once we reach the new
        // epoch, and verify that it fails.
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

        if tip_info.burn_block_height == epoch_2_05 || tip_info.burn_block_height == epoch_2_1 {
            assert!(res);
            if tip_info.burn_block_height == epoch_2_1 {
                crossed_21_boundary = true;
            }
        } else {
            assert!(!res);
        }

        if tip_info.burn_block_height + 1 >= epoch_2_1 {
            let burn_fee_cap = 100000000; // 1 BTC
            let commit_outs = if !burnchain.is_in_prepare_phase(tip_info.burn_block_height + 1) {
                vec![
                    PoxAddress::standard_burn_address(conf.is_mainnet()),
                    PoxAddress::standard_burn_address(conf.is_mainnet()),
                ]
            } else {
                vec![PoxAddress::standard_burn_address(conf.is_mainnet())]
            };

            // let's commit
            let burn_parent_modulus =
                ((tip_info.burn_block_height + 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8;
            let op = BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
                sunset_burn: 0,
                block_header_hash: BlockHeaderHash([0xff; 32]),
                burn_fee: burn_fee_cap,
                input: (Txid([0; 32]), 0),
                apparent_sender: keychain.get_burnchain_signer(),
                key_block_ptr,
                key_vtxindex,
                memo: vec![0], // bad epoch marker
                new_seed: VRFSeed([0x11; 32]),
                parent_block_ptr: 0,
                parent_vtxindex: 0,
                // to be filled in
                vtxindex: 0,
                txid: Txid([0u8; 32]),
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash::zero(),
                burn_parent_modulus,
                commit_outs,
            });
            let mut op_signer = keychain.generate_op_signer();
            let res =
                bitcoin_controller.submit_operation(StacksEpochId::Epoch21, op, &mut op_signer, 1);
            assert!(res.is_some(), "Failed to submit block-commit");
        }

        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    }

    let account = get_account(&http_origin, &miner_account);
    assert!(crossed_21_boundary);
    assert_eq!(account.nonce, 16);

    channel.stop_chains_coordinator();
}
