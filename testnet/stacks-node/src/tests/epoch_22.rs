use std::collections::HashMap;
use std::env;
use std::thread;

use stacks::burnchains::Burnchain;
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::core::PEER_VERSION_EPOCH_2_2;
use stacks::core::STACKS_EPOCH_MAX;
use stacks::types::chainstate::StacksAddress;

use crate::config::EventKeyType;
use crate::config::EventObserverConfig;
use crate::config::InitialBalance;
use crate::neon;
use crate::tests::bitcoin_regtest::BitcoinCoreController;
use crate::tests::neon_integrations::*;
use crate::tests::*;
use crate::BitcoinRegtestController;
use crate::BurnchainController;
use stacks::core;

use crate::stacks_common::types::Address;
use crate::stacks_common::util::hash::bytes_to_hex;
use stacks::burnchains::PoxConstants;

use stacks_common::util::hash::Hash160;
use stacks_common::util::secp256k1::Secp256k1PublicKey;

use stacks::clarity_cli::vm_execute as execute;

use clarity::vm::types::PrincipalData;
use clarity::vm::ClarityVersion;

use stacks::util::sleep_ms;

use stacks::util_lib::boot::boot_code_id;
use stacks_common::types::chainstate::StacksBlockId;

#[test]
#[ignore]
/// Verify that it is acceptable to launch PoX-2 at the end of a reward cycle, and set v1 unlock
/// height to be at the start of the subsequent reward cycle.
///
/// Verify that PoX-1 stackers continue to receive PoX payouts after v1 unlock height, and that
/// PoX-2 stackers only begin receiving rewards at the start of the reward cycle following the one
/// that contains v1 unlock height.
///
/// Verify that both of the above work even if miners do not mine in the same block as the PoX-2
/// start height or v1 unlock height (e.g. suppose there's a delay).
///
/// Verify the (buggy) stacks-increase behavior in PoX-2, and then verify that Epoch-2.2
///  *fixes* that behavior after it activates.
///
/// Verification works using expected number of slots for burn and various PoX addresses.
///
fn pox_2_stack_increase_epoch22_fix() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let reward_cycle_len = 10;
    let prepare_phase_len = 3;
    let epoch_2_05 = 215;
    let epoch_2_1 = 230;
    let v1_unlock_height = 231;
    let epoch_2_2 = 255; // two blocks before next prepare phase.

    let stacked = 100_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let increase_by = 1_000_0000 * (core::MICROSTACKS_PER_STACKS as u64);

    let spender_sk = StacksPrivateKey::new();
    let spender_addr: PrincipalData = to_addr(&spender_sk).into();

    let spender_2_sk = StacksPrivateKey::new();
    let spender_2_addr: PrincipalData = to_addr(&spender_2_sk).into();

    let spender_3_sk = StacksPrivateKey::new();
    let spender_3_addr: PrincipalData = to_addr(&spender_3_sk).into();

    let mut initial_balances = vec![];

    initial_balances.push(InitialBalance {
        address: spender_addr.clone(),
        amount: stacked + increase_by + 100_000,
    });

    initial_balances.push(InitialBalance {
        address: spender_2_addr.clone(),
        amount: stacked + 100_000,
    });

    // create a third initial balance so that there's more liquid ustx than the stacked amount bug.
    //  otherwise, it surfaces the DoS vector.
    initial_balances.push(InitialBalance {
        address: spender_3_addr.clone(),
        amount: stacked + 100_000,
    });

    let pox_pubkey_1 = Secp256k1PublicKey::from_hex(
        "02f006a09b59979e2cb8449f58076152af6b124aa29b948a3714b8d5f15aa94ede",
    )
    .unwrap();
    let pox_pubkey_hash_1 = bytes_to_hex(
        &Hash160::from_node_public_key(&pox_pubkey_1)
            .to_bytes()
            .to_vec(),
    );

    let pox_pubkey_2 = Secp256k1PublicKey::from_hex(
        "03cd91307e16c10428dd0120d0a4d37f14d4e0097b3b2ea1651d7bd0fb109cd44b",
    )
    .unwrap();
    let pox_pubkey_hash_2 = bytes_to_hex(
        &Hash160::from_node_public_key(&pox_pubkey_2)
            .to_bytes()
            .to_vec(),
    );

    let pox_pubkey_3 = Secp256k1PublicKey::from_hex(
        "0317782e663c77fb02ebf46a3720f41a70f5678ad185974a456d35848e275fe56b",
    )
    .unwrap();
    let pox_pubkey_hash_3 = bytes_to_hex(
        &Hash160::from_node_public_key(&pox_pubkey_3)
            .to_bytes()
            .to_vec(),
    );

    let (mut conf, _) = neon_integration_test_conf();

    // we'll manually post a forked stream to the node
    conf.node.mine_microblocks = false;
    conf.burnchain.max_rbf = 1000000;
    conf.node.wait_time_for_microblocks = 0;
    conf.node.microblock_frequency = 1_000;
    conf.miner.first_attempt_time_ms = 2_000;
    conf.miner.subsequent_attempt_time_ms = 5_000;
    conf.node.wait_time_for_blocks = 1_000;
    conf.miner.wait_for_block_download = false;

    conf.miner.min_tx_fee = 1;
    conf.miner.first_attempt_time_ms = i64::max_value() as u64;
    conf.miner.subsequent_attempt_time_ms = i64::max_value() as u64;

    test_observer::spawn();

    conf.events_observers.push(EventObserverConfig {
        endpoint: format!("localhost:{}", test_observer::EVENT_OBSERVER_PORT),
        events_keys: vec![EventKeyType::AnyEvent],
    });
    conf.initial_balances.append(&mut initial_balances);

    let mut epochs = core::STACKS_EPOCHS_REGTEST.to_vec();
    epochs[1].end_height = epoch_2_05;
    epochs[2].start_height = epoch_2_05;
    epochs[2].end_height = epoch_2_1;
    epochs[3].start_height = epoch_2_1;
    epochs[3].end_height = epoch_2_2;
    epochs.push(StacksEpoch {
        epoch_id: StacksEpochId::Epoch22,
        start_height: epoch_2_2,
        end_height: STACKS_EPOCH_MAX,
        block_limit: epochs[3].block_limit.clone(),
        network_epoch: PEER_VERSION_EPOCH_2_2,
    });
    conf.burnchain.epochs = Some(epochs);

    let mut burnchain_config = Burnchain::regtest(&conf.get_burn_db_path());

    let pox_constants = PoxConstants::new(
        reward_cycle_len,
        prepare_phase_len,
        4 * prepare_phase_len / 5,
        5,
        15,
        u64::max_value() - 2,
        u64::max_value() - 1,
        v1_unlock_height as u32,
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

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let runloop_burnchain = burnchain_config.clone();

    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();

    thread::spawn(move || run_loop.start(Some(runloop_burnchain), 0));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // push us to block 205
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // stack right away
    let sort_height = channel.get_sortitions_processed();
    let pox_addr_tuple_1 = execute(
        &format!("{{ hashbytes: 0x{}, version: 0x00 }}", pox_pubkey_hash_1,),
        ClarityVersion::Clarity2,
    )
    .unwrap()
    .unwrap();

    let pox_addr_tuple_3 = execute(
        &format!("{{ hashbytes: 0x{}, version: 0x00 }}", pox_pubkey_hash_3,),
        ClarityVersion::Clarity2,
    )
    .unwrap()
    .unwrap();

    let tx = make_contract_call(
        &spender_sk,
        0,
        3000,
        &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
        "pox",
        "stack-stx",
        &[
            Value::UInt(stacked.into()),
            pox_addr_tuple_1.clone(),
            Value::UInt(sort_height as u128),
            Value::UInt(12),
        ],
    );

    info!("Submit 2.05 stacking tx to {:?}", &http_origin);
    submit_tx(&http_origin, &tx);

    // wait until just before epoch 2.1
    loop {
        let tip_info = get_chain_info(&conf);
        if tip_info.burn_block_height >= epoch_2_1 - 2 {
            break;
        }
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    }

    // skip a couple sortitions
    btc_regtest_controller.bootstrap_chain(4);
    sleep_ms(5000);

    let sort_height = channel.get_sortitions_processed();
    assert!(sort_height > epoch_2_1);
    assert!(sort_height > v1_unlock_height);

    // *now* advance to 2.1
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    info!("Test passed processing 2.1");

    let sort_height = channel.get_sortitions_processed();
    let pox_addr_tuple_2 = execute(
        &format!("{{ hashbytes: 0x{}, version: 0x00 }}", pox_pubkey_hash_2,),
        ClarityVersion::Clarity2,
    )
    .unwrap()
    .unwrap();
    let tx = make_contract_call(
        &spender_sk,
        1,
        3000,
        &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
        "pox-2",
        "stack-stx",
        &[
            Value::UInt(stacked.into()),
            pox_addr_tuple_2.clone(),
            Value::UInt(sort_height as u128),
            Value::UInt(12),
        ],
    );

    info!("Submit 2.1 stacking tx to {:?}", &http_origin);
    submit_tx(&http_origin, &tx);

    let tx = make_contract_call(
        &spender_2_sk,
        0,
        3000,
        &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
        "pox-2",
        "stack-stx",
        &[
            Value::UInt(stacked.into()),
            pox_addr_tuple_3.clone(),
            Value::UInt(sort_height as u128),
            Value::UInt(10),
        ],
    );

    info!("Submit 2.1 stacking tx to {:?}", &http_origin);
    submit_tx(&http_origin, &tx);

    // that it can mine _at all_ is a success criterion
    let mut last_block_height = get_chain_info(&conf).burn_block_height;
    for _i in 0..5 {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        let tip_info = get_chain_info(&conf);
        if tip_info.burn_block_height > last_block_height {
            last_block_height = tip_info.burn_block_height;
        } else {
            panic!("FATAL: failed to mine");
        }
    }

    // invoke stack-increase
    let tx = make_contract_call(
        &spender_sk,
        2,
        3000,
        &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
        "pox-2",
        "stack-increase",
        &[Value::UInt(increase_by.into())],
    );

    info!("Submit 2.1 stack-increase tx to {:?}", &http_origin);
    submit_tx(&http_origin, &tx);

    for _i in 0..15 {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        let tip_info = get_chain_info(&conf);
        if tip_info.burn_block_height > last_block_height {
            last_block_height = tip_info.burn_block_height;
        } else {
            panic!("FATAL: failed to mine");
        }
    }

    // invoke stack-increase again, in Epoch-2.2, it should
    //  runtime abort
    let aborted_increase_nonce = 3;
    let tx = make_contract_call(
        &spender_sk,
        aborted_increase_nonce,
        3000,
        &StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
        "pox-2",
        "stack-increase",
        &[Value::UInt(5000)],
    );

    info!("Submit 2.1 stack-increase tx to {:?}", &http_origin);
    submit_tx(&http_origin, &tx);

    // finish the cycle after the 2.2 transition,
    //  and mine two more cycles
    for _i in 0..25 {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        let tip_info = get_chain_info(&conf);
        if tip_info.burn_block_height > last_block_height {
            last_block_height = tip_info.burn_block_height;
        } else {
            panic!("FATAL: failed to mine");
        }
    }

    let tip_info = get_chain_info(&conf);
    let tip = StacksBlockId::new(&tip_info.stacks_tip_consensus_hash, &tip_info.stacks_tip);

    let (mut chainstate, _) = StacksChainState::open(
        false,
        conf.burnchain.chain_id,
        &conf.get_chainstate_path_str(),
        None,
    )
    .unwrap();
    let sortdb = btc_regtest_controller.sortdb_mut();

    let mut reward_cycle_pox_addrs = HashMap::new();

    info!("Last tip height = {}", tip_info.burn_block_height);

    for height in 211..tip_info.burn_block_height {
        let reward_cycle = pox_constants
            .block_height_to_reward_cycle(burnchain_config.first_block_height, height)
            .unwrap();

        if !reward_cycle_pox_addrs.contains_key(&reward_cycle) {
            reward_cycle_pox_addrs.insert(reward_cycle, HashMap::new());
        }

        let iconn = sortdb.index_conn();
        let pox_addrs = chainstate
            .clarity_eval_read_only(
                &iconn,
                &tip,
                &boot_code_id("pox-2", false),
                &format!("(get-burn-block-info? pox-addrs u{})", height),
            )
            .expect_optional()
            .unwrap()
            .expect_tuple()
            .get_owned("addrs")
            .unwrap()
            .expect_list();

        debug!("Test burnchain height {}", height);
        if !burnchain_config.is_in_prepare_phase(height) {
            if pox_addrs.len() > 0 {
                assert_eq!(pox_addrs.len(), 2);
                let pox_addr_0 = PoxAddress::try_from_pox_tuple(false, &pox_addrs[0]).unwrap();
                let pox_addr_1 = PoxAddress::try_from_pox_tuple(false, &pox_addrs[1]).unwrap();

                if let Some(pox_slot_count) = reward_cycle_pox_addrs
                    .get_mut(&reward_cycle)
                    .unwrap()
                    .get_mut(&pox_addr_0)
                {
                    *pox_slot_count += 1;
                } else {
                    reward_cycle_pox_addrs
                        .get_mut(&reward_cycle)
                        .unwrap()
                        .insert(pox_addr_0, 1);
                }

                if let Some(pox_slot_count) = reward_cycle_pox_addrs
                    .get_mut(&reward_cycle)
                    .unwrap()
                    .get_mut(&pox_addr_1)
                {
                    *pox_slot_count += 1;
                } else {
                    reward_cycle_pox_addrs
                        .get_mut(&reward_cycle)
                        .unwrap()
                        .insert(pox_addr_1, 1);
                }
            }

            // let mut have_expected_payout = false;
            // if height < epoch_2_1 + (reward_cycle_len as u64) {
            //         for addr_tuple in pox_addrs {
            //             // can either pay to pox tuple 1, or burn
            //             assert_ne!(addr_tuple, pox_addr_tuple_2);
            //             if addr_tuple == pox_addr_tuple_1 {
            //                 have_expected_payout = true;
            //             }
            //         }
            //     }
            // } else {
            //     if pox_addrs.len() > 0 {
            //         assert_eq!(pox_addrs.len(), 2);
            //         for addr_tuple in pox_addrs {
            //             // can either pay to pox tuple 2, or burn
            //             assert_ne!(addr_tuple, pox_addr_tuple_1);
            //             if addr_tuple == pox_addr_tuple_2 {
            //                 have_expected_payout = true;
            //             }
            //         }
            //     }
            // }
            // assert!(have_expected_payout);
        }
    }

    let reward_cycle_min = *reward_cycle_pox_addrs.keys().min().unwrap();
    let reward_cycle_max = *reward_cycle_pox_addrs.keys().max().unwrap();

    let pox_addr_1 = PoxAddress::Standard(
        StacksAddress::new(26, Hash160::from_hex(&pox_pubkey_hash_1).unwrap()),
        Some(AddressHashMode::SerializeP2PKH),
    );
    let pox_addr_2 = PoxAddress::Standard(
        StacksAddress::new(26, Hash160::from_hex(&pox_pubkey_hash_2).unwrap()),
        Some(AddressHashMode::SerializeP2PKH),
    );
    let pox_addr_3 = PoxAddress::Standard(
        StacksAddress::new(26, Hash160::from_hex(&pox_pubkey_hash_3).unwrap()),
        Some(AddressHashMode::SerializeP2PKH),
    );
    let burn_pox_addr = PoxAddress::Standard(
        StacksAddress::new(
            26,
            Hash160::from_hex("0000000000000000000000000000000000000000").unwrap(),
        ),
        Some(AddressHashMode::SerializeP2PKH),
    );

    let expected_slots = HashMap::from([
        (
            21u64,
            HashMap::from([(pox_addr_1.clone(), 13u64), (burn_pox_addr.clone(), 1)]),
        ),
        (
            22u64,
            HashMap::from([(pox_addr_1.clone(), 13u64), (burn_pox_addr.clone(), 1)]),
        ),
        (
            23u64,
            HashMap::from([(pox_addr_1.clone(), 13u64), (burn_pox_addr.clone(), 1)]),
        ),
        // cycle 24 is the first 2.1, it should have pox_2 and pox_3 with equal
        //  slots (because increase hasn't gone into effect yet) and 2 burn slots
        (
            24,
            HashMap::from([
                (pox_addr_2.clone(), 6u64),
                (pox_addr_3.clone(), 6),
                (burn_pox_addr.clone(), 2),
            ]),
        ),
        // stack-increase has been invoked, and so the reward set is skewed.
        //  pox_addr_2 should get the majority of slots (~ 67%)
        (
            25,
            HashMap::from([
                (pox_addr_2.clone(), 9u64),
                (pox_addr_3.clone(), 4),
                (burn_pox_addr.clone(), 1),
            ]),
        ),
        // Epoch 2.2 has started, so the reward set should be fixed.
        //  pox_addr_2 should get 1 extra slot, because stack-increase
        //  did increase their stacked amount
        (
            26,
            HashMap::from([
                (pox_addr_2.clone(), 7u64),
                (pox_addr_3.clone(), 6),
                (burn_pox_addr.clone(), 1),
            ]),
        ),
        (
            27,
            HashMap::from([
                (pox_addr_2.clone(), 7u64),
                (pox_addr_3.clone(), 6),
                (burn_pox_addr.clone(), 1),
            ]),
        ),
    ]);

    for reward_cycle in reward_cycle_min..(reward_cycle_max + 1) {
        let cycle_counts = &reward_cycle_pox_addrs[&reward_cycle];
        assert_eq!(cycle_counts.len(), expected_slots[&reward_cycle].len(), "The number of expected PoX addresses in reward cycle {} is mismatched with the actual count.", reward_cycle);
        for (pox_addr, slots) in cycle_counts.iter() {
            assert_eq!(
                *slots,
                expected_slots[&reward_cycle][&pox_addr],
                "The number of expected slots for PoX address {} in reward cycle {} is mismatched with the actual count.",
                &pox_addr,
                reward_cycle,
            );
            info!("PoX payment received"; "cycle" => reward_cycle, "pox_addr" => %pox_addr, "slots" => slots);
        }
    }

    let mut abort_tested = false;
    let blocks = test_observer::get_blocks();
    for block in blocks {
        let transactions = block.get("transactions").unwrap().as_array().unwrap();
        for tx in transactions {
            let raw_tx = tx.get("raw_tx").unwrap().as_str().unwrap();
            if raw_tx == "0x00" {
                continue;
            }
            let tx_bytes = hex_bytes(&raw_tx[2..]).unwrap();
            let parsed =
                StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
            let tx_sender = PrincipalData::from(parsed.auth.origin().address_testnet());
            if &tx_sender == &spender_addr
                && parsed.auth.get_origin_nonce() == aborted_increase_nonce
            {
                let contract_call = match &parsed.payload {
                    TransactionPayload::ContractCall(cc) => cc,
                    _ => panic!("Expected aborted_increase_nonce to be a contract call"),
                };
                assert_eq!(contract_call.contract_name.as_str(), "pox-2");
                assert_eq!(contract_call.function_name.as_str(), "stack-increase");
                let result = Value::try_deserialize_hex_untyped(
                    tx.get("raw_result").unwrap().as_str().unwrap(),
                )
                .unwrap();
                assert_eq!(result.to_string(), "(err none)");
                abort_tested = true;
            }
        }
    }

    assert!(abort_tested, "The stack-increase transaction must have been aborted, and it must have been tested in the tx receipts");

    test_observer::clear();
    channel.stop_chains_coordinator();
}
