use std::thread;
use std::time::{Duration, Instant};

use clarity::boot_util::boot_code_addr;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::Value;
use rand_core::OsRng;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::nakamoto::NakamotoChainState;
use stacks::chainstate::stacks::boot::POX_4_NAME;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey};
use stacks_common::types::StacksEpochId;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::to_hex;
use wsts::curve::point::Point;
use wsts::curve::scalar::Scalar;

use super::MockamotoNode;
use crate::config::{EventKeyType, EventObserverConfig};
use crate::neon_node::PeerThread;
use crate::tests::neon_integrations::{submit_tx, test_observer};
use crate::tests::{make_contract_call, make_stacks_transfer, to_addr};
use crate::{Config, ConfigFile};

#[test]
fn observe_100_blocks() {
    let mut conf = Config::from_config_file(ConfigFile::mockamoto()).unwrap();
    conf.node.working_dir = format!(
        "/tmp/stacks-node-tests/mock_observe_100_blocks-{}",
        get_epoch_time_secs()
    );
    conf.node.rpc_bind = "127.0.0.1:19343".into();
    conf.node.p2p_bind = "127.0.0.1:19344".into();
    conf.node.mockamoto_time_ms = 10;

    let submitter_sk = StacksPrivateKey::from_seed(&[1]);
    let submitter_addr = to_addr(&submitter_sk);
    conf.add_initial_balance(submitter_addr.to_string(), 1_000_000);
    let recipient_addr = StacksAddress::burn_address(false).into();

    let observer_port = 19300;
    test_observer::spawn_at(observer_port);
    conf.events_observers.insert(EventObserverConfig {
        endpoint: format!("localhost:{observer_port}"),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let mut mockamoto = MockamotoNode::new(&conf).unwrap();
    let globals = mockamoto.globals.clone();

    let mut mempool = PeerThread::connect_mempool_db(&conf);
    let (mut chainstate, _) = StacksChainState::open(
        conf.is_mainnet(),
        conf.burnchain.chain_id,
        &conf.get_chainstate_path_str(),
        None,
    )
    .unwrap();
    let burnchain = conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    let start = Instant::now();

    let node_thread = thread::Builder::new()
        .name("mockamoto-main".into())
        .spawn(move || mockamoto.run())
        .expect("FATAL: failed to start mockamoto main thread");

    // make a transfer tx to test that the mockamoto miner picks up txs from the mempool
    let tx_fee = 200;
    let transfer_tx = make_stacks_transfer(&submitter_sk, 0, tx_fee, &recipient_addr, 100);
    let transfer_tx_hex = format!("0x{}", to_hex(&transfer_tx));

    let mut sent_tx = false;

    // complete within 2 minutes or abort
    let completed = loop {
        if Instant::now().duration_since(start) > Duration::from_secs(120) {
            break false;
        }
        let latest_block = test_observer::get_blocks().pop();
        thread::sleep(Duration::from_secs(1));
        let Some(ref latest_block) = latest_block else {
            info!("No block observed yet!");
            continue;
        };
        let stacks_block_height = latest_block.get("block_height").unwrap().as_u64().unwrap();
        info!("Block height observed: {stacks_block_height}");

        if stacks_block_height >= 1 && !sent_tx {
            let tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
                .unwrap()
                .unwrap();
            // Bypass admission checks
            mempool
                .submit_raw(
                    &mut chainstate,
                    &sortdb,
                    &tip.consensus_hash,
                    &tip.anchored_header.block_hash(),
                    transfer_tx.clone(),
                    &ExecutionCost::max_value(),
                    &StacksEpochId::Epoch30,
                )
                .unwrap();

            sent_tx = true;
        }

        if stacks_block_height >= 100 {
            break true;
        }
    };

    globals.signal_stop();

    node_thread
        .join()
        .expect("Failed to join node thread to exit");

    let transfer_tx_included = test_observer::get_blocks()
        .into_iter()
        .find(|block_json| {
            block_json["transactions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|tx_json| tx_json["raw_tx"].as_str() == Some(&transfer_tx_hex))
                .is_some()
        })
        .is_some();

    assert!(
        transfer_tx_included,
        "Mockamoto node failed to include the transfer tx"
    );

    assert!(
        completed,
        "Mockamoto node failed to produce and announce 100 blocks before timeout"
    );
}

#[test]
fn mempool_rpc_submit() {
    let mut conf = Config::from_config_file(ConfigFile::mockamoto()).unwrap();
    conf.node.working_dir = format!(
        "/tmp/stacks-node-tests/mempool_rpc_submit-{}",
        get_epoch_time_secs()
    );
    conf.node.rpc_bind = "127.0.0.1:19743".into();
    conf.node.p2p_bind = "127.0.0.1:19744".into();
    conf.node.mockamoto_time_ms = 10;

    let submitter_sk = StacksPrivateKey::from_seed(&[1]);
    let submitter_addr = to_addr(&submitter_sk);
    conf.add_initial_balance(submitter_addr.to_string(), 1_000);
    let recipient_addr = StacksAddress::burn_address(false).into();

    let observer_port = 19800;
    test_observer::spawn_at(observer_port);
    conf.events_observers.insert(EventObserverConfig {
        endpoint: format!("localhost:{observer_port}"),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let mut mockamoto = MockamotoNode::new(&conf).unwrap();
    let globals = mockamoto.globals.clone();

    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    let start = Instant::now();

    let node_thread = thread::Builder::new()
        .name("mockamoto-main".into())
        .spawn(move || mockamoto.run())
        .expect("FATAL: failed to start mockamoto main thread");

    // make a transfer tx to test that the mockamoto miner picks up txs from the mempool
    let tx_fee = 200;
    let transfer_tx = make_stacks_transfer(&submitter_sk, 0, tx_fee, &recipient_addr, 100);
    let transfer_tx_hex = format!("0x{}", to_hex(&transfer_tx));

    let mut sent_tx = false;

    // complete within 2 minutes or abort
    let completed = loop {
        if Instant::now().duration_since(start) > Duration::from_secs(120) {
            break false;
        }
        let latest_block = test_observer::get_blocks().pop();
        thread::sleep(Duration::from_secs(1));
        let Some(ref latest_block) = latest_block else {
            info!("No block observed yet!");
            continue;
        };
        let stacks_block_height = latest_block.get("block_height").unwrap().as_u64().unwrap();
        info!("Block height observed: {stacks_block_height}");

        if stacks_block_height >= 1 && !sent_tx {
            // Enforce admission checks by utilizing the RPC endpoint
            submit_tx(&http_origin, &transfer_tx);
            sent_tx = true;
        }

        if stacks_block_height >= 100 {
            break true;
        }
    };

    globals.signal_stop();

    node_thread
        .join()
        .expect("Failed to join node thread to exit");

    let transfer_tx_included = test_observer::get_blocks()
        .into_iter()
        .find(|block_json| {
            block_json["transactions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|tx_json| tx_json["raw_tx"].as_str() == Some(&transfer_tx_hex))
                .is_some()
        })
        .is_some();

    assert!(
        transfer_tx_included,
        "Mockamoto node failed to include the transfer tx"
    );

    assert!(
        completed,
        "Mockamoto node failed to produce and announce 100 blocks before timeout"
    );
}

#[test]
fn observe_set_aggregate_key() {
    let mut conf = Config::from_config_file(ConfigFile::mockamoto()).unwrap();
    conf.node.mockamoto_time_ms = 10;

    let submitter_sk = StacksPrivateKey::from_seed(&[1]);
    let submitter_addr = to_addr(&submitter_sk);
    conf.add_initial_balance(submitter_addr.to_string(), 1_000);

    test_observer::spawn();
    let observer_port = test_observer::EVENT_OBSERVER_PORT;
    conf.events_observers.insert(EventObserverConfig {
        endpoint: format!("localhost:{observer_port}"),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let mut mockamoto = MockamotoNode::new(&conf).unwrap();
    // Get the aggregate public key of the original reward cycle to compare against
    let orig_key = mockamoto.self_signer.aggregate_public_key;

    let globals = mockamoto.globals.clone();

    let mut mempool = PeerThread::connect_mempool_db(&conf);
    let (mut chainstate, _) = StacksChainState::open(
        conf.is_mainnet(),
        conf.burnchain.chain_id,
        &conf.get_chainstate_path_str(),
        None,
    )
    .unwrap();
    let burnchain = conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(mockamoto.sortdb.conn()).unwrap();

    let start = Instant::now();
    // Get the reward cycle of the sortition tip
    let reward_cycle = mockamoto
        .sortdb
        .pox_constants
        .block_height_to_reward_cycle(
            mockamoto.sortdb.first_block_height,
            sortition_tip.block_height,
        )
        .expect(
            format!(
                "Failed to determine reward cycle of block height: {}",
                sortition_tip.block_height
            )
            .as_str(),
        );

    let node_thread = thread::Builder::new()
        .name("mockamoto-main".into())
        .spawn(move || {
            mockamoto.run();
            let aggregate_key_block_header = NakamotoChainState::get_canonical_block_header(
                mockamoto.chainstate.db(),
                &mockamoto.sortdb,
            )
            .unwrap()
            .unwrap();
            // Get the aggregate public key of the original reward cycle
            let orig_aggregate_key = mockamoto
                .chainstate
                .get_aggregate_public_key_pox_4(
                    &mockamoto.sortdb,
                    &aggregate_key_block_header.index_block_hash(),
                    reward_cycle,
                )
                .unwrap();
            // Get the aggregate public key of the next reward cycle that we manually overwrote
            let new_aggregate_key = mockamoto
                .chainstate
                .get_aggregate_public_key_pox_4(
                    &mockamoto.sortdb,
                    &aggregate_key_block_header.index_block_hash(),
                    reward_cycle + 1,
                )
                .unwrap();
            (orig_aggregate_key, new_aggregate_key)
        })
        .expect("FATAL: failed to start mockamoto main thread");

    // complete within 5 seconds or abort (we are only observing one block)
    let completed = loop {
        if Instant::now().duration_since(start) > Duration::from_secs(120) {
            break false;
        }
        let latest_block = test_observer::get_blocks().pop();
        thread::sleep(Duration::from_secs(1));
        let Some(ref latest_block) = latest_block else {
            info!("No block observed yet!");
            continue;
        };
        let stacks_block_height = latest_block.get("block_height").unwrap().as_u64().unwrap();
        info!("Block height observed: {stacks_block_height}");
        if stacks_block_height >= 100 {
            break true;
        }
    };

    globals.signal_stop();

    let (orig_aggregate_key, new_aggregate_key) = node_thread
        .join()
        .expect("Failed to join node thread to exit");

    assert!(
        completed,
        "Mockamoto node failed to produce and announce its block before timeout"
    );

    // Did we set and retrieve the aggregate key correctly?
    assert_eq!(orig_aggregate_key.unwrap(), orig_key);
    assert_eq!(new_aggregate_key.unwrap(), orig_key);
}
