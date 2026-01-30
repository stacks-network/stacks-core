// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::net::TcpListener;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Instant, SystemTime};

use clarity::boot_util::boot_code_id;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::events::SmartContractEventData;
use clarity::vm::types::StacksAddressExtensions;
use clarity::vm::Value;
use rusqlite::Connection;
use serial_test::serial;
use stacks::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks::burnchains::{PoxConstants, Txid};
use stacks::chainstate::burn::operations::{BlockstackOperationType, PreStxOp};
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use stacks::chainstate::stacks::db::{StacksBlockHeaderTypes, StacksHeaderInfo};
use stacks::chainstate::stacks::events::{StacksBlockEventData, TransactionOrigin};
use stacks::chainstate::stacks::{
    SinglesigHashMode, SinglesigSpendingCondition, StacksBlock, TenureChangeCause,
    TenureChangePayload, TokenTransferMemo, TransactionAnchorMode, TransactionAuth,
    TransactionPayload, TransactionPostConditionMode, TransactionPublicKeyEncoding,
    TransactionSpendingCondition, TransactionVersion,
};
use stacks::net::http::HttpRequestContents;
use stacks::net::httpcore::{send_http_request, StacksHttpRequest};
use stacks::types::chainstate::{
    BlockHeaderHash, StacksAddress, StacksPrivateKey, StacksPublicKey,
};
use stacks::types::net::PeerHost;
use stacks::util::hash::{Hash160, Sha512Trunc256Sum};
use stacks::util::secp256k1::MessageSignature;
use stacks_common::bitvec::BitVec;
use stacks_common::types::chainstate::{BurnchainHeaderHash, StacksBlockId};
use tempfile::tempdir;
use tiny_http::{Method, Response, Server, StatusCode};

use crate::event_dispatcher::payloads::*;
use crate::event_dispatcher::*;

#[test]
fn build_block_processed_event() {
    let filtered_events = vec![];
    let block = StacksBlock::genesis_block();
    let metadata = StacksHeaderInfo::regtest_genesis();
    let receipts = vec![];
    let parent_index_hash = StacksBlockId([0; 32]);
    let winner_txid = Txid([0; 32]);
    let mature_rewards = serde_json::Value::Array(vec![]);
    let parent_burn_block_hash = BurnchainHeaderHash([0; 32]);
    let parent_burn_block_height = 0;
    let parent_burn_block_timestamp = 0;
    let anchored_consumed = ExecutionCost::ZERO;
    let mblock_confirmed_consumed = ExecutionCost::ZERO;
    let pox_constants = PoxConstants::testnet_default();
    let signer_bitvec = BitVec::zeros(2).expect("Failed to create BitVec with length 2");
    let block_timestamp = Some(123456);
    let coinbase_height = 1234;

    let payload = make_new_block_processed_payload(
        filtered_events,
        &block.into(),
        &metadata,
        &receipts,
        &parent_index_hash,
        &winner_txid,
        &mature_rewards,
        &parent_burn_block_hash,
        parent_burn_block_height,
        parent_burn_block_timestamp,
        &anchored_consumed,
        &mblock_confirmed_consumed,
        &pox_constants,
        &None,
        &Some(signer_bitvec.clone()),
        block_timestamp,
        coinbase_height,
    );
    assert_eq!(
        payload
            .get("pox_v1_unlock_height")
            .unwrap()
            .as_u64()
            .unwrap(),
        pox_constants.v1_unlock_height as u64
    );

    let expected_bitvec_str = serde_json::to_value(signer_bitvec)
        .unwrap_or_default()
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        payload.get("signer_bitvec").unwrap().as_str().unwrap(),
        expected_bitvec_str
    );
}

#[test]
fn test_block_processed_event_nakamoto() {
    let filtered_events = vec![];
    let mut block_header = NakamotoBlockHeader::empty();
    let signer_signature = vec![
        MessageSignature::from_bytes(&[0; 65]).unwrap(),
        MessageSignature::from_bytes(&[1; 65]).unwrap(),
    ];
    block_header.signer_signature = signer_signature.clone();
    let block = NakamotoBlock {
        header: block_header.clone(),
        txs: vec![],
    };
    let mut metadata = StacksHeaderInfo::regtest_genesis();
    metadata.anchored_header = StacksBlockHeaderTypes::Nakamoto(block_header);
    let receipts = vec![];
    let parent_index_hash = StacksBlockId([0; 32]);
    let winner_txid = Txid([0; 32]);
    let mature_rewards = serde_json::Value::Array(vec![]);
    let parent_burn_block_hash = BurnchainHeaderHash([0; 32]);
    let parent_burn_block_height = 0;
    let parent_burn_block_timestamp = 0;
    let anchored_consumed = ExecutionCost::ZERO;
    let mblock_confirmed_consumed = ExecutionCost::ZERO;
    let pox_constants = PoxConstants::testnet_default();
    let signer_bitvec = BitVec::zeros(2).expect("Failed to create BitVec with length 2");
    let block_timestamp = Some(123456);
    let coinbase_height = 1234;

    let payload = make_new_block_processed_payload(
        filtered_events,
        &StacksBlockEventData::from((block, BlockHeaderHash([0; 32]))),
        &metadata,
        &receipts,
        &parent_index_hash,
        &winner_txid,
        &mature_rewards,
        &parent_burn_block_hash,
        parent_burn_block_height,
        parent_burn_block_timestamp,
        &anchored_consumed,
        &mblock_confirmed_consumed,
        &pox_constants,
        &None,
        &Some(signer_bitvec),
        block_timestamp,
        coinbase_height,
    );

    let event_signer_signature = payload
        .get("signer_signature")
        .unwrap()
        .as_array()
        .expect("Expected signer_signature to be an array")
        .iter()
        .cloned()
        .map(serde_json::from_value::<MessageSignature>)
        .collect::<Result<Vec<_>, _>>()
        .expect("Unable to deserialize array of MessageSignature");
    assert_eq!(event_signer_signature, signer_signature);
}

#[test]
fn test_send_request_connect_timeout() {
    let timeout_duration = Duration::from_secs(3);

    // Start measuring time
    let start_time = Instant::now();

    let host = "10.255.255.1"; // non-routable IP for timeout
    let port = 80;

    let peerhost: PeerHost = format!("{host}:{port}")
        .parse()
        .unwrap_or(PeerHost::DNS(host.to_string(), port));
    let mut request = StacksHttpRequest::new_for_peer(
        peerhost,
        "POST".into(),
        "/".into(),
        HttpRequestContents::new().payload_json(serde_json::from_slice(b"{}").unwrap()),
    )
    .unwrap_or_else(|_| panic!("FATAL: failed to encode infallible data as HTTP request"));
    request.add_header("Connection".into(), "close".into());

    // Attempt to send a request with a timeout
    let result = send_http_request(host, port, request, timeout_duration);

    // Measure the elapsed time
    let elapsed_time = start_time.elapsed();

    // Assert that the connection attempt timed out
    assert!(
        result.is_err(),
        "Expected a timeout error, but got {result:?}"
    );
    assert_eq!(
        result.unwrap_err().kind(),
        std::io::ErrorKind::TimedOut,
        "Expected a TimedOut error"
    );

    // Assert that the elapsed time is within an acceptable range
    assert!(
        elapsed_time >= timeout_duration,
        "Timeout occurred too quickly"
    );
    assert!(
        elapsed_time < timeout_duration + Duration::from_secs(1),
        "Timeout took too long"
    );
}

fn get_random_port() -> u16 {
    // Bind to a random port by specifying port 0, then retrieve the port assigned by the OS
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to a random port");
    listener.local_addr().unwrap().port()
}

#[test]
#[serial]
fn test_process_pending_payloads() {
    use mockito::Matcher;

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("event_observers.sqlite");
    let mut server = mockito::Server::new();
    let endpoint = server.host_with_port();
    info!("endpoint: {}", endpoint);
    let timeout = Duration::from_secs(5);

    let mut dispatcher = EventDispatcher::new_with_custom_queue_size(dir.path().to_path_buf(), 0);

    dispatcher.register_observer(&EventObserverConfig {
        endpoint: endpoint.clone(),
        events_keys: vec![EventKeyType::AnyEvent],
        timeout_ms: timeout.as_millis() as u64,
        disable_retries: false,
    });

    let conn =
        EventDispatcherDbConnection::new(&db_path).expect("Failed to initialize the database");

    let payload = json!({"key": "value"});
    let payload_bytes = serde_json::to_vec(&payload).expect("Failed to serialize payload");
    let timeout = Duration::from_secs(5);

    let _m = server
        .mock("POST", "/api")
        .match_header("content-type", Matcher::Regex("application/json.*".into()))
        .match_body(Matcher::Json(payload.clone()))
        .with_status(200)
        .create();

    let url = format!("{}/api", &server.url());

    let data = EventRequestData {
        url,
        payload_bytes: payload_bytes.into(),
        timeout,
    };

    TEST_EVENT_OBSERVER_SKIP_RETRY.set(false);

    // Insert payload
    conn.insert_payload(&data, SystemTime::now())
        .expect("Failed to insert payload");

    // Process pending payloads
    dispatcher.process_pending_payloads();

    // Verify that the pending payloads list is empty
    let pending_payloads = conn
        .get_pending_payloads()
        .expect("Failed to get pending payloads");
    assert_eq!(pending_payloads.len(), 0, "Expected no pending payloads");

    // Verify that the mock was called
    _m.assert();
}

#[test]
fn pending_payloads_are_skipped_if_url_does_not_match() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("event_observers.sqlite");

    let mut server = mockito::Server::new();
    let endpoint = server.host_with_port();
    let timeout = Duration::from_secs(5);
    let mut dispatcher = EventDispatcher::new(dir.path().to_path_buf());

    dispatcher.register_observer(&EventObserverConfig {
        endpoint: endpoint.clone(),
        events_keys: vec![EventKeyType::AnyEvent],
        timeout_ms: timeout.as_millis() as u64,
        disable_retries: false,
    });

    let conn =
        EventDispatcherDbConnection::new(&db_path).expect("Failed to initialize the database");

    let payload = json!({"key": "value"});
    let payload_bytes = serde_json::to_vec(&payload).expect("Failed to serialize payload");
    let timeout = Duration::from_secs(5);

    let mock = server
        .mock("POST", "/api")
        .match_header(
            "content-type",
            mockito::Matcher::Regex("application/json.*".into()),
        )
        .match_body(mockito::Matcher::Json(payload.clone()))
        .with_status(200)
        .expect(0) // Expect 0 calls to this endpoint
        .create();

    // Use a different URL than the observer's endpoint
    let url = "http://different-domain.com/api".to_string();

    let data = EventRequestData {
        url,
        payload_bytes: payload_bytes.into(),
        timeout,
    };

    conn.insert_payload(&data, SystemTime::now())
        .expect("Failed to insert payload");

    dispatcher.process_pending_payloads();

    let pending_payloads = conn
        .get_pending_payloads()
        .expect("Failed to get pending payloads");
    // Verify that the pending payload is no longer in the database,
    // because this observer is no longer registered.
    assert_eq!(
        pending_payloads.len(),
        0,
        "Expected payload to be removed from database since URL didn't match"
    );

    mock.assert();
}

#[test]
fn test_new_event_dispatcher_with_db() {
    let dir = tempdir().unwrap();
    let working_dir = dir.path().to_path_buf();
    let expected_db_path = working_dir.join("event_observers.sqlite");

    assert!(!expected_db_path.exists(), "Database file already exists");

    let dispatcher = EventDispatcher::new(working_dir.clone());

    assert_eq!(dispatcher.db_path, expected_db_path.clone());

    // Verify that the database was initialized
    assert!(expected_db_path.exists(), "Database file was not created");
}

#[test]
fn test_new_event_observer() {
    let endpoint = "http://example.com".to_string();
    let timeout = Duration::from_secs(5);

    let observer = EventObserver::new(endpoint.clone(), timeout, false);

    // Verify fields
    assert_eq!(observer.endpoint, endpoint);
    assert_eq!(observer.timeout, timeout);
    assert_eq!(observer.disable_retries, false);
}

#[test]
#[serial]
fn test_send_payload_with_db() {
    use mockito::Matcher;

    let dir = tempdir().unwrap();
    let working_dir = dir.path().to_path_buf();
    let payload = json!({"key": "value"});

    let dispatcher = EventDispatcher::new(working_dir.clone());

    // Create a mock server
    let mut server = mockito::Server::new();
    let _m = server
        .mock("POST", "/test")
        .match_header("content-type", Matcher::Regex("application/json.*".into()))
        .match_body(Matcher::Json(payload.clone()))
        .with_status(200)
        .create();

    let endpoint = server.url().strip_prefix("http://").unwrap().to_string();
    let timeout = Duration::from_secs(5);

    let observer = EventObserver::new(endpoint, timeout, false);

    TEST_EVENT_OBSERVER_SKIP_RETRY.set(false);

    // Call send_payload
    dispatcher
        .dispatch_to_observer(&observer, &payload, "/test")
        .unwrap()
        .wait_until_complete();

    // Verify that the payload was sent and database is empty
    _m.assert();

    // Verify that the database is empty
    let db_path = dispatcher.db_path;
    let db_path_str = db_path.to_str().unwrap();
    let conn = Connection::open(db_path_str).expect("Failed to open database");
    let pending_payloads = EventDispatcherDbConnection::new_from_exisiting_connection(conn)
        .get_pending_payloads()
        .expect("Failed to get pending payloads");
    assert_eq!(pending_payloads.len(), 0, "Expected no pending payloads");
}

#[test]
fn test_send_payload_success() {
    let port = get_random_port();

    // Set up a channel to notify when the server has processed the request
    let (tx, rx) = channel();

    // Start a mock server in a separate thread
    let server = Server::http(format!("127.0.0.1:{port}")).unwrap();
    thread::spawn(move || {
        let request = server.recv().unwrap();
        assert_eq!(request.url(), "/test");
        assert_eq!(request.method(), &Method::Post);

        // Simulate a successful response
        let response = Response::from_string("HTTP/1.1 200 OK");
        request.respond(response).unwrap();

        // Notify the test that the request was processed
        tx.send(()).unwrap();
    });

    let observer = EventObserver::new(format!("127.0.0.1:{port}"), Duration::from_secs(3), false);

    let payload = json!({"key": "value"});

    let dir = tempdir().unwrap();
    let working_dir = dir.path().to_path_buf();
    let dispatcher = EventDispatcher::new(working_dir);

    dispatcher.dispatch_to_observer_or_log_error(&observer, &payload, "/test");

    // Wait for the server to process the request
    rx.recv_timeout(Duration::from_secs(5))
        .expect("Server did not receive request in time");
}

#[test]
fn test_send_payload_retry() {
    let port = get_random_port();

    // Set up a channel to notify when the server has processed the request
    let (tx, rx) = channel();

    // Start a mock server in a separate thread
    let server = Server::http(format!("127.0.0.1:{port}")).unwrap();
    let thread = thread::spawn(move || {
        let mut attempt = 0;
        while let Ok(request) = server.recv() {
            attempt += 1;
            if attempt == 1 {
                debug!("Mock server received request attempt 1");
                // Simulate a failure on the first attempt
                let response = Response::new(
                    StatusCode(500),
                    vec![],
                    "Internal Server Error".as_bytes(),
                    Some(21),
                    None,
                );
                request.respond(response).unwrap();
            } else {
                debug!("Mock server received request attempt 2");
                // Simulate a successful response on the second attempt
                let response = Response::from_string("HTTP/1.1 200 OK");
                request.respond(response).unwrap();

                // Notify the test that the request was processed successfully
                tx.send(()).unwrap();
                break;
            }
        }
    });

    let observer = EventObserver::new(format!("127.0.0.1:{port}"), Duration::from_secs(3), false);

    let payload = json!({"key": "value"});

    let dir = tempdir().unwrap();
    let working_dir = dir.path().to_path_buf();
    let dispatcher = EventDispatcher::new(working_dir);

    dispatcher.dispatch_to_observer_or_log_error(&observer, &payload, "/test");

    // Wait for the server to process the request
    rx.recv_timeout(Duration::from_secs(5))
        .expect("Server did not receive request in time");

    thread.join().unwrap();
}

#[test]
#[serial]
fn test_send_payload_timeout() {
    let port = get_random_port();
    let timeout = Duration::from_secs(3);

    // Set up a channel to notify when the server has processed the request
    let (tx, rx) = channel();

    // Start a mock server in a separate thread
    let server = Server::http(format!("127.0.0.1:{port}")).unwrap();
    let thread = thread::spawn(move || {
        let mut attempt = 0;
        // This exists to only keep request from being dropped
        #[allow(clippy::collection_is_never_read)]
        let mut _request_holder = None;
        while let Ok(request) = server.recv() {
            attempt += 1;
            if attempt == 1 {
                debug!("Mock server received request attempt 1");
                // Do not reply, forcing the sender to timeout and retry,
                // but don't drop the request or it will receive a 500 error,
                _request_holder = Some(request);
            } else {
                debug!("Mock server received request attempt 2");
                // Simulate a successful response on the second attempt
                let response = Response::from_string("HTTP/1.1 200 OK");
                request.respond(response).unwrap();

                // Notify the test that the request was processed successfully
                tx.send(()).unwrap();
                break;
            }
        }
    });

    let observer = EventObserver::new(format!("127.0.0.1:{port}"), timeout, false);

    let payload = json!({"key": "value"});

    // Record the time before sending the payload
    let start_time = Instant::now();

    let dir = tempdir().unwrap();
    let working_dir = dir.path().to_path_buf();
    let dispatcher = EventDispatcher::new(working_dir);

    // Call the function being tested
    dispatcher
        .dispatch_to_observer(&observer, &payload, "/test")
        .unwrap()
        .wait_until_complete();

    // Record the time after the function returns
    let elapsed_time = start_time.elapsed();

    println!("Elapsed time: {elapsed_time:?}");
    assert!(
        elapsed_time >= timeout,
        "Expected a timeout, but the function returned too quickly"
    );

    assert!(
        elapsed_time < timeout + Duration::from_secs(1),
        "Expected a timeout, but the function took too long"
    );

    // Wait for the server to process the request
    rx.recv_timeout(Duration::from_secs(5))
        .expect("Server did not receive request in time");

    thread.join().unwrap();
}

#[test]
#[serial]
fn test_send_payload_with_db_force_restart() {
    let port = get_random_port();
    let timeout = Duration::from_secs(3);
    let dir = tempdir().unwrap();
    let working_dir = dir.path().to_path_buf();

    // Set up a channel to notify when the server has processed the request
    let (tx, rx) = channel();

    info!("Starting mock server on port {port}");
    // Start a mock server in a separate thread
    let server = Server::http(format!("127.0.0.1:{port}")).unwrap();
    let thread = thread::spawn(move || {
        let mut attempt = 0;
        // This exists to only keep request from being dropped
        #[allow(clippy::collection_is_never_read)]
        let mut _request_holder = None;
        while let Ok(mut request) = server.recv() {
            attempt += 1;
            match attempt {
                1 => {
                    info!("Mock server received request attempt 1");
                    // Do not reply, forcing the sender to timeout and retry,
                    // but don't drop the request or it will receive a 500 error,
                    _request_holder = Some(request);
                }
                2 => {
                    info!("Mock server received request attempt 2");

                    // Verify the payload
                    let mut payload = String::new();
                    request.as_reader().read_to_string(&mut payload).unwrap();
                    let expected_payload = r#"{"key":"value"}"#;
                    assert_eq!(payload, expected_payload);

                    // Simulate a successful response on the second attempt
                    let response = Response::from_string("HTTP/1.1 200 OK");
                    request.respond(response).unwrap();
                }
                3 => {
                    info!("Mock server received request attempt 3");

                    // Verify the payload
                    let mut payload = String::new();
                    request.as_reader().read_to_string(&mut payload).unwrap();
                    let expected_payload = r#"{"key":"value2"}"#;
                    assert_eq!(payload, expected_payload);

                    // Simulate a successful response on the second attempt
                    let response = Response::from_string("HTTP/1.1 200 OK");
                    request.respond(response).unwrap();

                    // When we receive attempt 3 (message 1, re-sent message 1, message 2),
                    // notify the test that the request was processed successfully
                    tx.send(()).unwrap();
                    break;
                }
                _ => panic!("Unexpected request attempt"),
            }
        }
    });

    let mut dispatcher = EventDispatcher::new(working_dir.clone());

    let observer = dispatcher.register_observer_private(&EventObserverConfig {
        endpoint: format!("127.0.0.1:{port}"),
        timeout_ms: timeout.as_millis() as u64,
        events_keys: vec![EventKeyType::AnyEvent],
        disable_retries: false,
    });

    EventDispatcherDbConnection::new(&dispatcher.clone().db_path).unwrap();

    let payload = json!({"key": "value"});
    let payload2 = json!({"key": "value2"});

    // Disable retrying so that it sends the payload only once
    // and that payload will be ignored by the test server.
    TEST_EVENT_OBSERVER_SKIP_RETRY.set(true);

    info!("Sending payload 1");

    // Send the payload
    dispatcher
        .dispatch_to_observer(&observer, &payload, "/test")
        .unwrap()
        .wait_until_complete();

    // Re-enable retrying
    TEST_EVENT_OBSERVER_SKIP_RETRY.set(false);

    dispatcher.process_pending_payloads();

    info!("Sending payload 2");

    // Send another payload
    dispatcher.dispatch_to_observer_or_log_error(&observer, &payload2, "/test");

    // Wait for the server to process the requests
    rx.recv_timeout(Duration::from_secs(5))
        .expect("Server did not receive request in time");

    thread.join().unwrap();
}

#[test]
fn test_event_dispatcher_disable_retries() {
    let timeout = Duration::from_secs(5);
    let payload = json!({"key": "value"});

    // Create a mock server returning error 500
    let mut server = mockito::Server::new();
    let _m = server.mock("POST", "/test").with_status(500).create();

    let endpoint = server.url().strip_prefix("http://").unwrap().to_string();

    let observer = EventObserver::new(endpoint, timeout, true);

    let dir = tempdir().unwrap();
    let working_dir = dir.path().to_path_buf();
    let dispatcher = EventDispatcher::new(working_dir);

    // in non "disable_retries" mode this will run forever
    dispatcher
        .dispatch_to_observer(&observer, &payload, "/test")
        .unwrap()
        .wait_until_complete();

    // Verify that the payload was sent
    _m.assert();
}

#[test]
fn test_event_dispatcher_disable_retries_invalid_url() {
    let timeout = Duration::from_secs(5);
    let payload = json!({"key": "value"});

    let endpoint = String::from("255.255.255.255");

    let observer = EventObserver::new(endpoint, timeout, true);

    let dir = tempdir().unwrap();
    let working_dir = dir.path().to_path_buf();
    let dispatcher = EventDispatcher::new(working_dir);

    // in non "disable_retries" mode this will run forever
    dispatcher
        .dispatch_to_observer(&observer, &payload, "/test")
        .unwrap()
        .wait_until_complete();
}

#[test]
#[ignore]
/// This test generates a new block and ensures the "disable_retries" events_observer will not block.
fn block_event_with_disable_retries_observer() {
    let dir = tempdir().unwrap();
    let working_dir = dir.path().to_path_buf();

    let mut event_dispatcher = EventDispatcher::new(working_dir.clone());
    let config = EventObserverConfig {
        endpoint: String::from("255.255.255.255"),
        events_keys: vec![EventKeyType::MinedBlocks],
        timeout_ms: 1000,
        disable_retries: true,
    };
    event_dispatcher.register_observer(&config);

    let nakamoto_block = NakamotoBlock {
        header: NakamotoBlockHeader::empty(),
        txs: vec![],
    };

    // this will block forever in non "disable_retries" mode
    event_dispatcher.process_mined_nakamoto_block_event(
        0,
        &nakamoto_block,
        0,
        &ExecutionCost::max_value(),
        vec![],
    );

    assert_eq!(event_dispatcher.registered_observers.len(), 1);
}

#[test]
/// This test checks that tx payloads properly convert the stacks transaction receipt regardless of the presence of the vm_error
fn make_new_block_txs_payload_vm_error() {
    let privkey = StacksPrivateKey::random();
    let pubkey = StacksPublicKey::from_private(&privkey);
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![pubkey],
    )
    .unwrap();

    let tx = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: 0x80000000,
        auth: TransactionAuth::from_p2pkh(&privkey).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::TokenTransfer(
            addr.to_account_principal(),
            123,
            TokenTransferMemo([0u8; 34]),
        ),
    };

    let mut receipt = StacksTransactionReceipt {
        transaction: TransactionOrigin::Burn(BlockstackOperationType::PreStx(PreStxOp {
            output: StacksAddress::new(0, Hash160([1; 20])).unwrap(),
            txid: tx.txid(),
            vtxindex: 0,
            block_height: 1,
            burn_header_hash: BurnchainHeaderHash([5u8; 32]),
        })),
        events: vec![],
        post_condition_aborted: true,
        result: Value::okay_true(),
        contract_analysis: None,
        execution_cost: ExecutionCost {
            write_length: 0,
            write_count: 0,
            read_length: 0,
            read_count: 0,
            runtime: 0,
        },
        microblock_header: None,
        vm_error: None,
        stx_burned: 0u128,
        tx_index: 0,
    };

    let payload_no_error = make_new_block_txs_payload(&receipt, 0);
    assert_eq!(payload_no_error.vm_error, receipt.vm_error);

    receipt.vm_error = Some("Inconceivable!".into());

    let payload_with_error = make_new_block_txs_payload(&receipt, 0);
    assert_eq!(payload_with_error.vm_error, receipt.vm_error);
}

fn make_tenure_change_payload() -> TenureChangePayload {
    TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0; 20]),
        prev_tenure_consensus_hash: ConsensusHash([0; 20]),
        burn_view_consensus_hash: ConsensusHash([0; 20]),
        previous_tenure_end: StacksBlockId([0; 32]),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::Extended,
        pubkey_hash: Hash160([0; 20]),
    }
}

fn make_tenure_change_tx(payload: TenureChangePayload) -> StacksTransaction {
    StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: 1,
        auth: TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(
            SinglesigSpendingCondition {
                hash_mode: SinglesigHashMode::P2PKH,
                signer: Hash160([0; 20]),
                nonce: 0,
                tx_fee: 0,
                key_encoding: TransactionPublicKeyEncoding::Compressed,
                signature: MessageSignature([0; 65]),
            },
        )),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::TenureChange(payload),
    }
}

#[test]
fn backwards_compatibility_transaction_event_payload() {
    let tx = make_tenure_change_tx(make_tenure_change_payload());
    let receipt = StacksTransactionReceipt {
        transaction: TransactionOrigin::Burn(BlockstackOperationType::PreStx(PreStxOp {
            output: StacksAddress::new(0, Hash160([1; 20])).unwrap(),
            txid: tx.txid(),
            vtxindex: 0,
            block_height: 1,
            burn_header_hash: BurnchainHeaderHash([5u8; 32]),
        })),
        events: vec![StacksTransactionEvent::SmartContractEvent(
            SmartContractEventData {
                key: (boot_code_id("some-contract", false), "some string".into()),
                value: Value::Bool(false),
            },
        )],
        post_condition_aborted: false,
        result: Value::okay_true(),
        stx_burned: 100,
        contract_analysis: None,
        execution_cost: ExecutionCost {
            write_length: 1,
            write_count: 2,
            read_length: 3,
            read_count: 4,
            runtime: 5,
        },
        microblock_header: None,
        tx_index: 1,
        vm_error: None,
    };
    let payload = make_new_block_txs_payload(&receipt, 0);
    let new_serialized_data = serde_json::to_string_pretty(&payload).expect("Failed");
    let old_serialized_data = r#"
        {
            "burnchain_op": {
                "pre_stx": {
                    "burn_block_height": 1,
                    "burn_header_hash": "0505050505050505050505050505050505050505050505050505050505050505",
                    "burn_txid": "ace70e63009a2c2d22c0f948b146d8a28df13a2900f3b5f3cc78b56459ffef05",
                    "output": {
                        "address": "S0G2081040G2081040G2081040G2081054GYN98",
                        "address_hash_bytes": "0x0101010101010101010101010101010101010101",
                        "address_version": 0
                    },
                    "vtxindex": 0
                }
            },
            "contract_abi": null,
            "execution_cost": {
                "read_count": 4,
                "read_length": 3,
                "runtime": 5,
                "write_count": 2,
                "write_length": 1
            },
            "microblock_hash": null,
            "microblock_parent_hash": null,
            "microblock_sequence": null,
            "raw_result": "0x0703",
            "raw_tx": "0x00",
            "status": "success",
            "tx_index": 0,
            "txid": "0xace70e63009a2c2d22c0f948b146d8a28df13a2900f3b5f3cc78b56459ffef05"
        }
        "#;
    let new_value: TransactionEventPayload = serde_json::from_str(&new_serialized_data)
        .expect("Failed to deserialize new data as TransactionEventPayload");
    let old_value: TransactionEventPayload = serde_json::from_str(&old_serialized_data)
        .expect("Failed to deserialize old data as TransactionEventPayload");
    assert_eq!(new_value, old_value);
}

#[test]
fn test_block_proposal_validation_event() {
    let mut server = mockito::Server::new();
    let mock = server.mock("POST", "/proposal_response").create();

    let endpoint = server.url().strip_prefix("http://").unwrap().to_string();
    let dir = tempdir().unwrap();
    let mut dispatcher = EventDispatcher::new(dir.path().to_path_buf());

    dispatcher.register_observer(&EventObserverConfig {
        endpoint: endpoint.clone(),
        events_keys: vec![EventKeyType::BlockProposal],
        timeout_ms: 3_000,
        disable_retries: false,
    });

    // The below matches what the `RPCBlockProposalRequestHandler` does via
    // `NakamotoBlockProposal::spawn_validation_thread`: It calls
    // `get_proposal_callback_receiver()` and moves the result to the thread
    // that performs that validation and when done, sends the validation
    // result through the event dispatcher.

    let receiver = dispatcher.get_proposal_callback_receiver().unwrap();

    let validation_thread = thread::spawn(move || {
        let result = BlockValidateOk {
            signer_signature_hash: Sha512Trunc256Sum::from_data(&[0, 8, 15]),
            cost: ExecutionCost::ZERO,
            size: 666,
            validation_time_ms: 4321,
            replay_tx_hash: None,
            replay_tx_exhausted: false,
        };
        receiver.notify_proposal_result(Ok(result));
    });

    validation_thread.join().unwrap();

    mock.assert();
}

#[test]
fn test_http_delivery_non_blocking() {
    let mut slow_server = mockito::Server::new();

    let start_count = Arc::new(AtomicU32::new(0));
    let end_count = Arc::new(AtomicU32::new(0));

    let start_count2 = start_count.clone();
    let end_count2 = end_count.clone();

    let mock = slow_server
        .mock("POST", "/mined_nakamoto_block")
        .with_body_from_request(move |_| {
            start_count2.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_secs(2));
            end_count2.fetch_add(1, Ordering::SeqCst);
            "".into()
        })
        .create();

    let endpoint = slow_server
        .url()
        .strip_prefix("http://")
        .unwrap()
        .to_string();

    let dir = tempdir().unwrap();
    let mut dispatcher = EventDispatcher::new(dir.path().to_path_buf());

    dispatcher.register_observer(&EventObserverConfig {
        endpoint: endpoint.clone(),
        events_keys: vec![EventKeyType::MinedBlocks],
        timeout_ms: 3_000,
        disable_retries: false,
    });

    let nakamoto_block = NakamotoBlock {
        header: NakamotoBlockHeader::empty(),
        txs: vec![],
    };

    let start = Instant::now();

    dispatcher.process_mined_nakamoto_block_event(
        0,
        &nakamoto_block,
        0,
        &ExecutionCost::max_value(),
        vec![],
    );

    assert!(
        start.elapsed() < Duration::from_millis(100),
        "dispatcher blocked while sending event"
    );

    thread::sleep(Duration::from_secs(1));

    assert!(start_count.load(Ordering::SeqCst) == 1);
    assert!(end_count.load(Ordering::SeqCst) == 0);

    thread::sleep(Duration::from_secs(2));

    assert!(start_count.load(Ordering::SeqCst) == 1);
    assert!(end_count.load(Ordering::SeqCst) == 1);

    mock.assert();
}

#[test]
fn test_http_delivery_blocks_once_queue_is_full() {
    let mut slow_server = mockito::Server::new();

    let start_count = Arc::new(AtomicU32::new(0));
    let end_count = Arc::new(AtomicU32::new(0));

    let start_count2 = start_count.clone();
    let end_count2 = end_count.clone();

    // this server takes 2 seconds until it finally responds
    let mock = slow_server
        .mock("POST", "/mined_nakamoto_block")
        .expect(4)
        .with_body_from_request(move |_| {
            start_count2.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_secs(2));
            end_count2.fetch_add(1, Ordering::SeqCst);
            "".into()
        })
        .create();

    let endpoint = slow_server
        .url()
        .strip_prefix("http://")
        .unwrap()
        .to_string();

    let dir = tempdir().unwrap();

    // Create a dispatcher with a queue size of 3, so that three pending requests
    // don't block, but the fourth one does.
    let mut dispatcher = EventDispatcher::new_with_custom_queue_size(dir.path().to_path_buf(), 3);

    dispatcher.register_observer(&EventObserverConfig {
        endpoint: endpoint.clone(),
        events_keys: vec![EventKeyType::MinedBlocks],
        timeout_ms: 3_000,
        disable_retries: false,
    });

    let nakamoto_block = NakamotoBlock {
        header: NakamotoBlockHeader::empty(),
        txs: vec![],
    };

    let start = Instant::now();

    // send the first three requests
    for _ in 1..=3 {
        dispatcher.process_mined_nakamoto_block_event(
            0,
            &nakamoto_block,
            0,
            &ExecutionCost::max_value(),
            vec![],
        );
    }

    let elapsed = start.elapsed();
    // this shouldn't block because they fit in the queue
    assert!(
        elapsed < Duration::from_millis(500),
        "dispatcher blocked while sending first three events"
    );

    thread::sleep(Duration::from_millis(500) - elapsed);

    assert_eq!(start_count.load(Ordering::SeqCst), 1);
    assert_eq!(end_count.load(Ordering::SeqCst), 0);

    let start = Instant::now();

    // send the fourth request -- this should now block until the first request is complete
    dispatcher.process_mined_nakamoto_block_event(
        0,
        &nakamoto_block,
        0,
        &ExecutionCost::max_value(),
        vec![],
    );

    // we waited 500ms previously, so it should take on the order of 1.5s until
    // the first request is complete
    assert!(
        start.elapsed() > Duration::from_millis(1000),
        "dispatcher did not block when sending fourth event"
    );

    assert!(
        start.elapsed() < Duration::from_millis(2000),
        "dispatcher blocked unexpectedly long after sending fourth event"
    );

    thread::sleep(Duration::from_millis(100));

    assert_eq!(start_count.load(Ordering::SeqCst), 2);
    assert_eq!(end_count.load(Ordering::SeqCst), 1);

    thread::sleep(Duration::from_secs(2));

    assert_eq!(start_count.load(Ordering::SeqCst), 3);
    assert_eq!(end_count.load(Ordering::SeqCst), 2);

    thread::sleep(Duration::from_secs(2));

    assert_eq!(start_count.load(Ordering::SeqCst), 4);
    assert_eq!(end_count.load(Ordering::SeqCst), 3);

    thread::sleep(Duration::from_secs(2));

    assert_eq!(start_count.load(Ordering::SeqCst), 4);
    assert_eq!(end_count.load(Ordering::SeqCst), 4);

    mock.assert();
}

#[test]
fn test_http_delivery_always_blocks_if_queue_size_is_zero() {
    let mut slow_server = mockito::Server::new();

    let start_count = Arc::new(AtomicU32::new(0));
    let end_count = Arc::new(AtomicU32::new(0));

    let start_count2 = start_count.clone();
    let end_count2 = end_count.clone();

    let mock = slow_server
        .mock("POST", "/mined_nakamoto_block")
        .with_body_from_request(move |_| {
            start_count2.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_secs(2));
            end_count2.fetch_add(1, Ordering::SeqCst);
            "".into()
        })
        .create();

    let endpoint = slow_server
        .url()
        .strip_prefix("http://")
        .unwrap()
        .to_string();

    let dir = tempdir().unwrap();
    let mut dispatcher = EventDispatcher::new_with_custom_queue_size(dir.path().to_path_buf(), 0);

    dispatcher.register_observer(&EventObserverConfig {
        endpoint: endpoint.clone(),
        events_keys: vec![EventKeyType::MinedBlocks],
        timeout_ms: 3_000,
        disable_retries: false,
    });

    let nakamoto_block = NakamotoBlock {
        header: NakamotoBlockHeader::empty(),
        txs: vec![],
    };

    let start = Instant::now();

    dispatcher.process_mined_nakamoto_block_event(
        0,
        &nakamoto_block,
        0,
        &ExecutionCost::max_value(),
        vec![],
    );

    assert!(
        start.elapsed() > Duration::from_millis(1900),
        "dispatcher did not block while sending event"
    );

    thread::sleep(Duration::from_millis(100));

    assert!(start_count.load(Ordering::SeqCst) == 1);
    assert!(end_count.load(Ordering::SeqCst) == 1);

    mock.assert();
}
