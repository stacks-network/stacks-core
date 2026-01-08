// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2025 Stacks Open Internet Foundation
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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clarity::types::chainstate::StacksPrivateKey;
use clarity::vm::{ClarityName, ContractName, Value as ClarityValue};
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::chainstate::StacksBlockId;

use crate::chainstate::stacks::{
    Error as ChainError, StacksTransaction, StacksTransactionSigner, TransactionAnchorMode,
    TransactionContractCall, TransactionPayload, TransactionPostConditionMode, TransactionVersion,
};
use crate::core::test_util::{
    make_contract_publish, make_contract_publish_tx, make_unsigned_tx, to_addr,
};
use crate::net::api::blockreplay;
use crate::net::api::tests::TestRPC;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{StacksHttp, StacksHttpRequest};
use crate::net::test::TestEventObserver;
use crate::net::tests::{NakamotoBootStep, NakamotoBootTenure};
use crate::net::ProtocolFamily;
use crate::stacks_common::codec::StacksMessageCodec;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let mut request = StacksHttpRequest::new_block_replay(addr.into(), &StacksBlockId([0x01; 32]));

    // add the authorization header
    request.add_header("authorization".into(), "password".into());

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();

    let mut handler =
        blockreplay::RPCNakamotoBlockReplayRequestHandler::new(Some("password".into()));

    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();
    assert_eq!(handler.block_id, Some(StacksBlockId([0x01; 32])));

    // parsed request consumes headers that would not be in a constructed request
    parsed_request.clear_headers();
    parsed_request.add_header("authorization".into(), "password".into());

    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());
    assert_eq!(handler.profiler, false);
}

#[test]
fn test_try_parse_request_with_profiler() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let mut request = StacksHttpRequest::new_block_replay_with_profiler(
        addr.into(),
        &StacksBlockId([0x01; 32]),
        true,
    );

    // add the authorization header
    request.add_header("authorization".into(), "password".into());

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();

    let mut handler =
        blockreplay::RPCNakamotoBlockReplayRequestHandler::new(Some("password".into()));

    let parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(handler.profiler, true);
}

#[test]
fn test_block_reply_errors() {
    let mut handler =
        blockreplay::RPCNakamotoBlockReplayRequestHandler::new(Some("password".into()));

    let test_observer = TestEventObserver::new();
    let mut rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

    let sort_db = rpc_test.peer_1.chain.sortdb.take().unwrap();
    let chainstate = rpc_test.peer_1.chainstate();

    let err = handler.block_replay(&sort_db, chainstate).err().unwrap();

    assert!(matches!(err, ChainError::InvalidStacksBlock(_)));
    assert_eq!(err.to_string(), "block_id is None");

    handler.block_id = Some(StacksBlockId([0x01; 32]));

    let err = handler.block_replay(&sort_db, chainstate).err().unwrap();

    assert!(matches!(err, ChainError::NoSuchBlockError));
    assert_eq!(err.to_string(), "No such Stacks block");
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();
    let rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

    let nakamoto_consensus_hash = rpc_test.consensus_hash.clone();

    let mut requests = vec![];

    // query existing, non-empty Nakamoto block
    let mut request = StacksHttpRequest::new_block_replay_with_profiler(
        addr.clone().into(),
        &rpc_test.canonical_tip,
        true,
    );
    // add the authorization header
    request.add_header("authorization".into(), "password".into());
    requests.push(request);

    // query non-existent block
    let mut request =
        StacksHttpRequest::new_block_replay(addr.clone().into(), &StacksBlockId([0x01; 32]));
    // add the authorization header
    request.add_header("authorization".into(), "password".into());
    requests.push(request);

    // unauthenticated request
    let request =
        StacksHttpRequest::new_block_replay(addr.clone().into(), &StacksBlockId([0x00; 32]));
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    // got the Nakamoto tip
    let response = responses.remove(0);

    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_replayed_block().unwrap();

    let tip_block = test_observer.get_blocks().last().unwrap().clone();

    assert_eq!(resp.consensus_hash, nakamoto_consensus_hash);
    assert_eq!(resp.consensus_hash, tip_block.metadata.consensus_hash);

    assert_eq!(resp.block_hash, tip_block.block.block_hash);
    assert_eq!(resp.block_id, tip_block.metadata.index_block_hash());
    assert_eq!(resp.parent_block_id, tip_block.parent);

    assert_eq!(resp.block_height, tip_block.metadata.stacks_block_height);

    assert!(resp.valid_merkle_root);

    assert_eq!(resp.transactions.len(), tip_block.receipts.len());

    for (resp_tx, tip_tx) in resp.transactions.iter().zip(tip_block.receipts.iter()) {
        assert_eq!(resp_tx.txid, tip_tx.transaction.txid());
        assert_eq!(resp_tx.events.len(), tip_tx.events.len());
        assert_eq!(resp_tx.result, tip_tx.result);
        assert_eq!(resp_tx.result_hex, tip_tx.result);
        assert!(!resp_tx.post_condition_aborted);
    }

    // got a failure (404)
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 404);

    // got another failure (401 this time)
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 401);
}

/// Test that events properly set the `committed` flag to `false`
/// when the transaction is aborted by a post-condition.
#[test]
fn replay_block_with_pc_failure() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();

    // Set up the RPC test with a contract, so that we can test a post-condition failure
    let rpc_test =
        TestRPC::setup_nakamoto_with_boot_plan(function_name!(), &test_observer, |boot_plan| {
            let private_key = StacksPrivateKey::from_seed("blockreplay".as_bytes());
            let addr = to_addr(&private_key);

            let code_body =
        "(define-public (test) (stx-transfer? u100 tx-sender 'ST000000000000000000002AMW42H))";

            let contract_deploy = make_contract_publish_tx(
                &private_key,
                0,
                1000,
                CHAIN_ID_TESTNET,
                &"test",
                &code_body,
                None,
            );

            let contract_call = {
                let contract_name = ContractName::from("test");
                let function_name = ClarityName::from("test");

                let payload = TransactionContractCall {
                    address: addr.clone(),
                    contract_name,
                    function_name,
                    function_args: vec![],
                };
                let mut unsigned_tx = make_unsigned_tx(
                    TransactionPayload::ContractCall(payload),
                    &private_key,
                    None,
                    1,
                    None,
                    1000,
                    CHAIN_ID_TESTNET,
                    TransactionAnchorMode::Any,
                    TransactionVersion::Testnet,
                );
                unsigned_tx.post_condition_mode = TransactionPostConditionMode::Deny;

                let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
                tx_signer.sign_origin(&private_key).unwrap();
                tx_signer.get_tx().unwrap()
            };

            let boot_tenures = vec![NakamotoBootTenure::Sortition(vec![
                NakamotoBootStep::Block(vec![contract_deploy]),
                NakamotoBootStep::Block(vec![contract_call]),
            ])];

            boot_plan
                .with_boot_tenures(boot_tenures)
                .with_ignore_transaction_errors(true)
                .with_initial_balances(vec![(addr.into(), 1_000_000)])
        });

    let nakamoto_consensus_hash = rpc_test.consensus_hash.clone();

    let mut requests = vec![];

    let mut request =
        StacksHttpRequest::new_block_replay(addr.clone().into(), &rpc_test.canonical_tip);
    request.add_header("authorization".into(), "password".into());
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    let response = responses.remove(0);

    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let contents = response.clone().get_http_payload_ok().unwrap();
    let response_json: serde_json::Value = contents.try_into().unwrap();

    let result_hex = response_json
        .get("transactions")
        .expect("Expected JSON to have a transactions field")
        .as_array()
        .expect("Expected transactions to be an array")
        .get(0)
        .expect("Expected transactions to have at least one element")
        .as_object()
        .expect("Expected transaction to be an object")
        .get("result_hex")
        .expect("Expected JSON to have a result_hex field")
        .as_str()
        .unwrap();
    let result = ClarityValue::try_deserialize_hex_untyped(&result_hex).unwrap();
    result.expect_result_ok().expect("FATAL: result is not ok");

    let resp = response.decode_replayed_block().unwrap();

    let tip_block = test_observer.get_blocks().last().unwrap().clone();

    assert_eq!(resp.transactions.len(), tip_block.receipts.len());

    assert_eq!(resp.transactions.len(), 1);

    let resp_tx = &resp.transactions.get(0).unwrap();

    assert!(resp_tx.vm_error.is_some());

    for event in resp_tx.events.iter() {
        let committed = event.get("committed").unwrap().as_bool().unwrap();
        assert!(!committed);
    }

    assert!(resp_tx.post_condition_aborted);
}

#[test]
fn test_try_make_response_with_unsuccessful_transaction() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();
    let rpc_test =
        TestRPC::setup_nakamoto_with_boot_plan(function_name!(), &test_observer, |boot_plan| {
            let mut tip_transactions: Vec<StacksTransaction> = vec![];

            let miner_privk = boot_plan.private_key.clone();

            let contract_code = "(broken)";

            let deploy_tx_bytes = make_contract_publish(
                &miner_privk,
                100,
                1000,
                CHAIN_ID_TESTNET,
                &"err-contract",
                &contract_code,
            );
            let deploy_tx =
                StacksTransaction::consensus_deserialize(&mut deploy_tx_bytes.as_slice()).unwrap();

            tip_transactions.push(deploy_tx);
            boot_plan
                .with_tip_transactions(tip_transactions)
                .with_ignore_transaction_errors(true)
        });

    let tip_block = test_observer.get_blocks().last().unwrap().clone();

    let nakamoto_consensus_hash = rpc_test.consensus_hash.clone();

    let mut requests = vec![];

    let mut request =
        StacksHttpRequest::new_block_replay(addr.clone().into(), &rpc_test.canonical_tip);
    // add the authorization header
    request.add_header("authorization".into(), "password".into());
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    // got the Nakamoto tip
    let response = responses.remove(0);

    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_replayed_block().unwrap();

    assert_eq!(resp.consensus_hash, nakamoto_consensus_hash);
    assert_eq!(resp.consensus_hash, tip_block.metadata.consensus_hash);

    assert_eq!(resp.block_hash, tip_block.block.block_hash);
    assert_eq!(resp.block_id, tip_block.metadata.index_block_hash());
    assert_eq!(resp.parent_block_id, tip_block.parent);

    assert_eq!(resp.block_height, tip_block.metadata.stacks_block_height);

    assert!(resp.valid_merkle_root);

    assert_eq!(resp.transactions.len(), tip_block.receipts.len());

    for (resp_tx, tip_tx) in resp.transactions.iter().zip(tip_block.receipts.iter()) {
        assert_eq!(resp_tx.txid, tip_tx.transaction.txid());
        assert_eq!(resp_tx.events.len(), tip_tx.events.len());
        assert_eq!(resp_tx.result, tip_tx.result);
        assert_eq!(resp_tx.result_hex, tip_tx.result);
        assert!(!resp_tx.post_condition_aborted);
    }

    assert_eq!(
        resp.transactions.last().unwrap().vm_error.clone().unwrap(),
        ":0:0: use of unresolved function 'broken'"
    );
}
