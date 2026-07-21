// Copyright (C) 2026 Stacks Open Internet Foundation
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
use std::time::Duration;

use clarity::types::chainstate::StacksPrivateKey;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::{ClarityName, ContractName, Value};
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::chainstate::StacksBlockId;

use crate::chainstate::stacks::Error as ChainError;
use crate::core::test_util::{make_contract_call_tx, make_contract_publish_tx, to_addr};
use crate::net::api::tests::TestRPC;
use crate::net::api::txsimulate;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{StacksHttp, StacksHttpRequest};
use crate::net::test::TestEventObserver;
use crate::net::tests::{NakamotoBootStep, NakamotoBootTenure};
use crate::net::ProtocolFamily;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let private_key = StacksPrivateKey::from_seed("txsimulate".as_bytes());
    let tx = make_contract_publish_tx(
        &private_key,
        0,
        1000,
        CHAIN_ID_TESTNET,
        &"print-contract",
        &"(print u1)",
        Some(clarity::vm::ClarityVersion::Clarity1),
    );

    let mut request = StacksHttpRequest::new_transaction_simulate(addr.into(), &tx);

    // add the authorization header
    request.add_header("authorization".into(), "password".into());

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();

    let mut handler =
        txsimulate::RPCTransactionSimulateRequestHandler::new(Some("password".into()));

    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();
    assert_eq!(handler.transaction, Some(tx));

    // parsed request consumes headers that would not be in a constructed request
    parsed_request.clear_headers();
    parsed_request.add_header("authorization".into(), "password".into());

    let (preamble, _contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());
}

#[test]
fn test_transaction_simulate_errors() {
    let test_observer = TestEventObserver::new();
    let mut rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

    let sort_db = rpc_test.peer_1.chain.sortdb.take().unwrap();
    let chainstate = rpc_test.peer_1.chainstate();

    let private_key = StacksPrivateKey::from_seed("txsimulate".as_bytes());
    let tx = make_contract_publish_tx(
        &private_key,
        0,
        1000,
        CHAIN_ID_TESTNET,
        &"print-contract",
        &"(print u1)",
        Some(clarity::vm::ClarityVersion::Clarity1),
    );

    // non-existent tip
    let err = txsimulate::RPCTransactionSimulateRequestHandler::transaction_simulate(
        &tx,
        &StacksBlockId([0x01; 32]),
        &sort_db,
        chainstate,
        Duration::from_secs(30),
        Duration::from_secs(30),
        0,
    )
    .err()
    .unwrap();

    assert!(matches!(err, ChainError::NoSuchBlockError));
}

/// Simulate a successful contract-call at the chain tip and check the
/// reported result, events, and execution cost.
#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();

    let private_key = StacksPrivateKey::from_seed("txsimulate".as_bytes());
    let address = to_addr(&private_key);

    let contract_name = ContractName::from_literal("test");
    let function_name = ClarityName::from_literal("test");

    // Set up the RPC test with a deployed contract to call
    let rpc_test =
        TestRPC::setup_nakamoto_with_boot_plan(function_name!(), &test_observer, |boot_plan| {
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

            let boot_tenures = vec![NakamotoBootTenure::Sortition(vec![
                NakamotoBootStep::Block(vec![contract_deploy]),
            ])];

            boot_plan
                .with_boot_tenures(boot_tenures)
                .with_initial_balances(vec![(address.clone().into(), 1_000_000)])
        });

    let nakamoto_consensus_hash = rpc_test.consensus_hash.clone();
    let canonical_tip = rpc_test.canonical_tip.clone();

    let contract_call = make_contract_call_tx(
        &private_key,
        1,
        1000,
        CHAIN_ID_TESTNET,
        &address,
        contract_name.clone(),
        function_name.clone(),
        &[],
    );

    let mut requests = vec![];

    // simulate the contract-call at the tip
    let mut request = StacksHttpRequest::new_transaction_simulate(addr.into(), &contract_call);
    request.add_header("authorization".into(), "password".into());
    requests.push(request);

    // a transaction with a stale nonce cannot be simulated
    let bad_nonce_call = make_contract_call_tx(
        &private_key,
        0,
        1000,
        CHAIN_ID_TESTNET,
        &address,
        contract_name.clone(),
        function_name.clone(),
        &[],
    );
    let mut request = StacksHttpRequest::new_transaction_simulate(addr.into(), &bad_nonce_call);
    request.add_header("authorization".into(), "password".into());
    requests.push(request);

    // unauthenticated request
    let request = StacksHttpRequest::new_transaction_simulate(addr.into(), &contract_call);
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    let tip_block = test_observer.get_blocks().last().unwrap().clone();

    // simulated the contract-call at the tip
    let response = responses.remove(0);

    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_simulated_transaction().unwrap();

    assert_eq!(resp.txid, contract_call.txid());
    assert_eq!(resp.tip_block_id, canonical_tip);
    assert_eq!(resp.consensus_hash, nakamoto_consensus_hash);
    assert_eq!(
        resp.block_height,
        tip_block.metadata.stacks_block_height + 1
    );

    assert_eq!(resp.result_hex, Value::okay_true());
    assert!(!resp.post_condition_aborted);
    assert!(resp.vm_error.is_none());

    // the stx-transfer generated one event
    assert_eq!(resp.events.len(), 1);

    // a contract-call must have consumed some of the execution budget, and
    // the reported limit is the full tenure budget
    assert!(resp.execution_cost.runtime > 0);
    assert!(resp.execution_cost.exceeds(&ExecutionCost::ZERO));
    assert!(!resp.execution_cost.exceeds(&resp.execution_limit));

    // got a failure for the stale nonce (400)
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, _body) = response.destruct();
    assert_eq!(preamble.status_code, 400);

    // got another failure (401 this time)
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, _body) = response.destruct();
    assert_eq!(preamble.status_code, 401);
}
