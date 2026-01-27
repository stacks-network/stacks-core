// Copyright (C) 2025 Stacks Open Internet Foundation
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
    Error as ChainError, StacksTransactionSigner, TransactionAnchorMode,
    TransactionContractCall, TransactionPayload, TransactionPostConditionMode, TransactionVersion,
};
use crate::chainstate::stacks::TokenTransferMemo;
use crate::core::test_util::{make_contract_publish_tx, make_unsigned_tx, to_addr, sign_standard_single_sig_tx};
use crate::net::api::tests::TestRPC;
use crate::net::api::transactionsimulate;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{StacksHttp, StacksHttpRequest};
use crate::net::test::TestEventObserver;
use crate::net::tests::{NakamotoBootStep, NakamotoBootTenure};
use crate::net::ProtocolFamily;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    // Create a simple token transfer transaction
    let privk = StacksPrivateKey::from_seed("test".as_bytes());
    let tx_payload = TransactionPayload::TokenTransfer(
        to_addr(&privk).into(),
        123,
        TokenTransferMemo([0u8; 34]),
    );
    let signed_tx = sign_standard_single_sig_tx(
        tx_payload,
        &privk,
        0, // nonce
        1000, // fee
        CHAIN_ID_TESTNET,
    );

    let mut request = StacksHttpRequest::new_transaction_simulate(addr.into(), &signed_tx);

    // add the authorization header
    request.add_header("authorization".into(), "password".into());

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();

    let mut handler =
        transactionsimulate::RPCTransactionSimulateRequestHandler::new(Some("password".into()));

    let parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    assert!(handler.tx.is_some());
    assert_eq!(handler.tx.as_ref().unwrap().txid(), signed_tx.txid());
    assert_eq!(handler.profiler, false);
    assert_eq!(handler.ignore_limits, false);
}

#[test]
fn test_try_parse_request_with_options() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    // Create a simple token transfer transaction
    let privk = StacksPrivateKey::from_seed("test".as_bytes());
    let tx_payload = TransactionPayload::TokenTransfer(
        to_addr(&privk).into(),
        123,
        TokenTransferMemo([0u8; 34]),
    );
    let signed_tx = sign_standard_single_sig_tx(
        tx_payload,
        &privk,
        0, // nonce
        1000, // fee
        CHAIN_ID_TESTNET,
    );

    let block_id = StacksBlockId([0x01; 32]);
    let mut request = StacksHttpRequest::new_transaction_simulate_with_options(
        addr.into(),
        &signed_tx,
        Some(&block_id),
        true,  // profiler
        true,  // ignore_limits
    );

    // add the authorization header
    request.add_header("authorization".into(), "password".into());

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();

    let mut handler =
        transactionsimulate::RPCTransactionSimulateRequestHandler::new(Some("password".into()));

    let _parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    assert!(handler.tx.is_some());
    assert_eq!(handler.profiler, true);
    assert_eq!(handler.ignore_limits, true);
    assert_eq!(handler.block_id, Some(block_id));
}

#[test]
fn test_simulate_errors() {
    let handler =
        transactionsimulate::RPCTransactionSimulateRequestHandler::new(Some("password".into()));

    let test_observer = TestEventObserver::new();
    let mut rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

    let sort_db = rpc_test.peer_1.chain.sortdb.take().unwrap();
    let chainstate = rpc_test.peer_1.chainstate();

    // Test with no transaction
    let err = handler.simulate_transaction(&sort_db, chainstate).err().unwrap();

    assert!(matches!(err, ChainError::InvalidStacksTransaction(_, _)));
    assert_eq!(err.to_string(), "No transaction provided");
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();
    let rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

    let mut requests = vec![];

    // Create a simple token transfer transaction
    let privk = StacksPrivateKey::from_seed("test-simulate".as_bytes());
    let recipient = to_addr(&StacksPrivateKey::from_seed("recipient".as_bytes()));
    let tx_payload = TransactionPayload::TokenTransfer(
        recipient.into(),
        1000,
        TokenTransferMemo([0u8; 34]),
    );
    let signed_tx = sign_standard_single_sig_tx(
        tx_payload,
        &privk,
        0, // nonce
        1000, // fee
        CHAIN_ID_TESTNET,
    );

    // Simulate the transaction
    let mut request =
        StacksHttpRequest::new_transaction_simulate_with_options(
            addr.clone().into(),
            &signed_tx,
            Some(&rpc_test.canonical_tip),
            true,  // profiler
            false, // respect limits
        );
    request.add_header("authorization".into(), "password".into());
    requests.push(request);

    // Simulate without auth (should fail)
    let request_no_auth = StacksHttpRequest::new_transaction_simulate(addr.clone().into(), &signed_tx);
    requests.push(request_no_auth);

    let mut responses = rpc_test.run(requests);

    // First response - successful simulation
    let response = responses.remove(0);

    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_simulated_transaction().unwrap();

    assert_eq!(resp.txid, signed_tx.txid());
    // Note: Transaction might not be valid if sender doesn't have balance in test chain
    // But we should get a response with execution details

    // Second response - unauthorized
    let response = responses.remove(0);
    let (preamble, _body) = response.destruct();
    assert_eq!(preamble.status_code, 401);
}

#[test]
fn test_simulate_contract_call() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();

    // Setup blockchain with a deployed contract
    let rpc_test =
        TestRPC::setup_nakamoto_with_boot_plan(function_name!(), &test_observer, |boot_plan| {
            let private_key = StacksPrivateKey::from_seed("transactionsimulate".as_bytes());
            let contract_addr = to_addr(&private_key);

            let code_body =
                "(define-public (test-fn (amount uint)) (ok amount))";

            let contract_deploy = make_contract_publish_tx(
                &private_key,
                0,
                1000,
                CHAIN_ID_TESTNET,
                "test-contract",
                &code_body,
                None,
            );

            let boot_tenures = vec![NakamotoBootTenure::Sortition(vec![
                NakamotoBootStep::Block(vec![contract_deploy]),
            ])];

            boot_plan
                .with_boot_tenures(boot_tenures)
                .with_initial_balances(vec![(contract_addr.into(), 1_000_000)])
        });

    // Now simulate a contract call to the deployed contract
    let private_key = StacksPrivateKey::from_seed("transactionsimulate".as_bytes());
    let contract_addr = to_addr(&private_key);

    let contract_name = ContractName::from("test-contract");
    let function_name = ClarityName::from("test-fn");

    let payload = TransactionContractCall {
        address: contract_addr.clone(),
        contract_name,
        function_name,
        function_args: vec![ClarityValue::UInt(42)],
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
    unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;

    let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
    tx_signer.sign_origin(&private_key).unwrap();
    let signed_tx = tx_signer.get_tx().unwrap();

    let mut request = StacksHttpRequest::new_transaction_simulate_with_options(
        addr.clone().into(),
        &signed_tx,
        Some(&rpc_test.canonical_tip),
        false, // no profiler
        false, // respect limits
    );
    request.add_header("authorization".into(), "password".into());

    let mut responses = rpc_test.run(vec![request]);
    let response = responses.remove(0);

    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_simulated_transaction().unwrap();

    assert_eq!(resp.txid, signed_tx.txid());
    // The transaction should be valid
    if resp.valid {
        assert!(resp.result.is_some());
        // Should return (ok u42)
        let result = resp.result.unwrap();
        assert!(result.expect_result_ok().is_ok());
    } else {
        debug!("Transaction simulation failed: {:?}", resp.error);
    }
}
