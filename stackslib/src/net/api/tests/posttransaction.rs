// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use clarity::vm::types::PrincipalData;
use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};

use super::TestRPC;
use crate::chainstate::stacks::{
    StacksTransaction, StacksTransactionSigner, TransactionAuth, TransactionPayload,
    TransactionVersion,
};
use crate::core::mempool::MAXIMUM_MEMPOOL_TX_CHAINING;
use crate::core::test_util::{
    make_sponsored_stacks_transfer_on_testnet, make_stacks_transfer_tx, to_addr,
};
use crate::core::CHAIN_ID_TESTNET;
use crate::net::api::posttransaction;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{RPCRequestHandler, StacksHttp, StacksHttpRequest, StacksHttpResponse};
use crate::net::{Attachment, ProtocolFamily};

fn rejection_data(
    response: StacksHttpResponse,
    tx: &StacksTransaction,
    reason: &str,
) -> serde_json::Value {
    let (preamble, body) = response.destruct();
    let body: serde_json::Value = body.try_into().unwrap();

    assert_eq!(preamble.status_code, 400);
    assert_eq!(body["txid"], tx.txid().to_string());
    assert_eq!(body["error"], "transaction rejected");
    assert_eq!(body["reason"], reason);

    body["reason_data"].clone()
}

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr, &ConnectionOptions::default());

    // ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R
    let privk1 = StacksPrivateKey::from_hex(
        "9f1f85a512a96a244e4c0d762788500687feb97481639572e3bffbd6860e6ab001",
    )
    .unwrap();

    let addr1 = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&privk1)],
    )
    .unwrap();

    let mut tx_cc = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&privk1).unwrap(),
        TransactionPayload::new_contract_call(addr1.clone(), "hello-world", "add-unit", vec![])
            .unwrap(),
    );

    tx_cc.chain_id = 0x80000000;
    tx_cc.auth.set_origin_nonce(2);
    tx_cc.set_tx_fee(123);

    let mut tx_signer = StacksTransactionSigner::new(&tx_cc);
    tx_signer.sign_origin(&privk1).unwrap();
    let tx_cc_signed = tx_signer.get_tx().unwrap();

    // Test without an attachment
    let request = StacksHttpRequest::new_post_transaction(addr.into(), tx_cc_signed.clone());
    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = posttransaction::RPCPostTransactionRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    assert_eq!(handler.tx, Some(tx_cc_signed.clone()));
    assert!(handler.attachment.is_none());

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.tx.is_none());
    assert!(handler.attachment.is_none());

    // Test with a null attachment
    let request = StacksHttpRequest::new_post_transaction_with_attachment(
        addr.into(),
        tx_cc_signed.clone(),
        None,
    );
    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = posttransaction::RPCPostTransactionRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    assert_eq!(handler.tx, Some(tx_cc_signed.clone()));
    assert_eq!(handler.attachment, None);

    handler.restart();
    assert!(handler.tx.is_none());
    assert!(handler.attachment.is_none());

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    // Test with an attachment
    let request = StacksHttpRequest::new_post_transaction_with_attachment(
        addr.into(),
        tx_cc_signed.clone(),
        Some(vec![0, 1, 2, 3, 4]),
    );
    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = posttransaction::RPCPostTransactionRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    assert_eq!(handler.tx, Some(tx_cc_signed));
    assert_eq!(
        handler.attachment,
        Some(Attachment::new(vec![0, 1, 2, 3, 4]))
    );

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.tx.is_none());
    assert!(handler.attachment.is_none());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let rpc_test = TestRPC::setup(function_name!());
    let sendable_txs = rpc_test.sendable_txs.clone();

    let mut requests = vec![];

    // send a tx (should succeed)
    let request = StacksHttpRequest::new_post_transaction_with_attachment(
        addr.into(),
        sendable_txs[0].clone(),
        None,
    );
    requests.push(request);

    // send a tx with an attachment (should succeed)
    let request = StacksHttpRequest::new_post_transaction_with_attachment(
        addr.into(),
        sendable_txs[1].clone(),
        Some(vec![0, 1, 2, 3, 4]),
    );
    requests.push(request);

    // send the same tx (should succeed)
    let request = StacksHttpRequest::new_post_transaction_with_attachment(
        addr.into(),
        sendable_txs[0].clone(),
        None,
    );
    requests.push(request);

    // send a bad tx (should fail)
    let mut bad_tx = sendable_txs[2].clone();
    bad_tx.version = TransactionVersion::Mainnet;
    let request =
        StacksHttpRequest::new_post_transaction_with_attachment(addr.into(), bad_tx, None);
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let txid = response.decode_txid().unwrap();
    assert_eq!(txid, sendable_txs[0].txid());

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let txid = response.decode_txid().unwrap();
    assert_eq!(txid, sendable_txs[1].txid());

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let txid = response.decode_txid().unwrap();
    assert_eq!(txid, sendable_txs[0].txid());

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 400);
}

#[test]
fn test_rejection_responses_from_submitted_transactions() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33333);

    // A separate payer keeps the origin and sponsor balance checks independent
    // from the transactions mined by the shared RPC fixture.
    let low_funds_sk = StacksPrivateKey::random();
    let low_funds_principal: PrincipalData = to_addr(&low_funds_sk).into();
    let peer_1_low_funds = low_funds_principal.clone();
    let peer_2_low_funds = low_funds_principal.clone();

    let rpc_test = TestRPC::setup_ex_with_config(
        function_name!(),
        false,
        None,
        None,
        move |config| {
            config
                .chain_config
                .initial_balances
                .push((peer_1_low_funds.clone(), 990));
        },
        move |config| {
            config
                .chain_config
                .initial_balances
                .push((peer_2_low_funds.clone(), 990));
        },
    );

    let stale_spender_sk = rpc_test.privk1.clone();
    let stale_spender_principal: PrincipalData = to_addr(&stale_spender_sk).into();
    let spender_sk = rpc_test.privk2.clone();
    let spender_principal: PrincipalData = to_addr(&spender_sk).into();
    let recipient: PrincipalData = to_addr(&StacksPrivateKey::random()).into();

    let too_much_chaining =
        make_stacks_transfer_tx(&spender_sk, 30, 200, CHAIN_ID_TESTNET, &recipient, 456);
    // A valid transaction can still be rejected after decoding when its nonce is stale.
    let mut stale_contract = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&stale_spender_sk).unwrap(),
        TransactionPayload::new_smart_contract("test", "(+ 1 1)", None).unwrap(),
    );
    stale_contract.chain_id = CHAIN_ID_TESTNET;
    stale_contract.auth.set_origin_nonce(0);
    stale_contract.set_tx_fee(1000);
    let mut signer = StacksTransactionSigner::new(&stale_contract);
    signer.sign_origin(&stale_spender_sk).unwrap();
    let stale_contract = signer.get_tx().unwrap();
    let fee_too_low = make_stacks_transfer_tx(&spender_sk, 0, 1, CHAIN_ID_TESTNET, &recipient, 456);
    let origin_cannot_pay =
        make_stacks_transfer_tx(&low_funds_sk, 0, 2000, CHAIN_ID_TESTNET, &recipient, 456);
    let sponsored_bytes = make_sponsored_stacks_transfer_on_testnet(
        &spender_sk,
        &low_funds_sk,
        0,
        0,
        2000,
        CHAIN_ID_TESTNET,
        &recipient,
        1000,
    );
    let sponsor_cannot_pay =
        StacksTransaction::consensus_deserialize(&mut &sponsored_bytes[..]).unwrap();

    let requests = [
        stale_contract.clone(),
        too_much_chaining.clone(),
        fee_too_low.clone(),
        origin_cannot_pay.clone(),
        sponsor_cannot_pay.clone(),
    ]
    .into_iter()
    .map(|tx| StacksHttpRequest::new_post_transaction(addr.into(), tx))
    .collect();
    let mut responses = rpc_test.run(requests).into_iter();

    let data = rejection_data(responses.next().unwrap(), &stale_contract, "BadNonce");
    assert_eq!(data["is_origin"], true);
    assert_eq!(data["principal"], stale_spender_principal.to_string());
    assert_eq!(data["expected"], 2);
    assert_eq!(data["actual"], 0);

    let data = rejection_data(
        responses.next().unwrap(),
        &too_much_chaining,
        "TooMuchChaining",
    );
    assert_eq!(data["is_origin"], true);
    assert_eq!(data["principal"], spender_principal.to_string());
    assert_eq!(data["expected"], 1 + MAXIMUM_MEMPOOL_TX_CHAINING);
    assert_eq!(data["actual"], 30);

    let data = rejection_data(responses.next().unwrap(), &fee_too_low, "FeeTooLow");
    assert_eq!(data["expected"], 180);
    assert_eq!(data["actual"], 1);

    let data = rejection_data(
        responses.next().unwrap(),
        &origin_cannot_pay,
        "NotEnoughFunds",
    );
    assert_eq!(data["expected"], format!("0x{:032x}", 2456u128));
    assert_eq!(data["actual"], format!("0x{:032x}", 990u128));

    let data = rejection_data(
        responses.next().unwrap(),
        &sponsor_cannot_pay,
        "NotEnoughFunds",
    );
    assert_eq!(data["expected"], format!("0x{:032x}", 2000u128));
    assert_eq!(data["actual"], format!("0x{:032x}", 990u128));

    assert!(responses.next().is_none());
}
