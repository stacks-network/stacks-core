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

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clarity::vm::types::PrincipalData;
use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};
use stacks_common::util::pipe::Pipe;

use super::TestRPC;
use crate::chainstate::stacks::{
    StacksTransaction, StacksTransactionSigner, TransactionAuth, TransactionPayload,
    TransactionVersion,
};
use crate::core::mempool::{
    ArrivalSeqBlock, MemPoolDB, ARRIVAL_SEQ_BLOCK_LEN, MAXIMUM_MEMPOOL_TX_CHAINING,
};
use crate::core::test_util::{
    make_sponsored_stacks_transfer_on_testnet, make_stacks_transfer_tx, to_addr,
};
use crate::core::CHAIN_ID_TESTNET;
use crate::net::api::posttransaction;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{RPCRequestHandler, StacksHttp, StacksHttpRequest, StacksHttpResponse};
use crate::net::poll::SocketArrival;
use crate::net::rpc::ConversationHttp;
use crate::net::test::{RPCHandlerArgsType, TestPeer};
use crate::net::{Attachment, ProtocolFamily, StacksNodeState};

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
    // the body was stamped on receipt
    let first_arrival_seq = handler.arrival_seq.expect("request body was not stamped");

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.tx.is_none());
    assert!(handler.attachment.is_none());
    assert!(handler.arrival_seq.is_none());

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
    // a later receipt gets a later stamp
    assert!(handler.arrival_seq.unwrap() > first_arrival_seq);

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

/// Deliver a `POST /v2/transactions` to `convo` as a socket read, with the first `queued_bytes` of
/// it already queued when `poll()` reserved `arrival_seqs`, then handle it on `peer`.
fn post_tx_as_socket_read(
    peer: &mut TestPeer,
    convo: &mut ConversationHttp,
    tx: &StacksTransaction,
    arrival_seqs: ArrivalSeqBlock,
    queued_bytes: impl FnOnce(usize) -> usize,
) {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let bytes = StacksHttpRequest::new_post_transaction(addr.into(), tx.clone())
        .try_serialize()
        .unwrap();
    let arrival = SocketArrival {
        arrival_seqs,
        queued_bytes: queued_bytes(bytes.len()),
    };
    let (mut pipe_read, mut pipe_write) = Pipe::new();
    pipe_read.set_nonblocking(true);
    pipe_write.write_all(&bytes).unwrap();
    pipe_write.try_flush().unwrap();
    convo.recv_ready(&mut pipe_read, Some(arrival)).unwrap();

    peer.refresh_burnchain_view();
    let sortdb = peer.chain.sortdb.take().unwrap();
    let mut stacks_node = peer.chain.stacks_node.take().unwrap();
    let mut mempool = peer.mempool.take().unwrap();
    let rpc_args = RPCHandlerArgsType::make_default();
    let mut node_state = StacksNodeState::new(
        &mut peer.network,
        &sortdb,
        &mut stacks_node.chainstate,
        &mut mempool,
        &rpc_args,
        false,
        peer.config.chain_config.txindex,
    );
    convo.chat(&mut node_state).unwrap();
    peer.chain.sortdb = Some(sortdb);
    peer.chain.stacks_node = Some(stacks_node);
    peer.mempool = Some(mempool);

    // clear the reply, so the conversation can take the next request
    let mut reply = vec![];
    convo.send(&mut reply).unwrap();
    assert!(!reply.is_empty());
}

#[test]
/// `POST /v2/transactions` over a conversation: the transaction is stored with the arrival stamp
/// `poll()` reserved if all of the request was queued by then, and a fresh stamp otherwise. A
/// duplicate lowers the stored stamp if it was received earlier.
fn test_post_transaction_uses_socket_arrival_seq() {
    let TestRPC {
        mut peer_2,
        mut convo_2,
        sendable_txs,
        ..
    } = TestRPC::setup(function_name!());
    let [fully_queued, partly_queued, duplicate, ..] = sendable_txs.as_slice() else {
        panic!("expected at least three sendable transactions");
    };
    let stored_stamp = |peer: &TestPeer, tx: &StacksTransaction| {
        let mempool = peer.mempool.as_ref().unwrap();
        MemPoolDB::get_tx(mempool.conn(), &tx.txid())
            .unwrap()
            .unwrap()
            .metadata
            .arrival_seq
    };

    // all of it was queued when the poll returned: stamped by the poll, not when handled
    let block = ArrivalSeqBlock::reserve();
    let mut expected = block;
    post_tx_as_socket_read(&mut peer_2, &mut convo_2, fully_queued, block, |len| len);
    assert_eq!(stored_stamp(&peer_2, fully_queued), expected.take());

    // its last byte landed after the poll returned: stamped when read
    let block = ArrivalSeqBlock::reserve();
    let mut reserved = block;
    post_tx_as_socket_read(&mut peer_2, &mut convo_2, partly_queued, block, |len| {
        len - 1
    });
    assert!(stored_stamp(&peer_2, partly_queued) >= reserved.take() + ARRIVAL_SEQ_BLOCK_LEN);

    // stored from a later receipt, then received again with an earlier stamp
    let earlier = ArrivalSeqBlock::reserve();
    let later = ArrivalSeqBlock::reserve();
    let mut expected = earlier;
    post_tx_as_socket_read(&mut peer_2, &mut convo_2, duplicate, later, |len| len);
    assert!(stored_stamp(&peer_2, duplicate) > { expected }.take());
    post_tx_as_socket_read(&mut peer_2, &mut convo_2, duplicate, earlier, |len| len);
    assert_eq!(stored_stamp(&peer_2, duplicate), expected.take());
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
    // Both nonces are ahead of their accounts but within the chaining limit, so
    // admission gets past the chaining checks to the sponsor's balance.
    let sponsored_bytes = make_sponsored_stacks_transfer_on_testnet(
        &spender_sk,
        &low_funds_sk,
        1 + MAXIMUM_MEMPOOL_TX_CHAINING,
        1,
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
