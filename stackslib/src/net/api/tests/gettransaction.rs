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

use clarity::util::hash::hex_bytes;
use stacks_common::codec::StacksMessageCodec;

use super::TestRPC;
use crate::burnchains::Txid;
use crate::chainstate::stacks::StacksTransaction;
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{RPCRequestHandler, StacksHttp, StacksHttpRequest};
use crate::net::test::TestEventObserver;
use crate::net::ProtocolFamily;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr, &ConnectionOptions::default());

    let request = StacksHttpRequest::new_gettransaction(
        addr.into(),
        Txid::from_hex("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").unwrap(),
    );
    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = gettransaction::RPCGetTransactionRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    // parsed request consumes headers that would not be in a constructed request
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    // consumed path args
    assert_eq!(
        handler.txid,
        Some(
            Txid::from_hex("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
                .unwrap()
        )
    );

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.txid.is_none());
}

#[test]
fn test_transaction_indexing_not_implemented() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();
    let rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

    let mut requests = vec![];

    // query dummy transaction
    let request = StacksHttpRequest::new_gettransaction(addr.into(), Txid([0x21; 32]));
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    // get response (501 Not Implemented)
    let response = responses.remove(0);

    let (preamble, body) = response.destruct();

    assert_eq!(preamble.status_code, 501);
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();
    let rpc_test =
        TestRPC::setup_nakamoto_with_boot_plan(function_name!(), &test_observer, |boot_plan| {
            boot_plan.with_txindex(true)
        });

    let consensus_hash = rpc_test.consensus_hash.clone();
    let canonical_tip = rpc_test.canonical_tip.clone();

    // dummy hack for generating an invalid tip
    let mut dummy_tip = rpc_test.canonical_tip.clone();
    dummy_tip.0[0] = dummy_tip.0[0].wrapping_add(1);

    let peer = &rpc_test.peer_1;
    let sortdb = peer.sortdb.as_ref().unwrap();
    let tenure_blocks = rpc_test
        .peer_1
        .chainstate_ref()
        .nakamoto_blocks_db()
        .get_all_blocks_in_tenure(&consensus_hash, &canonical_tip)
        .unwrap();

    let nakamoto_block_genesis = tenure_blocks.first().unwrap();
    let tx_genesis = &nakamoto_block_genesis.txs[0];

    let nakamoto_block_tip = tenure_blocks.last().unwrap();
    let tx_tip = &nakamoto_block_tip.txs[0];

    let mut requests = vec![];

    // query the transactions
    let request = StacksHttpRequest::new_gettransaction(addr.into(), tx_genesis.txid());
    requests.push(request);

    let request = StacksHttpRequest::new_gettransaction(addr.into(), tx_tip.txid());
    requests.push(request);

    // fake transaction
    let request = StacksHttpRequest::new_gettransaction(addr.into(), Txid([0x21; 32]));
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    // check genesis txid
    let response = responses.remove(0);
    let resp = response.decode_gettransaction().unwrap();

    let tx_bytes = hex_bytes(&resp.tx).unwrap();
    let stacks_transaction = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
    assert_eq!(stacks_transaction.txid(), tx_genesis.txid());
    assert_eq!(stacks_transaction.serialize_to_vec(), tx_bytes);

    // check tip txid
    let response = responses.remove(0);
    let resp = response.decode_gettransaction().unwrap();

    let tx_bytes = hex_bytes(&resp.tx).unwrap();
    let stacks_transaction = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
    assert_eq!(stacks_transaction.txid(), tx_tip.txid());
    assert_eq!(stacks_transaction.serialize_to_vec(), tx_bytes);

    // invalid tx
    let response = responses.remove(0);
    let (preamble, body) = response.destruct();

    assert_eq!(preamble.status_code, 404);
}
