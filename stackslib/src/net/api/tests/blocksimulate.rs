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

use stacks_common::types::chainstate::StacksBlockId;

use crate::net::api::blocksimulate;
use crate::net::api::tests::TestRPC;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{StacksHttp, StacksHttpRequest};
use crate::net::test::TestEventObserver;
use crate::net::ProtocolFamily;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let mut request =
        StacksHttpRequest::new_block_simulate(addr.into(), &StacksBlockId([0x01; 32]));

    // add the authorization header
    request.add_header("authorization".into(), "password".into());

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();

    let mut handler =
        blocksimulate::RPCNakamotoBlockSimulateRequestHandler::new(Some("password".into()));

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
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();
    let rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

    let nakamoto_consensus_hash = rpc_test.consensus_hash.clone();

    let mut requests = vec![];

    // query existing, non-empty Nakamoto block
    let mut request =
        StacksHttpRequest::new_block_simulate(addr.clone().into(), &rpc_test.canonical_tip);
    // add the authorization header
    request.add_header("authorization".into(), "password".into());
    requests.push(request);

    // query non-existent block
    let mut request =
        StacksHttpRequest::new_block_simulate(addr.clone().into(), &StacksBlockId([0x01; 32]));
    // add the authorization header
    request.add_header("authorization".into(), "password".into());
    requests.push(request);

    // unauthenticated request
    let request =
        StacksHttpRequest::new_block_simulate(addr.clone().into(), &StacksBlockId([0x00; 32]));
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    // got the Nakamoto tip
    let response = responses.remove(0);

    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_simulated_block().unwrap();

    let tip_block = test_observer.get_blocks().last().unwrap().clone();

    assert_eq!(resp.consensus_hash, nakamoto_consensus_hash);
    assert_eq!(resp.consensus_hash, tip_block.metadata.consensus_hash);

    assert_eq!(resp.block_hash, tip_block.block.block_hash);
    assert_eq!(resp.block_id, tip_block.metadata.index_block_hash());
    assert_eq!(resp.parent_block_id, tip_block.parent);

    assert!(resp.valid_merkle_root);

    assert_eq!(resp.transactions.len(), tip_block.receipts.len());

    for tx_index in 0..resp.transactions.len() {
        assert_eq!(
            resp.transactions[tx_index].txid,
            tip_block.receipts[tx_index].transaction.txid()
        );
        assert_eq!(
            resp.transactions[tx_index].events.len(),
            tip_block.receipts[tx_index].events.len()
        );
        assert_eq!(
            resp.transactions[tx_index].result,
            tip_block.receipts[tx_index].result
        );
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
