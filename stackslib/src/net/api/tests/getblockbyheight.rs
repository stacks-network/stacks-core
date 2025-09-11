// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use super::TestRPC;
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{RPCRequestHandler, StacksHttp, StacksHttpRequest};
use crate::net::test::TestEventObserver;
use crate::net::{ProtocolFamily, TipRequest};

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr, &ConnectionOptions::default());

    // NOTE: MARF enforces the height to be a u32 value
    let request = StacksHttpRequest::new_get_nakamoto_block_by_height(
        addr.into(),
        0xfffffffe,
        TipRequest::UseLatestAnchoredTip,
    );
    // NOTE: MARF enforces the height to be a u32 value
    let request = StacksHttpRequest::new_get_nakamoto_block_by_height(
        addr.into(),
        0xfffffffe,
        TipRequest::UseLatestAnchoredTip,
    );
    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getblockbyheight::RPCNakamotoBlockByHeightRequestHandler::new();
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
    assert_eq!(handler.block_height, Some(0xfffffffe));

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.block_height.is_none());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();
    let rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

    let nakamoto_chain_tip_height = rpc_test.tip_height;
    let canonical_tip = rpc_test.canonical_tip.clone();
    let consensus_hash = rpc_test.consensus_hash.clone();

    let mut requests = vec![];

    // query existing block (empty tip)
    let request = StacksHttpRequest::new_get_nakamoto_block_by_height(
        addr.into(),
        nakamoto_chain_tip_height,
        TipRequest::UseLatestAnchoredTip,
    );
    requests.push(request);

    // query non-existent block (with biggest positive u32 value - 1 as MARF enforces it)
    let request = StacksHttpRequest::new_get_nakamoto_block_by_height(
        addr.into(),
        0xfffffffe,
        TipRequest::UseLatestAnchoredTip,
    );
    requests.push(request);

    // query existing block using the canonical_tip
    let request = StacksHttpRequest::new_get_nakamoto_block_by_height(
        addr.into(),
        nakamoto_chain_tip_height,
        TipRequest::SpecificTip(rpc_test.canonical_tip.clone()),
    );
    requests.push(request);

    // query existing block using the unconfirmed tip
    let request = StacksHttpRequest::new_get_nakamoto_block_by_height(
        addr.into(),
        nakamoto_chain_tip_height,
        TipRequest::UseLatestUnconfirmedTip,
    );
    requests.push(request);

    // dummy hack for generating an invalid tip
    let mut dummy_tip = rpc_test.canonical_tip.clone();
    dummy_tip.0[0] = dummy_tip.0[0].wrapping_add(1);

    let request = StacksHttpRequest::new_get_nakamoto_block_by_height(
        addr.into(),
        nakamoto_chain_tip_height,
        TipRequest::SpecificTip(dummy_tip),
    );
    // dummy hack for generating an invalid tip
    let mut dummy_tip = rpc_test.canonical_tip.clone();
    dummy_tip.0[0] = dummy_tip.0[0].wrapping_add(1);

    let request = StacksHttpRequest::new_get_nakamoto_block_by_height(
        addr.into(),
        nakamoto_chain_tip_height,
        TipRequest::SpecificTip(dummy_tip),
    );
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    // got the block
    let response = responses.remove(0);
    let resp = response.decode_nakamoto_block().unwrap();

    assert_eq!(resp.header.consensus_hash, consensus_hash);
    assert_eq!(resp.header.block_id(), canonical_tip);

    // no block
    let response = responses.remove(0);
    let (preamble, body) = response.destruct();

    assert_eq!(preamble.status_code, 404);

    // got the block from the tip
    let response = responses.remove(0);
    let resp = response.decode_nakamoto_block().unwrap();

    assert_eq!(resp.header.consensus_hash, consensus_hash);
    assert_eq!(resp.header.block_id(), canonical_tip);

    // got the block from the tip (unconfirmed)
    let response = responses.remove(0);
    let resp = response.decode_nakamoto_block().unwrap();

    assert_eq!(resp.header.consensus_hash, consensus_hash);
    assert_eq!(resp.header.block_id(), canonical_tip);

    // no block for dummy tip
    let response = responses.remove(0);
    let (preamble, body) = response.destruct();

    assert_eq!(preamble.status_code, 404);
}
