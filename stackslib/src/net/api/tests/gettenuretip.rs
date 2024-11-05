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

use clarity::vm::types::{QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::{ClarityName, ContractName};
use serde_json;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{ConsensusHash, StacksAddress};
use stacks_common::types::net::PeerHost;
use stacks_common::types::Address;

use super::test_rpc;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::net::api::tests::TestRPC;
use crate::net::api::{gettenuretip, *};
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{
    HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp,
    StacksHttpRequest,
};
use crate::net::test::TestEventObserver;
use crate::net::{ProtocolFamily, TipRequest};

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let request = StacksHttpRequest::new_get_tenure_tip(addr.into(), &ConsensusHash([0x01; 20]));

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();

    let mut handler = gettenuretip::RPCNakamotoTenureTipRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();
    assert_eq!(handler.consensus_hash, Some(ConsensusHash([0x01; 20])));

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();
    let mut rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

    let nakamoto_chain_tip = rpc_test.canonical_tip.clone();
    let consensus_hash = rpc_test.consensus_hash.clone();

    let mut requests = vec![];

    // query existing, non-empty Nakamoto tenure
    let request = StacksHttpRequest::new_get_tenure_tip(addr.clone().into(), &consensus_hash);
    requests.push(request);

    // query existing epoch2 tenure
    let all_sortitions = rpc_test.peer_1.sortdb().get_all_snapshots().unwrap();
    assert!(all_sortitions.len() > 30);
    assert!(all_sortitions[30].sortition);
    let epoch2_consensus_hash = all_sortitions[30].consensus_hash.clone();

    let request =
        StacksHttpRequest::new_get_tenure_tip(addr.clone().into(), &epoch2_consensus_hash);
    requests.push(request);

    // query non-existant tenure
    let request =
        StacksHttpRequest::new_get_tenure_tip(addr.clone().into(), &ConsensusHash([0x01; 20]));
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    // got the Nakamoto tip
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_tenure_tip().unwrap();
    assert_eq!(
        resp.as_stacks_nakamoto().unwrap().consensus_hash,
        consensus_hash
    );
    assert_eq!(
        resp.as_stacks_nakamoto().unwrap().block_id(),
        nakamoto_chain_tip
    );

    // got an epoch2 block
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_tenure_tip().unwrap();
    let block_header = resp.as_stacks_epoch2().unwrap();
    assert_eq!(
        block_header.block_hash(),
        all_sortitions[30].winning_stacks_block_hash
    );

    // got a failure
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 404);
}
