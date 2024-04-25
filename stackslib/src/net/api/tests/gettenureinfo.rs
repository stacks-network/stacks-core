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

use clarity::vm::types::{QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::{ClarityName, ContractName};
use serde_json;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::net::PeerHost;
use stacks_common::types::Address;

use super::test_rpc;
use crate::net::api::getinfo::RPCPeerInfoData;
use crate::net::api::tests::TestRPC;
use crate::net::api::*;
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

    let request = StacksHttpRequest::new_get_nakamoto_tenure_info(addr.into());

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut parsed_request = http
        .try_parse_request(&parsed_preamble.expect_request(), &bytes[offset..])
        .unwrap();

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();
    let rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

    let nakamoto_chain_tip = rpc_test.canonical_tip.clone();
    let consensus_hash = rpc_test.consensus_hash.clone();

    let mut requests = vec![];

    // query existing account
    let request = StacksHttpRequest::new_get_nakamoto_tenure_info(addr.into());
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_nakamoto_tenure_info().unwrap();
    assert_eq!(resp.consensus_hash, consensus_hash);
    assert_eq!(resp.tip_block_id, nakamoto_chain_tip);
}
