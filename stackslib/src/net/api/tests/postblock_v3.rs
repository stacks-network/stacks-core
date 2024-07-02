// Copyright (C) 2024 Stacks Open Internet Foundation
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

use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::{ClarityName, ContractName, Value};
use stacks_common::types::chainstate::{ConsensusHash, StacksAddress, StacksPrivateKey};
use stacks_common::types::net::PeerHost;
use stacks_common::types::{Address, StacksEpochId};

use super::TestRPC;
use crate::chainstate::stacks::test::make_codec_test_nakamoto_block;
use crate::chainstate::stacks::StacksBlockHeader;
use crate::core::BLOCK_LIMIT_MAINNET_21;
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{
    HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp, StacksHttpRequest,
};
use crate::net::test::TestEventObserver;
use crate::net::{ProtocolFamily, TipRequest};

#[test]
fn parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let miner_sk = StacksPrivateKey::from_seed(&[0, 1, 2, 3, 4, 5, 6, 7, 8]);
    let block = make_codec_test_nakamoto_block(StacksEpochId::Epoch30, &miner_sk);
    let request = StacksHttpRequest::new_post_block_v3(addr.into(), &block);
    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = postblock_v3::RPCPostBlockRequestHandler::default();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    assert_eq!(handler.block, Some(block.clone()));

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, _contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.block.is_none());

    // try to deal with an invalid block
    let mut bad_block = block.clone();
    bad_block.txs.clear();

    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());
    let request = StacksHttpRequest::new_post_block_v3(addr.into(), &bad_block);
    let bytes = request.try_serialize().unwrap();
    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = postblock_v3::RPCPostBlockRequestHandler::default();
    match http.handle_try_parse_request(
        &mut handler,
        &parsed_preamble.expect_request(),
        &bytes[offset..],
    ) {
        Err(NetError::Http(Error::DecodeError(..))) => {}
        _ => {
            panic!("worked with bad block");
        }
    }
}

#[test]
fn handle_req_accepted() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let observer = TestEventObserver::new();
    let mut rpc_test = TestRPC::setup_nakamoto(function_name!(), &observer);
    let (next_block, ..) = rpc_test.peer_1.single_block_tenure(
        &rpc_test.privk1,
        |_| {},
        |burn_ops| {
            rpc_test.peer_2.next_burnchain_block(burn_ops.clone());
        },
        |_| true,
    );
    let next_block_id = next_block.block_id();
    let mut requests = vec![];

    // post the block
    requests.push(StacksHttpRequest::new_post_block_v3(
        addr.into(),
        &next_block,
    ));

    // idempotent
    requests.push(StacksHttpRequest::new_post_block_v3(
        addr.into(),
        &next_block,
    ));

    let mut responses = rpc_test.run(requests);

    let response = responses.remove(0);
    info!(
        "Response: {}",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_stacks_block_accepted().unwrap();
    assert_eq!(resp.accepted, true);
    assert_eq!(resp.stacks_block_id, next_block_id);

    let response = responses.remove(0);
    info!(
        "Response: {}",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );
    let resp = response.decode_stacks_block_accepted().unwrap();
    assert_eq!(resp.accepted, false);
    assert_eq!(resp.stacks_block_id, next_block_id);
}

#[test]
fn handle_req_unknown_burn_block() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let observer = TestEventObserver::new();
    let mut rpc_test = TestRPC::setup_nakamoto(function_name!(), &observer);
    // test with a consensus hash not known yet to the peer
    let (next_block, ..) =
        rpc_test
            .peer_1
            .single_block_tenure(&rpc_test.privk1, |_| {}, |_| {}, |_| true);
    let next_block_id = next_block.block_id();
    let requests = vec![StacksHttpRequest::new_post_block_v3(
        addr.into(),
        &next_block,
    )];

    let mut responses = rpc_test.run(requests);
    let response = responses.remove(0);
    info!(
        "Response: {}",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 400);
}
