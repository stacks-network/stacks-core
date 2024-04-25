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

use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::{ClarityName, ContractName, Value};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::net::PeerHost;
use stacks_common::types::Address;

use super::TestRPC;
use crate::chainstate::stacks::test::make_codec_test_microblock;
use crate::chainstate::stacks::StacksMicroblock;
use crate::core::BLOCK_LIMIT_MAINNET_21;
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{
    HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp, StacksHttpRequest,
};
use crate::net::{ProtocolFamily, TipRequest};

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let mblock = make_codec_test_microblock(3);
    let request = StacksHttpRequest::new_post_microblock(
        addr.into(),
        mblock.clone(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32])),
    );
    assert_eq!(
        request.contents().tip_request(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32]))
    );

    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = postmicroblock::RPCPostMicroblockRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    assert_eq!(handler.microblock, Some(mblock.clone()));

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.microblock.is_none());

    // try to decode a bad microblock
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());
    let mut bad_mblock = mblock.clone();
    bad_mblock.txs.clear();
    let request = StacksHttpRequest::new_post_microblock(
        addr.into(),
        bad_mblock.clone(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32])),
    );

    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = postmicroblock::RPCPostMicroblockRequestHandler::new();
    match http.handle_try_parse_request(
        &mut handler,
        &parsed_preamble.expect_request(),
        &bytes[offset..],
    ) {
        Err(NetError::Http(Error::DecodeError(..))) => {}
        _ => {
            panic!("worked with bad microblock");
        }
    }
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_rpc = TestRPC::setup_ex(function_name!(), false);
    let mblock = test_rpc.next_microblock.clone().unwrap();

    let mut requests = vec![];

    // fails due to bad tip
    let request = StacksHttpRequest::new_post_microblock(
        addr.into(),
        mblock.clone(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32])),
    );
    requests.push(request);

    // succeeds
    let request = StacksHttpRequest::new_post_microblock(
        addr.into(),
        mblock.clone(),
        TipRequest::UseLatestAnchoredTip,
    );
    requests.push(request);

    let mut responses = test_rpc.run(requests);

    // fails due to bad tip
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 404);

    // succeeds
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let mblock_hash = response.decode_stacks_microblock_response().unwrap();
    assert_eq!(mblock_hash, mblock.block_hash());
}
