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
use stacks_common::types::chainstate::{ConsensusHash, StacksAddress};
use stacks_common::types::net::PeerHost;
use stacks_common::types::{Address, StacksEpochId};

use super::TestRPC;
use crate::chainstate::stacks::test::make_codec_test_block;
use crate::chainstate::stacks::StacksBlockHeader;
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

    let block = make_codec_test_block(3, StacksEpochId::Epoch25);
    let request =
        StacksHttpRequest::new_post_block(addr.into(), ConsensusHash([0x11; 20]), block.clone());
    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = postblock::RPCPostBlockRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    assert_eq!(handler.consensus_hash, Some(ConsensusHash([0x11; 20])));
    assert_eq!(handler.block, Some(block.clone()));

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.consensus_hash.is_none());
    assert!(handler.block.is_none());

    // try to deal with an invalid block
    let mut bad_block = block.clone();
    bad_block.txs.clear();

    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());
    let request = StacksHttpRequest::new_post_block(
        addr.into(),
        ConsensusHash([0x11; 20]),
        bad_block.clone(),
    );
    let bytes = request.try_serialize().unwrap();
    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = postblock::RPCPostBlockRequestHandler::new();
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
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let rpc_test = TestRPC::setup(function_name!());
    let next_block = rpc_test.next_block.clone().unwrap();
    let stacks_block_id =
        StacksBlockHeader::make_index_block_hash(&next_block.0, &next_block.1.block_hash());
    let mut requests = vec![];

    // post the block
    let request =
        StacksHttpRequest::new_post_block(addr.into(), next_block.0.clone(), next_block.1.clone());
    requests.push(request);

    // idempotent
    let request =
        StacksHttpRequest::new_post_block(addr.into(), next_block.0.clone(), next_block.1.clone());
    requests.push(request);

    // fails if the consensus hash is not recognized
    let request = StacksHttpRequest::new_post_block(
        addr.into(),
        ConsensusHash([0x11; 20]),
        next_block.1.clone(),
    );
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_stacks_block_accepted().unwrap();
    assert_eq!(resp.accepted, true);
    assert_eq!(resp.stacks_block_id, stacks_block_id);

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_stacks_block_accepted().unwrap();
    assert_eq!(resp.accepted, false);
    assert_eq!(resp.stacks_block_id, stacks_block_id);

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 404);
}
