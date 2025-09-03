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

use stacks_common::types::chainstate::ConsensusHash;

use crate::net::api::gettenureblocks;
use crate::net::api::tests::TestRPC;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{StacksHttp, StacksHttpRequest};
use crate::net::test::TestEventObserver;
use crate::net::ProtocolFamily;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let request = StacksHttpRequest::new_get_tenure_blocks(addr.into(), &ConsensusHash([0x01; 20]));

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();

    let mut handler = gettenureblocks::RPCNakamotoTenureBlocksRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();
    assert_eq!(handler.consensus_hash, Some(ConsensusHash([0x01; 20])));

    // parsed request consumes headers that would not be in a constructed request
    parsed_request.clear_headers();
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

    // query existing, non-empty Nakamoto tenure
    let request =
        StacksHttpRequest::new_get_tenure_blocks(addr.clone().into(), &nakamoto_consensus_hash);
    requests.push(request);

    let genesis_consensus_hash = test_observer
        .get_blocks()
        .first()
        .unwrap()
        .metadata
        .consensus_hash;

    // query existing, non-empty Epoch2 tenure
    let request =
        StacksHttpRequest::new_get_tenure_blocks(addr.clone().into(), &genesis_consensus_hash);
    requests.push(request);

    // query non-existant tenure
    let request =
        StacksHttpRequest::new_get_tenure_blocks(addr.clone().into(), &ConsensusHash([0x01; 20]));
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    // got the Nakamoto tip
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_tenure_blocks().unwrap();
    assert_eq!(resp.consensus_hash, nakamoto_consensus_hash);
    let mut blocks_index = 0;
    for block in test_observer.get_blocks().iter().rev() {
        if block.metadata.consensus_hash != nakamoto_consensus_hash {
            break;
        }

        assert_eq!(
            resp.stacks_blocks[blocks_index].block_id,
            block.metadata.index_block_hash()
        );

        assert_eq!(
            resp.stacks_blocks[blocks_index].parent_block_id.to_string(),
            block.parent.to_hex()
        );

        assert_eq!(resp.stacks_blocks[blocks_index].header_type, "nakamoto");

        blocks_index += 1;
    }

    assert_eq!(blocks_index, resp.stacks_blocks.len());

    // got Epoch2 (genesis)
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_tenure_blocks().unwrap();
    assert_eq!(resp.consensus_hash, genesis_consensus_hash);
    let mut blocks_index = resp.stacks_blocks.len() - 1;
    for block in test_observer.get_blocks() {
        if block.metadata.consensus_hash != genesis_consensus_hash {
            break;
        }

        assert_eq!(
            resp.stacks_blocks[blocks_index].block_id,
            block.metadata.index_block_hash()
        );

        assert_eq!(
            resp.stacks_blocks[blocks_index].parent_block_id.to_string(),
            block.parent.to_hex()
        );

        assert_eq!(resp.stacks_blocks[blocks_index].header_type, "epoch2");

        blocks_index -= 1;
    }

    assert_eq!(blocks_index, 0);

    // got a failure
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 404);
}
