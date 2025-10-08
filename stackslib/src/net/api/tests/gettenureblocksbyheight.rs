// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2025 Stacks Open Internet Foundation
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

use crate::net::api::gettenureblocksbyheight;
use crate::net::api::tests::TestRPC;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{StacksHttp, StacksHttpRequest};
use crate::net::test::TestEventObserver;
use crate::net::ProtocolFamily;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let request =
        StacksHttpRequest::new_get_tenure_blocks_by_height(addr.into(), 0x7ffffffffffffffe);

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();

    let mut handler = gettenureblocksbyheight::RPCNakamotoTenureBlocksByHeightRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();
    assert_eq!(handler.burnchain_block_height, Some(0x7ffffffffffffffe));

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

    let burn_header_height = test_observer
        .get_blocks()
        .last()
        .unwrap()
        .metadata
        .burn_header_height;

    let mut requests = vec![];

    // query existing, non-empty Nakamoto tenure
    let request = StacksHttpRequest::new_get_tenure_blocks_by_height(
        addr.clone().into(),
        u64::from(burn_header_height),
    );
    requests.push(request);

    let genesis_burn_header_height = test_observer
        .get_blocks()
        .first()
        .unwrap()
        .metadata
        .burn_header_height;

    // query existing, non-empty Epoch2 tenure (will fail as we do not support it in search by hash or height)
    let request = StacksHttpRequest::new_get_tenure_blocks_by_height(
        addr.clone().into(),
        u64::from(genesis_burn_header_height),
    );
    requests.push(request);

    // query non-existant tenure
    let request =
        StacksHttpRequest::new_get_tenure_blocks_by_height(addr.clone().into(), 0x7ffffffffffffffe);
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    // got the Nakamoto tip
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_tenure_blocks().unwrap();
    assert_eq!(resp.burn_block_height, u64::from(burn_header_height));
    let mut blocks_index = 0;
    for block in test_observer.get_blocks().iter().rev() {
        if block.metadata.burn_header_height != burn_header_height {
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

    // Epoch2 (genesis) will fail

    // got a failure
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 404);

    // got a failure
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 404);
}
