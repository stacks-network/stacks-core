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

use stacks_common::types::chainstate::ConsensusHash;

use crate::net::api::gettenureblocks;
use crate::net::api::tests::TestRPC;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{StacksHttp, StacksHttpRequest};
use crate::net::test::TestEventObserver;
use crate::net::ProtocolFamily;

// A helper function to find two tenures with empty sortitions in between
pub fn find_sortitions_with_empty_sortitions_between(
    rpc_test: &mut TestRPC,
) -> (ConsensusHash, ConsensusHash, Vec<ConsensusHash>) {
    // Find two tenures with empty sortitions in bewteen
    let snapshots = rpc_test.peer_1.sortdb().get_all_snapshots().unwrap();

    let mut first_sortition: Option<&_> = None;
    let mut saw_non_sortition_between = false;
    let mut consensus_hashes_between = vec![];

    let mut result: Option<(&_, &_)> = None;

    for s in snapshots.iter() {
        if s.sortition {
            match first_sortition {
                None => {
                    first_sortition = Some(s);
                    saw_non_sortition_between = false;
                }
                Some(prev) => {
                    if saw_non_sortition_between {
                        // Found: sortition -> non-sortition(s) -> sortition
                        result = Some((prev, s));
                        break;
                    } else {
                        // restart window
                        first_sortition = Some(s);
                        saw_non_sortition_between = false;
                    }
                }
            }
        } else if first_sortition.is_some() {
            saw_non_sortition_between = true;
            consensus_hashes_between.push(s.consensus_hash.clone());
        }
    }

    let (first, second) = result
        .expect("Did not find sortition, non-sortition(s), sortition pattern required for test");
    (
        first.consensus_hash.clone(),
        second.consensus_hash.clone(),
        consensus_hashes_between,
    )
}

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
    let mut rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

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
        .consensus_hash
        .clone();

    // query existing, non-empty Epoch2 tenure
    let request =
        StacksHttpRequest::new_get_tenure_blocks(addr.clone().into(), &genesis_consensus_hash);
    requests.push(request);

    // query non-existant tenure
    let request =
        StacksHttpRequest::new_get_tenure_blocks(addr.clone().into(), &ConsensusHash([0x01; 20]));
    requests.push(request);

    // query tenure with empty sortitions in between
    let (first, second, consensus_hashes_between) =
        find_sortitions_with_empty_sortitions_between(&mut rpc_test);
    assert!(
        !consensus_hashes_between.is_empty(),
        "Test requires at least one empty sortition between tenures"
    );
    let request = StacksHttpRequest::new_get_tenure_blocks(addr.clone().into(), &second);
    requests.push(request);

    // Query an empty tenure directly
    let empty_tenure_ch = consensus_hashes_between.first().unwrap();
    let request = StacksHttpRequest::new_get_tenure_blocks(addr.into(), empty_tenure_ch);
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
    assert_ne!(
        resp.last_sortition_ch, genesis_consensus_hash,
        "Nakamoto tenure's last_sortition_ch should point to the previous winning sortition"
    );

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

    // genesis/Epoch2 tenure has no parent tenure. Should return an empty consensus hash.
    assert_eq!(
        resp.last_sortition_ch,
        ConsensusHash::from_bytes(&[0u8; 20]).unwrap(),
    );

    let blocks = test_observer.get_blocks();

    let block = blocks.first().unwrap();

    assert_eq!(resp.stacks_blocks.len(), 1);

    assert_eq!(
        resp.stacks_blocks[0].block_id,
        block.metadata.index_block_hash()
    );

    assert_eq!(resp.stacks_blocks[0].header_type, "epoch2");

    // got a failure
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, _body) = response.destruct();
    assert_eq!(preamble.status_code, 500);

    // got tenure with empty sortitions in between
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_tenure_blocks().unwrap();
    assert_eq!(resp.consensus_hash, second);
    assert_eq!(resp.last_sortition_ch, first);

    // got a tenure with no blocks (empty sortition)
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );
    let resp = response.decode_tenure_blocks().unwrap();
    assert_eq!(&resp.consensus_hash, empty_tenure_ch);
    assert_eq!(resp.last_sortition_ch, first);
    assert!(resp.stacks_blocks.is_empty());
}
