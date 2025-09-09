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

use super::TestRPC;
use crate::net::api::gethealth::{RPCGetHealthRequestHandler, RPCGetHealthResponse};
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{HttpPreambleExtensions as _, StacksHttp, StacksHttpRequest};
use crate::net::test::TestEventObserver;
use crate::net::ProtocolFamily;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33333);
    let mut http = StacksHttp::new(addr, &ConnectionOptions::default());

    let request = StacksHttpRequest::new_gethealth(addr.into());
    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = RPCGetHealthRequestHandler::new();
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

    assert_eq!(&preamble, request.preamble());
}

#[rstest]
#[case::node_behind(100, 100)]
#[case::same_height(0, 0)]
#[case::node_ahead(-10, 0)]
fn test_get_health(
    #[case] peer_1_height_relative_to_node: i64, // How many blocks peer_1 is ahead (positive) or behind (negative) the node.
    #[case] expected_difference_from_max_peer: u64,
) {
    // `rpc_test` will have peer_1 (client) and peer_2 (server/node)

    let test_observer = TestEventObserver::new();
    let mut rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

    // The node being tested is peer_2 (server role in TestRPC)
    rpc_test.peer_2.refresh_burnchain_view();
    let node_stacks_tip_height = rpc_test.peer_2.network.stacks_tip.height;

    // Calculate the target height for peer_1 based on the node's height and the relative offset
    let peer_1_actual_height = if peer_1_height_relative_to_node < 0 {
        node_stacks_tip_height.saturating_sub(peer_1_height_relative_to_node.abs() as u64)
    } else {
        node_stacks_tip_height + (peer_1_height_relative_to_node as u64)
    };
    let peer_1_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        rpc_test.peer_1.config.http_port,
    );
    rpc_test.peer_2.network.highest_stacks_neighbor = Some((peer_1_addr, peer_1_actual_height));

    // --- Invoke the Handler ---
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33333);
    let request = StacksHttpRequest::new_gethealth(addr.into());
    let mut responses = rpc_test.run(vec![request]);
    let response = responses.remove(0);

    // --- Assertions ---
    let (http_resp_preamble, contents) = response.destruct();
    assert_eq!(http_resp_preamble.status_code, 200, "Expected HTTP 200 OK");

    let response_json_val: serde_json::Value = contents
        .try_into()
        .unwrap_or_else(|e| panic!("Failed to parse JSON: {e}"));
    let health_response: RPCGetHealthResponse = serde_json::from_value(response_json_val)
        .unwrap_or_else(|e| panic!("Failed to deserialize RPCGetHealthResponse: {e}"));

    assert_eq!(
        health_response.node_stacks_tip_height, node_stacks_tip_height,
        "Mismatch in node_stacks_tip_height"
    );
    assert_eq!(
        health_response.max_stacks_height_of_neighbors, peer_1_actual_height,
        "Mismatch in max_stacks_height_of_neighbors"
    );
    assert_eq!(
        health_response.difference_from_max_peer, expected_difference_from_max_peer,
        "Mismatch in difference_from_max_peer"
    );

    assert_eq!(
        health_response.max_stacks_neighbor_address,
        Some(peer_1_addr.to_string()),
        "Mismatch in max_stacks_neighbor_address"
    );
}

#[test]
fn test_get_health_no_peers_stats() {
    let test_observer = TestEventObserver::new();
    let rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);
    // --- Invoke the Handler ---
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33333);
    let request = StacksHttpRequest::new_gethealth(addr.into());
    let mut responses = rpc_test.run(vec![request]);
    let response = responses.remove(0);
    // --- Assertions ---
    let (http_resp_preamble, contents) = response.destruct();
    assert_eq!(http_resp_preamble.status_code, 200, "Expected HTTP 200 OK");
    let response_json_val: serde_json::Value = contents.try_into().unwrap();
    let health_response: RPCGetHealthResponse = serde_json::from_value(response_json_val).unwrap();
    assert_eq!(health_response.max_stacks_height_of_neighbors, 0);
    assert_eq!(
        health_response.node_stacks_tip_height,
        http_resp_preamble
            .get_canonical_stacks_tip_height()
            .unwrap()
    );
    assert_eq!(health_response.difference_from_max_peer, 0);
}
