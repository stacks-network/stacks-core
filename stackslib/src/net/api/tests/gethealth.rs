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

use clarity::types::chainstate::StacksBlockId;
use clarity::types::StacksEpochId;

use super::TestRPC;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use crate::chainstate::stacks::boot::RewardSet;
use crate::net::api::gethealth::{
    NeighborsScope, RPCGetHealthRequestHandler, RPCGetHealthResponse,
};
use crate::net::api::gettenureinfo::RPCGetTenureInfo;
use crate::net::connection::ConnectionOptions;
use crate::net::download::nakamoto::{
    NakamotoDownloadState, NakamotoDownloadStateMachine, NakamotoTenureDownloader,
    NakamotoUnconfirmedTenureDownloader,
};
use crate::net::http::HttpRequestContents;
use crate::net::httpcore::{StacksHttp, StacksHttpRequest};
use crate::net::test::TestEventObserver;
use crate::net::{NeighborAddress, ProtocolFamily};

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let request = StacksHttpRequest::new_gethealth(addr.into(), NeighborsScope::Initial);
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

// Helper function for Nakamoto health test scenarios
fn setup_and_run_nakamoto_health_test(
    test_function_name_suffix: &str,
    peer_1_height_relative_to_node: i64, // How many blocks peer_1 is ahead (positive) or behind (negative) the node.
    expected_difference_from_max_peer: u64,
    nakamoto_download_state: NakamotoDownloadState,
) {
    // `rpc_test` will have peer_1 (client) and peer_2 (server/node)
    let test_observer = TestEventObserver::new();
    let rpc_test_name = format!("{}{}", function_name!(), test_function_name_suffix);
    let mut rpc_test = TestRPC::setup_nakamoto(&rpc_test_name, &test_observer);

    // The node being tested is peer_2 (server role in TestRPC)
    rpc_test.peer_2.refresh_burnchain_view();
    let node_stacks_tip_height = rpc_test.peer_2.network.stacks_tip.height;

    // Calculate the target height for peer_1 based on the node's height and the relative offset
    let peer_1_actual_height = if peer_1_height_relative_to_node < 0 {
        node_stacks_tip_height.saturating_sub(peer_1_height_relative_to_node.abs() as u64)
    } else {
        node_stacks_tip_height + (peer_1_height_relative_to_node as u64)
    };

    let peer_1_address = NeighborAddress::from_neighbor(&rpc_test.peer_1.config.to_neighbor());

    // Setup peer_1's tenure information to reflect its calculated height
    let peer_1_tenure_tip = RPCGetTenureInfo {
        consensus_hash: rpc_test.peer_1.network.stacks_tip.consensus_hash.clone(),
        tenure_start_block_id: rpc_test.peer_1.network.tenure_start_block_id.clone(),
        parent_consensus_hash: rpc_test
            .peer_1
            .network
            .parent_stacks_tip
            .consensus_hash
            .clone(),
        parent_tenure_start_block_id: StacksBlockId::new(
            &rpc_test.peer_1.network.parent_stacks_tip.consensus_hash,
            &rpc_test.peer_1.network.parent_stacks_tip.block_hash,
        ),
        tip_block_id: StacksBlockId::new(
            &rpc_test.peer_1.network.stacks_tip.consensus_hash, // We are not changing the tip block id for this height adjustment
            &rpc_test.peer_1.network.stacks_tip.block_hash,
        ),
        tip_height: peer_1_actual_height,
        reward_cycle: rpc_test
            .peer_1
            .network
            .burnchain
            .block_height_to_reward_cycle(rpc_test.peer_1.network.burnchain_tip.block_height)
            .expect("FATAL: burnchain tip before system start"),
    };

    // Initialize the downloader state for peer_2 (the node)
    let epoch = rpc_test
        .peer_1
        .network
        .get_epoch_by_epoch_id(StacksEpochId::Epoch30);
    let mut downloader = NakamotoDownloadStateMachine::new(
        epoch.start_height,
        rpc_test.peer_1.network.stacks_tip.block_id(), // Initial tip for the downloader state machine
    );
    match nakamoto_download_state {
        NakamotoDownloadState::Confirmed => {
            let mut confirmed_tenure = NakamotoTenureDownloader::new(
                peer_1_tenure_tip.consensus_hash.clone(),
                peer_1_tenure_tip.consensus_hash.clone(),
                peer_1_tenure_tip.parent_tenure_start_block_id.clone(),
                peer_1_tenure_tip.consensus_hash.clone(),
                peer_1_tenure_tip.tip_block_id.clone(),
                peer_1_address.clone(),
                RewardSet::empty(),
                RewardSet::empty(),
                false,
            );

            let mut header = NakamotoBlockHeader::empty();
            header.chain_length = peer_1_actual_height - 1;
            header.consensus_hash = peer_1_tenure_tip.consensus_hash.clone();
            header.parent_block_id = peer_1_tenure_tip.parent_tenure_start_block_id.clone();
            let nakamoto_block = NakamotoBlock {
                header,
                txs: vec![],
            };
            confirmed_tenure.tenure_end_block = Some(nakamoto_block);
            downloader
                .tenure_downloads
                .downloaders
                .push(Some(confirmed_tenure)); // Add peer_1's state to peer_2's downloader
            downloader.state = NakamotoDownloadState::Confirmed;
        }
        NakamotoDownloadState::Unconfirmed => {
            let mut unconfirmed_tenure = NakamotoUnconfirmedTenureDownloader::new(
                peer_1_address.clone(),
                Some(peer_1_tenure_tip.tip_block_id.clone()),
            );
            unconfirmed_tenure.tenure_tip = Some(peer_1_tenure_tip);
            downloader
                .unconfirmed_tenure_downloads
                .insert(peer_1_address, unconfirmed_tenure); // Add peer_1's state to peer_2's downloader
            downloader.state = NakamotoDownloadState::Unconfirmed;
        }
    }
    rpc_test.peer_2.network.block_downloader_nakamoto = Some(downloader);

    // --- Invoke the Handler ---
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let request = StacksHttpRequest::new_gethealth(addr.into(), NeighborsScope::Initial);
    let mut responses = rpc_test.run(vec![request]);
    let response = responses.remove(0);

    // --- Assertions ---
    let (http_resp_preamble, contents) = response.destruct();
    assert_eq!(
        http_resp_preamble.status_code, 200,
        "Expected HTTP 200 OK for test case: {}",
        test_function_name_suffix
    );

    let response_json_val: serde_json::Value = contents.try_into().unwrap_or_else(|e| {
        panic!(
            "Failed to parse JSON for test case {}: {}",
            test_function_name_suffix, e
        )
    });
    let health_response: RPCGetHealthResponse = serde_json::from_value(response_json_val)
        .unwrap_or_else(|e| {
            panic!(
                "Failed to deserialize RPCGetHealthResponse for test case {}: {}",
                test_function_name_suffix, e
            )
        });

    assert_eq!(
        health_response.node_stacks_tip_height, node_stacks_tip_height,
        "Mismatch in node_stacks_tip_height for test case: {}",
        test_function_name_suffix
    );
    // In these scenarios, peer_1 is the only peer configured with stats in the downloader.
    assert_eq!(
        health_response.max_stacks_height_of_neighbors, peer_1_actual_height,
        "Mismatch in max_stacks_height_of_neighbors for test case: {}",
        test_function_name_suffix
    );
    assert_eq!(
        health_response.difference_from_max_peer, expected_difference_from_max_peer,
        "Mismatch in difference_from_max_peer for test case: {}",
        test_function_name_suffix
    );
}

#[test]
fn test_get_health_node_behind_of_peers_unconfirmed() {
    // This test simulates peer_2 (node) being behind peer_1.
    // So, peer_1's height is greater than peer_2's height.
    setup_and_run_nakamoto_health_test(
        "node_behind",
        100, // peer_1 is 100 blocks *ahead* of the node (node's height + 100)
        100, // Expected difference: node is 100 blocks behind max peer height
        NakamotoDownloadState::Unconfirmed,
    );
}

#[test]
fn test_get_health_same_height_as_peers_unconfirmed() {
    // Test when node is at the same height as its most advanced peer (peer_1)
    setup_and_run_nakamoto_health_test(
        "same_height",
        0, // peer_1 is at the same height as the node (node's height + 0)
        0, // Expected difference: node is at the same height as max peer
        NakamotoDownloadState::Unconfirmed,
    );
}

#[test]
fn test_get_health_node_ahead_of_peers_unconfirmed() {
    // Test when node (peer_2) is ahead of its peer (peer_1)
    // So, peer_1's height is less than peer_2's height.
    setup_and_run_nakamoto_health_test(
        "node_ahead",
        -10, // peer_1 is 10 blocks *behind* the node (node's height - 10)
        0, // Expected difference: 0, because difference is node_height.saturating_sub(peer_height)
        // when the node is ahead, this results in 0 if peer_height < node_height.
        NakamotoDownloadState::Unconfirmed,
    );
}

#[test]
fn test_get_health_node_behind_of_peers_confirmed() {
    // Test when node (peer_2) is behind its peer (peer_1)
    // So, peer_1's height is greater than peer_2's height.
    setup_and_run_nakamoto_health_test(
        "node_behind",
        100, // peer_1 is 100 blocks *ahead* of the node (node's height + 100)
        100, // Expected difference: node is 100 blocks behind max peer height
        NakamotoDownloadState::Confirmed,
    );
}

#[test]
fn test_get_health_same_height_as_peers_confirmed() {
    // Test when node (peer_2) is at the same height as its peer (peer_1)
    // So, peer_1's height is equal to peer_2's height.
    setup_and_run_nakamoto_health_test(
        "same_height",
        0, // peer_1 is at the same height as the node (node's height + 0)
        0, // Expected difference: node is at the same height as max peer
        NakamotoDownloadState::Confirmed,
    );
}

#[test]
fn test_get_health_node_ahead_of_peers_confirmed() {
    // Test when node (peer_2) is ahead of its peer (peer_1)
    // So, peer_1's height is less than peer_2's height.
    setup_and_run_nakamoto_health_test(
        "node_ahead",
        -10, // peer_1 is 10 blocks *behind* the node (node's height - 10)
        0, // Expected difference: 0, because difference is node_height.saturating_sub(peer_height)
        // when the node is ahead, this results in 0 if peer_height < node_height.
        NakamotoDownloadState::Confirmed,
    );
}

#[test]
fn test_get_health_400_invalid_neighbors_param() {
    let test_observer = TestEventObserver::new();
    let rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);
    let request = StacksHttpRequest::new_for_peer(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333).into(),
        "GET".into(),
        "/v3/health".into(),
        HttpRequestContents::new().query_string(Some("neighbors=invalid")),
    )
    .expect("FATAL: failed to construct request from infallible data");

    let mut responses = rpc_test.run(vec![request]);
    let response = responses.remove(0);

    let (http_resp_preamble, contents) = response.destruct();
    let error_message: String = contents.try_into().unwrap();
    assert_eq!(
        error_message,
        "Invalid `neighbors` query parameter: `invalid`, allowed values are `initial` or `all`"
    );
    assert_eq!(
        http_resp_preamble.status_code, 400,
        "Expected HTTP 400 Bad Request for invalid neighbors parameter"
    );
}

#[test]
fn test_get_health_500_no_initial_neighbors() {
    // Test error handling when no initial neighbors are found
    let test_observer = TestEventObserver::new();
    let mut rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);
    rpc_test.peer_2.refresh_burnchain_view();
    rpc_test.peer_2.network.init_nakamoto_block_downloader();

    // Mock the PeerDB::get_valid_initial_neighbors to return empty vec by
    // clearing all peers from the peer DB
    rpc_test
        .peer_2
        .network
        .peerdb
        .conn()
        .execute("DELETE FROM frontier", [])
        .unwrap();

    // --- Invoke the Handler ---
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let request = StacksHttpRequest::new_gethealth(addr.into(), NeighborsScope::Initial);
    let mut responses = rpc_test.run(vec![request]);
    let response = responses.remove(0);

    // --- Assertions ---
    let (http_resp_preamble, contents) = response.destruct();
    assert_eq!(
        http_resp_preamble.status_code, 500,
        "Expected HTTP 500 Internal Server Error"
    );
    let error_message: String = contents
        .try_into()
        .expect("Failed to parse JSON from HttpResponseContents");
    assert_eq!(
        error_message,
        "No viable bootstrap peers found, unable to determine health"
    );
}

#[test]
fn test_get_health_500_no_inv_state_pre_nakamoto() {
    // Test when inv_state is None in pre-Nakamoto epochs
    let test_observer = TestEventObserver::new();
    let mut rpc_test = TestRPC::setup(function_name!());

    // Reset inv_state to None
    rpc_test.peer_2.network.inv_state = None;

    // --- Invoke the Handler ---
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let request = StacksHttpRequest::new_gethealth(addr.into(), NeighborsScope::Initial);
    let mut responses = rpc_test.run(vec![request]);
    let response = responses.remove(0);

    // --- Assertions ---
    let (http_resp_preamble, contents) = response.destruct();
    assert_eq!(
        http_resp_preamble.status_code, 500,
        "Expected HTTP 500 Internal Server Error"
    );
    let error_message: String = contents
        .try_into()
        .expect("Failed to parse JSON from HttpResponseContents");
    assert_eq!(
        error_message,
        "Peer inventory state (Epoch 2.x) not found, unable to determine health."
    );
}

#[test]
fn test_get_health_500_no_download_state() {
    let test_observer = TestEventObserver::new();
    // by default, setup_nakamoto doesn't intialize the network.block_downloader_nakamoto
    let rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);
    // --- Invoke the Handler ---
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let request = StacksHttpRequest::new_gethealth(addr.into(), NeighborsScope::Initial);
    let mut responses = rpc_test.run(vec![request]);
    let response = responses.remove(0);
    // --- Assertions ---
    let (http_resp_preamble, contents) = response.destruct();
    assert_eq!(
        http_resp_preamble.status_code, 500,
        "Expected HTTP 500 Internal Server Error"
    );
    let error_message: String = contents
        .try_into()
        .expect("Failed to parse JSON from HttpResponseContents");
    assert_eq!(
        error_message,
        "Nakamoto block downloader not found (Epoch 3.0+), unable to determine health."
    );
}

#[test]
fn test_get_health_500_no_peers_stats() {
    let test_observer = TestEventObserver::new();
    let mut rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);
    rpc_test.peer_2.network.init_nakamoto_block_downloader();
    // --- Invoke the Handler ---
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let request = StacksHttpRequest::new_gethealth(addr.into(), NeighborsScope::Initial);
    let mut responses = rpc_test.run(vec![request]);
    let response = responses.remove(0);
    // --- Assertions ---
    let (http_resp_preamble, contents) = response.destruct();
    assert_eq!(
        http_resp_preamble.status_code, 500,
        "Expected HTTP 500 Internal Server Error"
    );
    let error_message: String = contents
        .try_into()
        .expect("Failed to parse JSON from HttpResponseContents");
    assert_eq!(
        error_message,
        "Couldn't obtain stats on any bootstrap peers, unable to determine health."
    );
}
