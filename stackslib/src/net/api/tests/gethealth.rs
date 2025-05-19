use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clarity::types::chainstate::StacksBlockId;
use clarity::types::StacksEpochId;

use super::TestRPC;
use crate::net::api::gethealth::{RPCGetHealthRequestHandler, RPCGetHealthResponse};
use crate::net::api::gettenureinfo::RPCGetTenureInfo;
use crate::net::connection::ConnectionOptions;
use crate::net::download::nakamoto::{
    NakamotoDownloadStateMachine, NakamotoUnconfirmedTenureDownloader,
};
use crate::net::httpcore::{StacksHttp, StacksHttpRequest};
use crate::net::test::TestEventObserver;
use crate::net::{NeighborAddress, ProtocolFamily};

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

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

#[test]
fn test_get_health_happy_path() {
    // `rpc_test` will have peer_1 (client) and peer_2 (server)
    // peer_2 can be conceptually our "initial_neighbor".
    let test_observer = TestEventObserver::new();
    let mut rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);
    // Refresh the burnchain view to get the tip height
    rpc_test.peer_2.refresh_burnchain_view();
    let peer_2_height = rpc_test.peer_2.network.stacks_tip.height;
    let peer_1_height = peer_2_height + 100;

    let peer_1_address = NeighborAddress::from_neighbor(&rpc_test.peer_1.config.to_neighbor());

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
            &rpc_test.peer_1.network.stacks_tip.consensus_hash,
            &rpc_test.peer_1.network.stacks_tip.block_hash,
        ),
        tip_height: peer_1_height,
        reward_cycle: rpc_test
            .peer_1
            .network
            .burnchain
            .block_height_to_reward_cycle(rpc_test.peer_1.network.burnchain_tip.block_height)
            .expect("FATAL: burnchain tip before system start"),
    };

    let mut unconfirmed_tenure = NakamotoUnconfirmedTenureDownloader::new(
        peer_1_address.clone(),
        Some(peer_1_tenure_tip.tip_block_id.clone()),
    );
    unconfirmed_tenure.tenure_tip = Some(peer_1_tenure_tip);

    let epoch = rpc_test
        .peer_1
        .network
        .get_epoch_by_epoch_id(StacksEpochId::Epoch30);
    let mut downloader = NakamotoDownloadStateMachine::new(
        epoch.start_height,
        rpc_test.peer_1.network.stacks_tip.block_id(),
    );
    downloader
        .unconfirmed_tenure_downloads
        .insert(peer_1_address, unconfirmed_tenure);
    rpc_test.peer_2.network.block_downloader_nakamoto = Some(downloader);

    // --- Invoke the Handler ---
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let request = StacksHttpRequest::new_gethealth(addr.into());
    let mut responses = rpc_test.run(vec![request]);
    let response = responses.remove(0);

    // --- Assertions ---
    let (http_resp_preamble, contents) = response.destruct();
    assert_eq!(http_resp_preamble.status_code, 200, "Expected HTTP 200 OK");

    let response_json_val: serde_json::Value = contents
        .try_into()
        .expect("Failed to parse JSON from HttpResponseContents");
    let health_response: RPCGetHealthResponse = serde_json::from_value(response_json_val)
        .expect("Failed to deserialize into RPCGetHealthResponse");

    assert_eq!(health_response.node_stacks_tip_height, peer_2_height);
    assert_eq!(
        health_response.max_stacks_height_of_neighbors,
        peer_1_height
    );
    assert_eq!(health_response.difference_from_max_peer, 100);
}

#[test]
fn test_get_health_500_no_download_state() {
    let test_observer = TestEventObserver::new();
    // by default, setup_nakamoto doesn't intialize the network.block_downloader_nakamoto
    let rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);
    // --- Invoke the Handler ---
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let request = StacksHttpRequest::new_gethealth(addr.into());
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
    let request = StacksHttpRequest::new_gethealth(addr.into());
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
