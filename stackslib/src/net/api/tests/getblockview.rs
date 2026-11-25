// Copyright (C) 2026 Stacks Open Internet Foundation
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

use stacks_common::types::chainstate::{StacksBlockId, StacksPrivateKey};

use super::TestRPC;
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::core::test_util::{make_stacks_transfer_tx, to_addr};
use crate::core::CHAIN_ID_TESTNET;
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{RPCRequestHandler, StacksHttp, StacksHttpRequest};
use crate::net::test::TestEventObserver;
use crate::net::tests::{NakamotoBootStep, NakamotoBootTenure};
use crate::net::ProtocolFamily;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr, &ConnectionOptions::default());

    let block_id = StacksBlockId([0x11; 32]);
    let request = StacksHttpRequest::new_get_block_view(addr.into(), &block_id);
    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getblockview::GetBlockViewRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    parsed_request.clear_headers();
    let (preamble, _contents) = parsed_request.destruct();

    assert_eq!(handler.block_id, Some(block_id));
    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.block_id.is_none());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();
    let rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);
    let canonical_tip = rpc_test.canonical_tip.clone();
    let consensus_hash = rpc_test.consensus_hash.clone();

    let mut requests = vec![];

    // A block the node has.
    requests.push(StacksHttpRequest::new_get_block_view(
        addr.into(),
        &canonical_tip,
    ));

    // A block the node has never seen.
    requests.push(StacksHttpRequest::new_get_block_view(
        addr.into(),
        &StacksBlockId([0x22; 32]),
    ));

    let mut responses = rpc_test.run(requests);

    let view = responses.remove(0).decode_block_view().unwrap();
    assert_eq!(view.consensus_hash, consensus_hash);
    // Nothing has forked away beneath the canonical tip, so both of its views stand. The burn
    // view is what the whole endpoint exists to report, so it has to be present rather than
    // merely canonical-by-default.
    assert!(view.consensus_hash_canonical);
    assert!(view.burn_view.is_some());
    assert!(view.burn_view_canonical);

    let (preamble, _body) = responses.remove(0).destruct();
    assert_eq!(preamble.status_code, 404);
}

/// A block whose tenure and burn view a burnchain fork has orphaned is reported as such. Signers
/// read these `false` answers as proof the block is dead and release a signature on them, so
/// this is the answer that has to be right.
#[test]
fn test_try_make_response_orphaned() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();
    let mut rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);
    let canonical_tip = rpc_test.canonical_tip.clone();
    let consensus_hash = rpc_test.consensus_hash.clone();

    rpc_test.orphan_sortition(&consensus_hash);

    let request = StacksHttpRequest::new_get_block_view(addr.into(), &canonical_tip);
    let view = rpc_test.run_one(request).decode_block_view().unwrap();
    // The block is still in chainstate, so it is still answered for, but both views it hangs
    // from are now off the canonical fork.
    assert_eq!(view.consensus_hash, consensus_hash);
    assert!(!view.consensus_hash_canonical);
    assert!(view.burn_view.is_some());
    assert!(!view.burn_view_canonical);
}

/// The two flags answer different questions and must not be conflated. A tenure extended across
/// a later burn block keeps its own sortition but picks up that later burn block as its burn
/// view, and a burnchain fork can orphan the burn view alone. That is the case where a signer
/// releases a sibling signature on `burn_view_canonical`, so reporting the tenure's fate in its
/// place would either hold a dead block or release a live one.
#[test]
fn test_try_make_response_burn_view_orphaned_tenure_survives() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();
    let mut rpc_test =
        TestRPC::setup_nakamoto_with_boot_plan(function_name!(), &test_observer, |boot_plan| {
            let private_key = StacksPrivateKey::from_seed("getblockview".as_bytes());
            let transfer = make_stacks_transfer_tx(
                &private_key,
                0,
                1000,
                CHAIN_ID_TESTNET,
                &to_addr(&StacksPrivateKey::random()).into(),
                1,
            );
            // Extend the last tenure across an empty sortition, so the tip block's burn view
            // is a later burn block than the sortition that elected its miner.
            boot_plan
                .with_boot_tenures(vec![NakamotoBootTenure::NoSortition(vec![
                    NakamotoBootStep::Block(vec![transfer]),
                ])])
                .with_initial_balances(vec![(to_addr(&private_key).into(), 1_000_000)])
        });
    let canonical_tip = rpc_test.canonical_tip.clone();
    let consensus_hash = rpc_test.consensus_hash.clone();
    let burn_view =
        NakamotoChainState::get_block_header(rpc_test.peer_2.chainstate_ref().db(), &canonical_tip)
            .unwrap()
            .unwrap()
            .burn_view
            .expect("a Nakamoto block has a burn view");
    assert_ne!(
        burn_view, consensus_hash,
        "the tip has to be in an extended tenure for the two views to differ"
    );

    // Fork off the tenure's own sortition, so it survives and only the burn view is orphaned.
    rpc_test.orphan_sortition(&burn_view);

    let request = StacksHttpRequest::new_get_block_view(addr.into(), &canonical_tip);
    let view = rpc_test.run_one(request).decode_block_view().unwrap();
    assert_eq!(view.consensus_hash, consensus_hash);
    assert!(view.consensus_hash_canonical);
    assert_eq!(view.burn_view, Some(burn_view));
    assert!(!view.burn_view_canonical);
}
