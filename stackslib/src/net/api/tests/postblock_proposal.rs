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

use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::{ClarityName, ContractName, Value};
use mempool::{MemPoolEventDispatcher, ProposalCallbackReceiver};
use postblock_proposal::NakamotoBlockProposal;
use stacks_common::types::chainstate::{ConsensusHash, StacksAddress};
use stacks_common::types::net::PeerHost;
use stacks_common::types::{Address, StacksEpochId};

use super::TestRPC;
use crate::chainstate::stacks::test::{make_codec_test_block, make_codec_test_nakamoto_block};
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
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let block = make_codec_test_nakamoto_block(3, StacksEpochId::Epoch30);
    let proposal = NakamotoBlockProposal {
        block: block.clone(),
        chain_id: 0x80000000,
    };
    let mut request = StacksHttpRequest::new_for_peer(
        addr.into(),
        "POST".into(),
        "/v2/block_proposal".into(),
        HttpRequestContents::new().payload_json(serde_json::to_value(proposal).unwrap()),
    )
    .expect("failed to construct request");
    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler =
        postblock_proposal::RPCBlockProposalRequestHandler::new(Some("password".into()));

    // missing authorization header
    let bad_request = http.handle_try_parse_request(
        &mut handler,
        &parsed_preamble.expect_request(),
        &bytes[offset..],
    );
    match bad_request {
        Err(crate::net::Error::Http(crate::net::http::Error::Http(err_code, message))) => {
            assert_eq!(err_code, 401);
            assert_eq!(message, "Unauthorized");
        }
        _ => panic!("expected error"),
    }

    // add the authorization header
    request.add_header("authorization".into(), "password".into());
    let bytes = request.try_serialize().unwrap();
    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    assert_eq!(
        handler.block_proposal,
        Some(NakamotoBlockProposal {
            block,
            chain_id: 0x80000000
        })
    );

    // parsed request consumes headers that would not be in a constructed request
    parsed_request.clear_headers();
    // but the authorization header should still be there
    parsed_request.add_header("authorization".into(), "password".into());
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.auth.is_some());
    assert!(handler.block_proposal.is_none());
}

struct NullObserver;
impl MemPoolEventDispatcher for NullObserver {
    fn get_proposal_callback_receiver(&self) -> Option<Box<dyn mempool::ProposalCallbackReceiver>> {
        Some(Box::new(NullObserver {}))
    }

    fn mempool_txs_dropped(&self, txids: Vec<Txid>, reason: mempool::MemPoolDropReason) {}

    fn mined_block_event(
        &self,
        target_burn_height: u64,
        block: &crate::chainstate::stacks::StacksBlock,
        block_size_bytes: u64,
        consumed: &ExecutionCost,
        confirmed_microblock_cost: &ExecutionCost,
        tx_results: Vec<crate::chainstate::stacks::miner::TransactionEvent>,
    ) {
    }

    fn mined_microblock_event(
        &self,
        microblock: &StacksMicroblock,
        tx_results: Vec<crate::chainstate::stacks::miner::TransactionEvent>,
        anchor_block_consensus_hash: ConsensusHash,
        anchor_block: BlockHeaderHash,
    ) {
    }

    fn mined_nakamoto_block_event(
        &self,
        target_burn_height: u64,
        block: &crate::chainstate::nakamoto::NakamotoBlock,
        block_size_bytes: u64,
        consumed: &ExecutionCost,
        tx_results: Vec<crate::chainstate::stacks::miner::TransactionEvent>,
    ) {
    }
}

impl ProposalCallbackReceiver for NullObserver {
    fn notify_proposal_result(
        &self,
        result: Result<
            postblock_proposal::BlockValidateOk,
            postblock_proposal::BlockValidateReject,
        >,
    ) {
    }
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let test_observer = TestEventObserver::new();
    let rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);
    let mut requests = vec![];

    let block = make_codec_test_nakamoto_block(3, StacksEpochId::Epoch30);

    // post the block proposal
    let proposal = NakamotoBlockProposal {
        block: block.clone(),
        chain_id: 0x80000000,
    };
    println!(
        "Peer1 host: {:?} {}",
        rpc_test.peer_1.to_peer_host(),
        rpc_test.peer_1.config.http_port
    );
    println!(
        "Peer2 host: {:?} {}",
        rpc_test.peer_2.to_peer_host(),
        rpc_test.peer_2.config.http_port
    );
    let mut request = StacksHttpRequest::new_for_peer(
        rpc_test.peer_1.to_peer_host(),
        "POST".into(),
        "/v2/block_proposal".into(),
        HttpRequestContents::new().payload_json(serde_json::to_value(proposal).unwrap()),
    )
    .expect("failed to construct request");
    request.add_header("authorization".into(), "password".into());
    requests.push(request);

    // // idempotent
    // let request =
    //     StacksHttpRequest::new_post_block(addr.into(), next_block.0.clone(), next_block.1.clone());
    // requests.push(request);

    // // fails if the consensus hash is not recognized
    // let request = StacksHttpRequest::new_post_block(
    //     addr.into(),
    //     ConsensusHash([0x11; 20]),
    //     next_block.1.clone(),
    // );
    // requests.push(request);

    let observer = NullObserver {};
    let mut responses = rpc_test.run_with_observer(requests, Some(&observer));

    let response = responses.remove(0);
    println!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    // let resp = response.decode_stacks_block_accepted().unwrap();
    // assert_eq!(resp.accepted, true);
    // assert_eq!(resp.stacks_block_id, stacks_block_id);

    // let response = responses.remove(0);
    // debug!(
    //     "Response:\n{}\n",
    //     std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    // );

    // let resp = response.decode_stacks_block_accepted().unwrap();
    // assert_eq!(resp.accepted, false);
    // assert_eq!(resp.stacks_block_id, stacks_block_id);

    // let response = responses.remove(0);
    // debug!(
    //     "Response:\n{}\n",
    //     std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    // );

    // let (preamble, body) = response.destruct();
    // assert_eq!(preamble.status_code, 404);
}
