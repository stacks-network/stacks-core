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

use std::collections::VecDeque;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex};

use clarity::codec::StacksMessageCodec;
use clarity::consts::CHAIN_ID_TESTNET;
use clarity::types::chainstate::{BlockHeaderHash, StacksBlockId, StacksPrivateKey};
use clarity::vm::ast::ASTRules;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::StandardPrincipalData;
use postblock_proposal::{NakamotoBlockProposal, ValidateRejectCode};
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::types::StacksEpochId;

use super::TestRPC;
use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::miner::NakamotoBlockBuilder;
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::miner::{BlockBuilder, BlockLimitFunction};
use crate::chainstate::stacks::test::make_codec_test_nakamoto_block;
use crate::chainstate::stacks::{StacksMicroblock, StacksTransaction};
use crate::core::mempool::{MemPoolDropReason, MemPoolEventDispatcher, ProposalCallbackReceiver};
use crate::core::test_util::{
    make_big_read_count_contract, make_contract_call, make_contract_publish,
    make_stacks_transfer_tx, to_addr,
};
use crate::core::{MemPoolDB, BLOCK_LIMIT_MAINNET_21};
use crate::net::api::postblock_proposal::{
    BlockValidateOk, BlockValidateReject, TEST_REPLAY_TRANSACTIONS,
};
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::http::HttpRequestContents;
use crate::net::httpcore::{RPCRequestHandler, StacksHttp, StacksHttpRequest};
use crate::net::relay::Relayer;
use crate::net::test::{TestEventObserver, TestPeer};
use crate::net::ProtocolFamily;

#[warn(unused)]
#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr, &ConnectionOptions::default());

    let block = make_codec_test_nakamoto_block(StacksEpochId::Epoch30, &StacksPrivateKey::random());
    let proposal = NakamotoBlockProposal {
        block: block.clone(),
        chain_id: 0x80000000,
        replay_txs: None,
    };
    let mut request = StacksHttpRequest::new_for_peer(
        addr.into(),
        "POST".into(),
        "/v3/block_proposal".into(),
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
            chain_id: 0x80000000,
            replay_txs: None,
        })
    );

    // parsed request consumes headers that would not be in a constructed request
    parsed_request.clear_headers();
    // but the authorization header should still be there
    parsed_request.add_header("authorization".into(), "password".into());
    let (preamble, _contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.auth.is_some());
    assert!(handler.block_proposal.is_none());
}

struct ProposalObserver {
    results: Mutex<
        Vec<Result<postblock_proposal::BlockValidateOk, postblock_proposal::BlockValidateReject>>,
    >,
    condvar: Condvar,
}

impl ProposalObserver {
    fn new() -> Self {
        Self {
            results: Mutex::new(vec![]),
            condvar: Condvar::new(),
        }
    }
}

impl ProposalCallbackReceiver for ProposalObserver {
    fn notify_proposal_result(
        &self,
        result: Result<
            postblock_proposal::BlockValidateOk,
            postblock_proposal::BlockValidateReject,
        >,
    ) {
        let mut results = self.results.lock().unwrap();
        results.push(result);
        self.condvar.notify_one();
    }
}

struct ProposalTestObserver {
    pub proposal_observer: Arc<Mutex<ProposalObserver>>,
}

impl ProposalTestObserver {
    fn new() -> Self {
        Self {
            proposal_observer: Arc::new(Mutex::new(ProposalObserver::new())),
        }
    }
}

impl ProposalCallbackReceiver for Arc<Mutex<ProposalObserver>> {
    fn notify_proposal_result(
        &self,
        result: Result<
            postblock_proposal::BlockValidateOk,
            postblock_proposal::BlockValidateReject,
        >,
    ) {
        let observer = self.lock().unwrap();
        observer.notify_proposal_result(result);
    }
}

impl MemPoolEventDispatcher for ProposalTestObserver {
    fn get_proposal_callback_receiver(&self) -> Option<Box<dyn ProposalCallbackReceiver>> {
        Some(Box::new(Arc::clone(&self.proposal_observer)))
    }

    fn mempool_txs_dropped(
        &self,
        txids: Vec<Txid>,
        new_txid: Option<Txid>,
        reason: MemPoolDropReason,
    ) {
    }

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

#[test]
#[ignore]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let test_observer = TestEventObserver::new();
    let mut rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);
    let mut requests = vec![];

    let tip =
        SortitionDB::get_canonical_burn_chain_tip(rpc_test.peer_1.sortdb.as_ref().unwrap().conn())
            .unwrap();

    let (stacks_tip_ch, stacks_tip_bhh) = SortitionDB::get_canonical_stacks_chain_tip_hash(
        rpc_test.peer_1.sortdb.as_ref().unwrap().conn(),
    )
    .unwrap();
    let stacks_tip = StacksBlockId::new(&stacks_tip_ch, &stacks_tip_bhh);

    let miner_privk = &rpc_test.peer_1.miner.nakamoto_miner_key();

    let mut good_block = {
        let chainstate = rpc_test.peer_1.chainstate();
        let parent_stacks_header =
            NakamotoChainState::get_block_header(chainstate.db(), &stacks_tip)
                .unwrap()
                .unwrap();

        let tx = make_stacks_transfer_tx(
            miner_privk,
            36,
            300,
            CHAIN_ID_TESTNET,
            &StandardPrincipalData::transient().into(),
            123,
        );

        let mut builder = NakamotoBlockBuilder::new(
            &parent_stacks_header,
            &parent_stacks_header.consensus_hash,
            26000,
            None,
            None,
            8,
            None,
            None,
        )
        .unwrap();

        rpc_test
            .peer_1
            .with_db_state(
                |sort_db: &mut SortitionDB,
                 chainstate: &mut StacksChainState,
                 _: &mut Relayer,
                 _: &mut MemPoolDB| {
                    let burn_dbconn = sort_db.index_handle_at_tip();
                    let mut miner_tenure_info = builder
                        .load_tenure_info(chainstate, &burn_dbconn, None)
                        .unwrap();
                    let burn_chain_height = miner_tenure_info.burn_tip_height;
                    let mut tenure_tx = builder
                        .tenure_begin(&burn_dbconn, &mut miner_tenure_info)
                        .unwrap();
                    builder.try_mine_tx_with_len(
                        &mut tenure_tx,
                        &tx,
                        tx.tx_len(),
                        &BlockLimitFunction::NO_LIMIT_HIT,
                        ASTRules::PrecheckSize,
                        None,
                    );
                    let block = builder.mine_nakamoto_block(&mut tenure_tx, burn_chain_height);
                    Ok(block)
                },
            )
            .unwrap()
    };

    // Increment the timestamp by 1 to ensure it is different from the previous block
    good_block.header.timestamp += 1;
    rpc_test.peer_1.miner.sign_nakamoto_block(&mut good_block);

    // post the valid block proposal
    let proposal = NakamotoBlockProposal {
        block: good_block.clone(),
        chain_id: 0x80000000,
        replay_txs: None,
    };

    let mut request = StacksHttpRequest::new_for_peer(
        rpc_test.peer_1.to_peer_host(),
        "POST".into(),
        "/v3/block_proposal".into(),
        HttpRequestContents::new().payload_json(serde_json::to_value(proposal).unwrap()),
    )
    .expect("failed to construct request");
    request.add_header("authorization".into(), "password".into());
    requests.push(request);

    // Set the timestamp to a value in the past (but NOT BEFORE timeout)
    let mut early_time_block = good_block.clone();
    early_time_block.header.timestamp -= 400;
    rpc_test
        .peer_1
        .miner
        .sign_nakamoto_block(&mut early_time_block);

    // post the invalid block proposal
    let proposal = NakamotoBlockProposal {
        block: early_time_block,
        chain_id: 0x80000000,
        replay_txs: None,
    };

    let mut request = StacksHttpRequest::new_for_peer(
        rpc_test.peer_1.to_peer_host(),
        "POST".into(),
        "/v3/block_proposal".into(),
        HttpRequestContents::new().payload_json(serde_json::to_value(proposal).unwrap()),
    )
    .expect("failed to construct request");
    request.add_header("authorization".into(), "password".into());
    requests.push(request);

    // Set the timestamp to a value in the future
    let mut late_time_block = good_block.clone();
    late_time_block.header.timestamp += 20000;
    rpc_test
        .peer_1
        .miner
        .sign_nakamoto_block(&mut late_time_block);

    // post the invalid block proposal
    let proposal = NakamotoBlockProposal {
        block: late_time_block,
        chain_id: 0x80000000,
        replay_txs: None,
    };

    let mut request = StacksHttpRequest::new_for_peer(
        rpc_test.peer_1.to_peer_host(),
        "POST".into(),
        "/v3/block_proposal".into(),
        HttpRequestContents::new().payload_json(serde_json::to_value(proposal).unwrap()),
    )
    .expect("failed to construct request");
    request.add_header("authorization".into(), "password".into());
    requests.push(request);

    // Set the timestamp to a value in the past (BEFORE the timeout)
    let mut stale_block = good_block.clone();
    stale_block.header.timestamp -= 10000;
    rpc_test.peer_1.miner.sign_nakamoto_block(&mut stale_block);

    // post the invalid block proposal
    let proposal = NakamotoBlockProposal {
        block: stale_block,
        chain_id: 0x80000000,
        replay_txs: None,
    };

    let mut request = StacksHttpRequest::new_for_peer(
        rpc_test.peer_1.to_peer_host(),
        "POST".into(),
        "/v3/block_proposal".into(),
        HttpRequestContents::new().payload_json(serde_json::to_value(proposal).unwrap()),
    )
    .expect("failed to construct request");
    request.add_header("authorization".into(), "password".into());
    requests.push(request);

    // execute the requests
    let observer = ProposalTestObserver::new();
    let proposal_observer = Arc::clone(&observer.proposal_observer);

    info!("Run requests with observer");
    let wait_for = |peer_1: &mut TestPeer, peer_2: &mut TestPeer| {
        !peer_1.network.is_proposal_thread_running() && !peer_2.network.is_proposal_thread_running()
    };

    let responses = rpc_test.run_with_observer(requests, Some(&observer), wait_for);

    for response in responses.iter().take(3) {
        assert_eq!(response.preamble().status_code, 202);
    }
    let response = &responses[3];
    assert_eq!(response.preamble().status_code, 422);

    // Wait for the results of all 3 PROCESSED requests
    let start = std::time::Instant::now();
    loop {
        info!("Wait for results to be non-empty");
        if proposal_observer
            .lock()
            .unwrap()
            .results
            .lock()
            .unwrap()
            .len()
            < 3
        {
            std::thread::sleep(std::time::Duration::from_secs(1));
        } else {
            break;
        }
        assert!(
            start.elapsed().as_secs() < 60,
            "Timed out waiting for results"
        );
    }

    let observer = proposal_observer.lock().unwrap();
    let mut results = observer.results.lock().unwrap();

    let result = results.remove(0);
    match result {
        Ok(postblock_proposal::BlockValidateOk {
            signer_signature_hash,
            cost,
            size,
            validation_time_ms,
            replay_tx_hash,
            replay_tx_exhausted,
        }) => {
            assert_eq!(
                signer_signature_hash,
                good_block.header.signer_signature_hash()
            );
            assert_eq!(cost, ExecutionCost::ZERO);
            assert_eq!(size, 180);
            assert!(validation_time_ms > 0 && validation_time_ms < 60000);
            assert!(replay_tx_hash.is_none());
            assert!(!replay_tx_exhausted);
        }
        _ => panic!("expected ok"),
    }

    let result = results.remove(0);
    match result {
        Ok(_) => panic!("expected error"),
        Err(postblock_proposal::BlockValidateReject {
            reason_code,
            reason,
            ..
        }) => {
            assert_eq!(reason_code, ValidateRejectCode::InvalidTimestamp);
            assert_eq!(reason, "Block timestamp is not greater than parent block");
        }
    }

    let result = results.remove(0);
    match result {
        Ok(_) => panic!("expected error"),
        Err(postblock_proposal::BlockValidateReject {
            reason_code,
            reason,
            ..
        }) => {
            assert_eq!(reason_code, ValidateRejectCode::InvalidTimestamp);
            assert_eq!(reason, "Block timestamp is too far into the future");
        }
    }
}

#[warn(unused)]
fn replay_validation_test(
    setup_fn: impl FnOnce(&mut TestRPC) -> (VecDeque<StacksTransaction>, Vec<StacksTransaction>),
) -> Result<BlockValidateOk, BlockValidateReject> {
    let test_observer = TestEventObserver::new();
    let mut rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

    let (expected_replay_txs, block_txs) = setup_fn(&mut rpc_test);

    let mut requests = vec![];

    let (stacks_tip_ch, stacks_tip_bhh) = SortitionDB::get_canonical_stacks_chain_tip_hash(
        rpc_test.peer_1.sortdb.as_ref().unwrap().conn(),
    )
    .unwrap();
    let stacks_tip = StacksBlockId::new(&stacks_tip_ch, &stacks_tip_bhh);

    let mut proposed_block = {
        let chainstate = rpc_test.peer_1.chainstate();
        let parent_stacks_header =
            NakamotoChainState::get_block_header(chainstate.db(), &stacks_tip)
                .unwrap()
                .unwrap();

        let mut builder = NakamotoBlockBuilder::new(
            &parent_stacks_header,
            &parent_stacks_header.consensus_hash,
            26000,
            None,
            None,
            8,
            None,
            None,
        )
        .unwrap();

        rpc_test
            .peer_1
            .with_db_state(
                |sort_db: &mut SortitionDB,
                 chainstate: &mut StacksChainState,
                 _: &mut Relayer,
                 _: &mut MemPoolDB| {
                    let burn_dbconn = sort_db.index_handle_at_tip();
                    let mut miner_tenure_info = builder
                        .load_tenure_info(chainstate, &burn_dbconn, None)
                        .unwrap();
                    let burn_chain_height = miner_tenure_info.burn_tip_height;
                    let mut tenure_tx = builder
                        .tenure_begin(&burn_dbconn, &mut miner_tenure_info)
                        .unwrap();
                    for tx in block_txs {
                        builder.try_mine_tx_with_len(
                            &mut tenure_tx,
                            &tx,
                            tx.tx_len(),
                            &BlockLimitFunction::NO_LIMIT_HIT,
                            ASTRules::PrecheckSize,
                            None,
                        );
                    }
                    let block = builder.mine_nakamoto_block(&mut tenure_tx, burn_chain_height);
                    Ok(block)
                },
            )
            .unwrap()
    };

    // Increment the timestamp by 1 to ensure it is different from the previous block
    proposed_block.header.timestamp += 1;
    rpc_test
        .peer_1
        .miner
        .sign_nakamoto_block(&mut proposed_block);

    let proposal = NakamotoBlockProposal {
        block: proposed_block.clone(),
        chain_id: 0x80000000,
        replay_txs: Some(expected_replay_txs.into()),
    };

    let mut request = StacksHttpRequest::new_for_peer(
        rpc_test.peer_1.to_peer_host(),
        "POST".into(),
        "/v3/block_proposal".into(),
        HttpRequestContents::new().payload_json(serde_json::to_value(proposal).unwrap()),
    )
    .expect("failed to construct request");
    request.add_header("authorization".into(), "password".into());
    requests.push(request);

    // Execute the request
    let observer = ProposalTestObserver::new();
    let proposal_observer = Arc::clone(&observer.proposal_observer);

    let wait_for = |peer_1: &mut TestPeer, peer_2: &mut TestPeer| {
        !peer_1.network.is_proposal_thread_running() && !peer_2.network.is_proposal_thread_running()
    };

    info!("Run request with observer for validation with replay set test");
    let responses = rpc_test.run_with_observer(requests, Some(&observer), wait_for);

    // Expect 202 Accepted initially
    assert_eq!(responses[0].preamble().status_code, 202);

    // Wait for the asynchronous validation result
    let start = std::time::Instant::now();
    loop {
        info!("Wait for validation result to be non-empty");
        if proposal_observer
            .lock()
            .unwrap()
            .results
            .lock()
            .unwrap()
            .len()
            >= 1
        // Expecting one result
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(
            start.elapsed().as_secs() < 60,
            "Timed out waiting for validation result"
        );
    }

    let observer_locked = proposal_observer.lock().unwrap();
    let mut results = observer_locked.results.lock().unwrap();
    let result = results.pop().unwrap();

    TEST_REPLAY_TRANSACTIONS.set(Default::default());

    result
}

#[test]
#[ignore]
/// Tx replay test with mismatching mineable transactions.
fn replay_validation_test_transaction_mismatch() {
    let result = replay_validation_test(|rpc_test| {
        let miner_privk = &rpc_test.peer_1.miner.nakamoto_miner_key();
        // Transaction expected in the replay set (different amount)
        let tx_for_replay = make_stacks_transfer_tx(
            miner_privk,
            36,
            300,
            CHAIN_ID_TESTNET,
            &StandardPrincipalData::transient().into(),
            1234,
        );

        let tx = make_stacks_transfer_tx(
            miner_privk,
            36,
            300,
            CHAIN_ID_TESTNET,
            &StandardPrincipalData::transient().into(),
            123,
        );

        (vec![tx_for_replay].into(), vec![tx])
    });

    match result {
        Ok(_) => panic!("Expected error due to replay transaction mismatch, but got Ok"),
        Err(postblock_proposal::BlockValidateReject { reason_code, .. }) => {
            assert_eq!(
                reason_code,
                ValidateRejectCode::InvalidTransactionReplay,
                "Expected InvalidTransactionReplay reason code"
            );
        }
    }
}

#[test]
#[ignore]
/// Replay set has one unmineable tx, and one mineable tx.
/// The block has the one mineable tx.
fn replay_validation_test_transaction_unmineable_match() {
    let result = replay_validation_test(|rpc_test| {
        let miner_privk = &rpc_test.peer_1.miner.nakamoto_miner_key();
        // Transaction expected in the replay set (different amount)
        let unmineable_tx = make_stacks_transfer_tx(
            miner_privk,
            37,
            300,
            CHAIN_ID_TESTNET,
            &StandardPrincipalData::transient().into(),
            1234,
        );

        let mineable_tx = make_stacks_transfer_tx(
            miner_privk,
            36,
            300,
            CHAIN_ID_TESTNET,
            &StandardPrincipalData::transient().into(),
            123,
        );

        (
            vec![unmineable_tx, mineable_tx.clone()].into(),
            vec![mineable_tx],
        )
    });

    match result {
        Ok(_) => {}
        Err(rejection) => {
            panic!("Expected validation to be OK, but got {:?}", rejection);
        }
    }
}

#[test]
#[ignore]
/// Replay set has [mineable, unmineable, mineable]
/// The block has [mineable, mineable]
fn replay_validation_test_transaction_unmineable_match_2() {
    let mut replay_set = vec![];
    let result = replay_validation_test(|rpc_test| {
        let miner_privk = &rpc_test.peer_1.miner.nakamoto_miner_key();
        // Unmineable tx
        let unmineable_tx = make_stacks_transfer_tx(
            miner_privk,
            38,
            300,
            CHAIN_ID_TESTNET,
            &StandardPrincipalData::transient().into(),
            123,
        );

        let mineable_tx = make_stacks_transfer_tx(
            miner_privk,
            36,
            300,
            CHAIN_ID_TESTNET,
            &StandardPrincipalData::transient().into(),
            123,
        );

        let mineable_tx_2 = make_stacks_transfer_tx(
            miner_privk,
            37,
            300,
            CHAIN_ID_TESTNET,
            &StandardPrincipalData::transient().into(),
            123,
        );

        replay_set = vec![unmineable_tx, mineable_tx.clone(), mineable_tx_2.clone()];

        (replay_set.clone().into(), vec![mineable_tx, mineable_tx_2])
    });

    match result {
        Ok(block_validate_ok) => {
            let mut hasher = DefaultHasher::new();
            replay_set.hash(&mut hasher);
            let replay_hash = hasher.finish();

            assert_eq!(block_validate_ok.replay_tx_hash, Some(replay_hash));
            assert!(block_validate_ok.replay_tx_exhausted);
        }
        Err(rejection) => {
            panic!("Expected validation to be OK, but got {:?}", rejection);
        }
    }
}

#[test]
#[ignore]
/// Replay set has [mineable, mineable, tx_a, mineable]
/// The block has [mineable, mineable, tx_b, mineable]
fn replay_validation_test_transaction_mineable_mismatch_series() {
    let result = replay_validation_test(|rpc_test| {
        let miner_privk = &rpc_test.peer_1.miner.nakamoto_miner_key();
        // Mineable tx
        let mineable_tx_1 = make_stacks_transfer_tx(
            miner_privk,
            36,
            300,
            CHAIN_ID_TESTNET,
            &StandardPrincipalData::transient().into(),
            123,
        );

        let mineable_tx_2 = make_stacks_transfer_tx(
            miner_privk,
            37,
            300,
            CHAIN_ID_TESTNET,
            &StandardPrincipalData::transient().into(),
            123,
        );

        let tx_a = make_stacks_transfer_tx(
            miner_privk,
            38,
            300,
            CHAIN_ID_TESTNET,
            &StandardPrincipalData::transient().into(),
            123,
        );

        let tx_b = make_stacks_transfer_tx(
            miner_privk,
            38,
            300,
            CHAIN_ID_TESTNET,
            &StandardPrincipalData::transient().into(),
            1234, // different amount
        );

        let mineable_tx_3 = make_stacks_transfer_tx(
            miner_privk,
            39,
            300,
            CHAIN_ID_TESTNET,
            &StandardPrincipalData::transient().into(),
            123,
        );

        (
            vec![
                mineable_tx_1.clone(),
                mineable_tx_2.clone(),
                tx_a.clone(),
                mineable_tx_3.clone(),
            ]
            .into(),
            vec![mineable_tx_1, mineable_tx_2, tx_b, mineable_tx_3],
        )
    });

    match result {
        Ok(_) => {
            panic!("Expected validation to be rejected, but got Ok");
        }
        Err(rejection) => {
            assert_eq!(
                rejection.reason_code,
                ValidateRejectCode::InvalidTransactionReplay
            );
        }
    }
}

#[test]
#[ignore]
/// Replay set has [mineable, tx_b, tx_a]
/// The block has [mineable, tx_a, tx_b]
fn replay_validation_test_transaction_mineable_mismatch_series_2() {
    let result = replay_validation_test(|rpc_test| {
        let miner_privk = &rpc_test.peer_1.miner.nakamoto_miner_key();

        let recipient_sk = StacksPrivateKey::random();
        let recipient_addr = to_addr(&recipient_sk);
        let miner_addr = to_addr(miner_privk);

        let mineable_tx_1 = make_stacks_transfer_tx(
            miner_privk,
            36,
            300,
            CHAIN_ID_TESTNET,
            &recipient_addr.clone().into(),
            1000000,
        );

        let tx_b = make_stacks_transfer_tx(
            &recipient_sk,
            0,
            300,
            CHAIN_ID_TESTNET,
            &miner_addr.into(),
            123,
        );

        let tx_a = make_stacks_transfer_tx(
            miner_privk,
            37,
            300,
            CHAIN_ID_TESTNET,
            &recipient_addr.into(),
            123,
        );

        (
            vec![mineable_tx_1.clone(), tx_b.clone(), tx_a.clone()].into(),
            vec![mineable_tx_1, tx_a, tx_b],
        )
    });

    match result {
        Ok(_) => {
            panic!("Expected validation to be rejected, but got Ok");
        }
        Err(rejection) => {
            assert_eq!(
                rejection.reason_code,
                ValidateRejectCode::InvalidTransactionReplay
            );
        }
    }
}

#[test]
#[ignore]
/// Replay set has [deploy, big_a, big_b, c]
/// The block has [deploy, big_a, c]
///
/// The block should have ended at big_a, because big_b would
/// have cost too much to include.
fn replay_validation_test_budget_exceeded() {
    let result = replay_validation_test(|rpc_test| {
        let miner_privk = &rpc_test.peer_1.miner.nakamoto_miner_key();
        let miner_addr = to_addr(miner_privk);

        let contract_code = make_big_read_count_contract(BLOCK_LIMIT_MAINNET_21, 50);

        let deploy_tx_bytes = make_contract_publish(
            miner_privk,
            36,
            1000,
            CHAIN_ID_TESTNET,
            &"big-contract",
            &contract_code,
        );

        let big_a_bytes = make_contract_call(
            miner_privk,
            37,
            1000,
            CHAIN_ID_TESTNET,
            &miner_addr,
            &"big-contract",
            "big-tx",
            &vec![],
        );

        let big_b_bytes = make_contract_call(
            miner_privk,
            38,
            1000,
            CHAIN_ID_TESTNET,
            &miner_addr,
            &"big-contract",
            "big-tx",
            &vec![],
        );

        let deploy_tx =
            StacksTransaction::consensus_deserialize(&mut deploy_tx_bytes.as_slice()).unwrap();
        let big_a = StacksTransaction::consensus_deserialize(&mut big_a_bytes.as_slice()).unwrap();
        let big_b = StacksTransaction::consensus_deserialize(&mut big_b_bytes.as_slice()).unwrap();

        let transfer_tx = make_stacks_transfer_tx(
            miner_privk,
            38,
            1000,
            CHAIN_ID_TESTNET,
            &StandardPrincipalData::transient().into(),
            100,
        );

        (
            vec![deploy_tx.clone(), big_a.clone(), big_b.clone()].into(),
            vec![deploy_tx, big_a, transfer_tx],
        )
    });

    match result {
        Ok(_) => {
            panic!("Expected validation to be rejected, but got Ok");
        }
        Err(rejection) => {
            assert_eq!(
                rejection.reason_code,
                ValidateRejectCode::InvalidTransactionReplay
            );
        }
    }
}

#[test]
#[ignore]
/// Replay set has [deploy, big_a, big_b]
/// The block has [deploy, big_a]
///
/// The block is valid, but the replay set is _not_ exhausted.
fn replay_validation_test_budget_exhausted() {
    let mut replay_set = vec![];
    let result = replay_validation_test(|rpc_test| {
        let miner_privk = &rpc_test.peer_1.miner.nakamoto_miner_key();
        let miner_addr = to_addr(miner_privk);

        let contract_code = make_big_read_count_contract(BLOCK_LIMIT_MAINNET_21, 50);

        let deploy_tx_bytes = make_contract_publish(
            miner_privk,
            36,
            1000,
            CHAIN_ID_TESTNET,
            &"big-contract",
            &contract_code,
        );

        let big_a_bytes = make_contract_call(
            miner_privk,
            37,
            1000,
            CHAIN_ID_TESTNET,
            &miner_addr,
            &"big-contract",
            "big-tx",
            &vec![],
        );

        let big_b_bytes = make_contract_call(
            miner_privk,
            38,
            1000,
            CHAIN_ID_TESTNET,
            &miner_addr,
            &"big-contract",
            "big-tx",
            &vec![],
        );

        let deploy_tx =
            StacksTransaction::consensus_deserialize(&mut deploy_tx_bytes.as_slice()).unwrap();
        let big_a = StacksTransaction::consensus_deserialize(&mut big_a_bytes.as_slice()).unwrap();
        let big_b = StacksTransaction::consensus_deserialize(&mut big_b_bytes.as_slice()).unwrap();

        let transfer_tx = make_stacks_transfer_tx(
            miner_privk,
            38,
            1000,
            CHAIN_ID_TESTNET,
            &StandardPrincipalData::transient().into(),
            100,
        );

        replay_set = vec![deploy_tx.clone(), big_a.clone(), big_b.clone()];

        (replay_set.clone().into(), vec![deploy_tx, big_a])
    });

    match result {
        Ok(block_validate_ok) => {
            let mut hasher = DefaultHasher::new();
            replay_set.hash(&mut hasher);
            let replay_hash = hasher.finish();

            assert_eq!(block_validate_ok.replay_tx_hash, Some(replay_hash));
            assert!(!block_validate_ok.replay_tx_exhausted);
        }
        Err(rejection) => {
            panic!(
                "Expected validation to be rejected, but got {:?}",
                rejection
            );
        }
    }
}
