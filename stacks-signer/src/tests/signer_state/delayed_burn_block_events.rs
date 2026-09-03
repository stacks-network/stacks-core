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

//! Regression tests for delayed and reordered burn-block events.
//!
//! These tests cover the relationship between the incoming event, the node's
//! canonical tip, and the signer's prior view. Confirmed-stale events must be
//! ignored without losing state, failed classifications must remain retryable,
//! and competing views must still reach fork handling. Shorter node tips retain
//! the pre-existing behavior pending a broader reconciliation policy.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use blockstack_lib::chainstate::stacks::db::StacksBlockHeaderTypes;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::core::test_util::make_stacks_transfer_tx;
use blockstack_lib::net::api::get_tenure_tip_meta::BlockHeaderWithMetadata;
use blockstack_lib::net::api::get_tenures_fork_info::TenureForkingInfo;
use blockstack_lib::net::api::getsortition::SortitionInfo;
use clarity::types::chainstate::{
    BurnchainHeaderHash, ConsensusHash, SortitionId, StacksAddress, StacksBlockId,
    StacksPrivateKey, TrieHash,
};
use clarity::util::hash::{Hash160, MerkleTree, Sha512Trunc256Sum};
use clarity::util::secp256k1::MessageSignature;
use libsigner::v0::signer_state::{
    GlobalStateEvaluator, MinerState, ReplayTransactionSet, SignerStateMachine,
};
use stacks_common::bitvec::BitVec;
use stacks_common::consts::CHAIN_ID_TESTNET;

use super::test_proposal_eval_config;
use crate::chainstate::{ProposalEvalConfig, SignerChainstateError};
use crate::client::tests::{
    build_get_peer_info_response, build_get_pox_data_response, build_get_tenure_tip_response,
    MockServerClient,
};
use crate::client::StacksClient;
use crate::signerdb::tests::tmp_db_path;
use crate::signerdb::SignerDb;
use crate::v0::signer_state::{
    LocalStateMachine, NewBurnBlock, ReplayScopeOpt, ReplayState, StateMachineUpdate,
};

fn test_ch(i: u8) -> ConsensusHash {
    ConsensusHash([i; 20])
}

fn test_bhh(i: u8) -> BurnchainHeaderHash {
    BurnchainHeaderHash([i; 32])
}

/// Insert a linked chain of canonical burn blocks at the given heights, where
/// block `i` has consensus hash `[i; 20]`, burn hash `[i; 32]`, and parent
/// burn hash `[i - 1; 32]`.
fn insert_canonical_burn_blocks(db: &mut SignerDb, heights: RangeInclusive<u8>) {
    for i in heights {
        db.insert_burn_block(
            &test_bhh(i),
            &test_ch(i),
            i.into(),
            &SystemTime::now(),
            &test_bhh(i - 1),
        )
        .unwrap();
    }
}

/// A signer state machine whose burn view is the canonical block at `height`.
fn signer_state_at(height: u8) -> SignerStateMachine {
    SignerStateMachine {
        burn_block: test_ch(height),
        burn_block_height: height.into(),
        current_miner: MinerState::NoValidMiner,
        active_signer_protocol_version: 0,
        tx_replay_set: ReplayTransactionSet::none(),
    }
}

/// A burn-block event for the canonical block at `height`.
fn canonical_event_at(height: u8) -> NewBurnBlock {
    NewBurnBlock {
        burn_block_height: height.into(),
        consensus_hash: test_ch(height),
    }
}

/// Fork info reporting the canonical tenure at `height` as forked away.
fn fork_info_entry(height: u8, nakamoto_blocks: Option<Vec<NakamotoBlock>>) -> TenureForkingInfo {
    TenureForkingInfo {
        burn_block_hash: test_bhh(height),
        burn_block_height: height.into(),
        sortition_id: SortitionId([height; 32]),
        parent_sortition_id: SortitionId([height - 1; 32]),
        consensus_hash: test_ch(height),
        was_sortition: true,
        first_block_mined: Some(StacksBlockId([1; 32])),
        nakamoto_blocks,
    }
}

/// A winning sortition for the canonical burn block at `height`.
fn sortition_info_at(height: u8, miner_pkh: Hash160) -> SortitionInfo {
    SortitionInfo {
        burn_block_hash: test_bhh(height),
        burn_block_height: height.into(),
        burn_header_timestamp: height.into(),
        sortition_id: SortitionId([height; 32]),
        parent_sortition_id: SortitionId([height - 1; 32]),
        consensus_hash: test_ch(height),
        was_sortition: true,
        miner_pk_hash160: Some(miner_pkh),
        last_sortition_ch: Some(test_ch(height - 1)),
        committed_block_hash: None,
        vrf_seed: None,
        stacks_parent_ch: Some(test_ch(height - 1)),
    }
}

fn http_ok_json<T: serde::Serialize>(value: &T) -> String {
    format!(
        "HTTP/1.1 200 OK\n\n{}",
        serde_json::to_string(value).unwrap()
    )
}

/// A token-transfer transaction and a Nakamoto block containing it, mined in
/// the tenure with the given consensus hash.
fn make_replay_tx_and_block(consensus_hash: ConsensusHash) -> (StacksTransaction, NakamotoBlock) {
    let replay_tx = make_stacks_transfer_tx(
        &StacksPrivateKey::random(),
        0,
        0,
        CHAIN_ID_TESTNET,
        &StacksAddress::burn_address(false).into(),
        100,
    );
    let mut block = NakamotoBlock::new(NakamotoBlockHeader::empty(), vec![replay_tx.clone()]);
    block.header.consensus_hash = consensus_hash;
    let txid_vecs: Vec<_> = vec![replay_tx.txid().as_bytes().to_vec()];
    block.header.tx_merkle_root = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root();
    (replay_tx, block)
}

/// Serve canned HTTP responses by request-path prefix until stopped. Routes
/// are matched in order (put more specific prefixes first). Duplicate prefixes
/// are consumed in order, with the final response reused; an unmatched request
/// panics.
fn spawn_node_responder(
    server: TcpListener,
    routes: Vec<(&'static str, String)>,
) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let stop = Arc::new(AtomicBool::new(false));
    let handle = std::thread::spawn({
        let stop = stop.clone();
        move || {
            let mut routes = routes;
            server.set_nonblocking(true).unwrap();
            while !stop.load(Ordering::SeqCst) {
                let mut stream = match server.accept() {
                    Ok((stream, ..)) => stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(e) => panic!("Unexpected network error in mock server: {e:?}"),
                };
                stream.set_nonblocking(false).unwrap();
                let mut request_bytes = [0u8; 2048];
                let n = stream.read(&mut request_bytes).unwrap();
                let request = String::from_utf8_lossy(&request_bytes[..n]);
                let route_index = routes
                    .iter()
                    .position(|(prefix, _)| request.starts_with(prefix))
                    .unwrap_or_else(|| {
                        panic!(
                            "Unexpected request to mock server: {}",
                            request.lines().next().unwrap_or("")
                        )
                    });
                let route_prefix = routes[route_index].0;
                let has_later_response = routes[route_index + 1..]
                    .iter()
                    .any(|(prefix, _)| *prefix == route_prefix);
                let response = if has_later_response {
                    routes.remove(route_index).1
                } else {
                    routes[route_index].1.clone()
                };
                stream.write_all(response.as_bytes()).unwrap();
            }
        }
    });
    (stop, handle)
}

fn peer_info_route(burn_height: u8, consensus_hash: ConsensusHash) -> (&'static str, String) {
    (
        "GET /v2/info",
        build_get_peer_info_response(Some(burn_height.into()), Some(consensus_hash)).0,
    )
}

/// Route answering the canonicity query for the burn block at `height`,
/// reporting `consensus_hash` as canonical at that height.
fn burn_height_route(height: u8, consensus_hash: ConsensusHash) -> (&'static str, String) {
    let mut sortition = sortition_info_at(height, Hash160([0xab; 20]));
    sortition.consensus_hash = consensus_hash;
    (
        "GET /v3/sortitions/burn_height",
        http_ok_json(&vec![sortition]),
    )
}

/// Route simulating a transient failure of the burn-height canonicity query.
fn burn_height_failure_route() -> (&'static str, String) {
    (
        "GET /v3/sortitions/burn_height",
        "HTTP/1.1 500 Internal Server Error\n\n".to_string(),
    )
}

/// Route serving a tenure-tip query with a Nakamoto header anchored at
/// `consensus_hash`.
fn tenure_tip_route(consensus_hash: ConsensusHash) -> (&'static str, String) {
    let tenure_tip = BlockHeaderWithMetadata {
        anchored_header: StacksBlockHeaderTypes::Nakamoto(NakamotoBlockHeader {
            version: 1,
            chain_length: 1,
            burn_spent: 0,
            consensus_hash: consensus_hash.clone(),
            parent_block_id: StacksBlockId([0x77; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0u8; 32]),
            state_index_root: TrieHash([0u8; 32]),
            timestamp: 0,
            miner_signature: MessageSignature([0u8; 65]),
            signer_signature: vec![],
            pox_treatment: BitVec::ones(1).unwrap(),
            problematic_txs: vec![],
        }),
        burn_view: Some(consensus_hash),
    };
    (
        "GET /v3/tenures/tip",
        build_get_tenure_tip_response(&tenure_tip),
    )
}

struct BurnBlockArrivalOutcome {
    result: Result<(), SignerChainstateError>,
    state: LocalStateMachine,
    replay_scope: ReplayScopeOpt,
}

/// Mutable state shared across each step of a burn-block arrival scenario.
struct BurnBlockArrivalDriver {
    /// Signer database populated for the scenario.
    db: SignerDb,
    /// Client connected to the path-routed mock node.
    client: StacksClient,
    /// Proposal evaluation settings used by state transitions.
    proposal_config: ProposalEvalConfig,
    /// Global signer-state evaluator used by state transitions.
    eval: GlobalStateEvaluator,
    /// Local state machine driven by the scenario.
    state: LocalStateMachine,
    /// Replay scope produced if the scenario detects a fork.
    replay_scope: ReplayScopeOpt,
}

impl BurnBlockArrivalDriver {
    /// Build a driver whose prior burn view is height 110.
    fn new(client: StacksClient, db_heights: RangeInclusive<u8>) -> Self {
        let mut db = SignerDb::new(tmp_db_path()).expect("Failed to create signer db");
        insert_canonical_burn_blocks(&mut db, db_heights);
        let proposal_config = test_proposal_eval_config();
        let mut address_weights = HashMap::new();
        address_weights.insert(client.get_signer_address().clone(), 10_u32);
        let eval = GlobalStateEvaluator::new(HashMap::new(), address_weights);

        Self {
            db,
            client,
            proposal_config,
            eval,
            state: LocalStateMachine::Initialized(signer_state_at(110)),
            replay_scope: None,
        }
    }

    /// Process an incoming burn-block event.
    fn process(&mut self, event: NewBurnBlock) -> Result<(), SignerChainstateError> {
        self.state.bitcoin_block_arrival(
            &mut self.db,
            &self.client,
            &self.proposal_config,
            Some(event),
            &mut self.replay_scope,
            &self.eval,
            0,
        )
    }

    /// Retry the burn-block event currently parked in `Pending`.
    fn retry_pending(&mut self) -> Result<(), SignerChainstateError> {
        self.state.handle_pending_update(
            &mut self.db,
            &self.client,
            &self.proposal_config,
            &mut self.replay_scope,
            &self.eval,
            0,
        )
    }

    /// Convert the final driver state and result into test assertions' shared shape.
    fn into_outcome(self, result: Result<(), SignerChainstateError>) -> BurnBlockArrivalOutcome {
        BurnBlockArrivalOutcome {
            result,
            state: self.state,
            replay_scope: self.replay_scope,
        }
    }
}

/// Run a multi-step burn-block scenario against a path-routed mock node.
fn drive_burn_block_scenario(
    db_heights: RangeInclusive<u8>,
    routes: Vec<(&'static str, String)>,
    scenario: impl FnOnce(&mut BurnBlockArrivalDriver) -> Result<(), SignerChainstateError>,
) -> BurnBlockArrivalOutcome {
    let MockServerClient { server, client, .. } = MockServerClient::new();
    let mut driver = BurnBlockArrivalDriver::new(client, db_heights);
    let (stop, responder) = spawn_node_responder(server, routes);
    let result = scenario(&mut driver);
    stop.store(true, Ordering::SeqCst);
    responder.join().unwrap();
    driver.into_outcome(result)
}

/// Drive `bitcoin_block_arrival` for the canonical event at `event_height`
/// against a prior state machine at height 110, with the mock node serving
/// `routes`.
fn drive_burn_block_arrival(
    db_heights: RangeInclusive<u8>,
    event_height: u8,
    routes: Vec<(&'static str, String)>,
) -> BurnBlockArrivalOutcome {
    drive_burn_block_scenario(db_heights, routes, |driver| {
        driver.process(canonical_event_at(event_height))
    })
}

/// Assert the outcome retained the initialized view at height 110 with no
/// replay state.
#[track_caller]
fn assert_live_view_retained(outcome: &BurnBlockArrivalOutcome) {
    match &outcome.state {
        LocalStateMachine::Initialized(machine) => {
            assert_eq!(
                machine.burn_block_height, 110,
                "State machine moved backward off the live burn view"
            );
            assert_eq!(
                machine.burn_block,
                test_ch(110),
                "State machine moved off the live burn block"
            );
            assert!(
                machine.tx_replay_set.is_empty(),
                "Stale canonical event triggered a tx replay set"
            );
        }
        other => panic!(
            "Stale queued burn-block event left the state machine as {other:?} instead of Initialized"
        ),
    }
    assert!(
        outcome.replay_scope.is_none(),
        "Stale canonical event set a fork replay scope"
    );
}

/// Assert that an unclassified event is parked with the prior live view.
#[track_caller]
fn assert_event_pending(driver: &BurnBlockArrivalDriver, expected_event: &NewBurnBlock) {
    match &driver.state {
        LocalStateMachine::Pending { update, prior } => {
            assert_eq!(
                update,
                &StateMachineUpdate::BurnBlock(expected_event.clone()),
                "Pending state did not retain the unclassified event"
            );
            assert_eq!(
                prior,
                &signer_state_at(110),
                "Pending state did not retain the prior live view"
            );
        }
        other => panic!("Unclassified burn-block event left the state machine as {other:?}"),
    }
    assert!(
        driver.replay_scope.is_none(),
        "Failed canonicity check started fork replay"
    );
}

/// Assert that fork handling completed with the expected origin and replay transaction.
#[track_caller]
fn assert_successful_fork_replay(
    outcome: &BurnBlockArrivalOutcome,
    expected_origin: &NewBurnBlock,
    replay_tx: &StacksTransaction,
) {
    assert!(
        outcome.result.is_ok(),
        "Fork handling failed: {:?}",
        outcome.result.as_ref().err()
    );
    let scope = outcome
        .replay_scope
        .as_ref()
        .expect("Burn-block event did not enter fork handling");
    assert_eq!(&scope.fork_origin, expected_origin);
    assert_eq!(scope.past_tip.burn_block_height, 110);
    assert_eq!(scope.past_tip.consensus_hash, test_ch(110));
    let LocalStateMachine::Initialized(machine) = &outcome.state else {
        panic!(
            "Successful fork handling left the state machine as {:?}",
            outcome.state
        );
    };
    assert_eq!(
        machine.tx_replay_set.clone_as_optional(),
        Some(vec![replay_tx.clone()]),
        "Reorged-away transaction missing from the replay set"
    );
}

/// A burn-block event at the same height as the state-machine tip but with a
/// different consensus hash is a genuine competing branch and must still be
/// detected as a fork. This is the boundary case a naive "ignore events at or
/// below the prior height" fix would silently break.
#[test]
fn conflicting_burn_block_at_same_height_is_a_bitcoin_fork() {
    let MockServerClient {
        mut server,
        client,
        config,
    } = MockServerClient::new();
    let mut db = SignerDb::new(tmp_db_path()).expect("Failed to create signer db");
    insert_canonical_burn_blocks(&mut db, 100..=110);

    // A Nakamoto block mined in the forked-away canonical tenure at height 110.
    let (replay_tx, forked_block) = make_replay_tx_and_block(test_ch(110));

    let fork_event = NewBurnBlock {
        burn_block_height: 110,
        consensus_hash: ConsensusHash([0xfe; 20]),
    };
    let prior = signer_state_at(110);

    let expected_tx = replay_tx;
    let expected_fork_event = fork_event.clone();
    let h = std::thread::spawn(move || {
        let state = LocalStateMachine::Initialized(prior.clone());
        let result = state
            .handle_possible_bitcoin_fork(&db, &client, &fork_event, &prior, &ReplayState::Unset)
            .expect("Fork handling should not error");
        match result {
            Some(ReplayState::InProgress(replay_set, scope)) => {
                assert_eq!(replay_set.clone_as_optional(), Some(vec![expected_tx]));
                assert_eq!(scope.fork_origin, expected_fork_event);
                assert_eq!(scope.past_tip.burn_block_height, 110);
                assert_eq!(scope.past_tip.consensus_hash, test_ch(110));
            }
            Some(ReplayState::Unset) => {
                panic!("Same-height competing branch produced an unset replay state")
            }
            None => panic!("Same-height competing branch was not detected as a fork"),
        }
    });

    // The forked-away range is the single tenure at the prior tip.
    let to_send = http_ok_json(&vec![fork_info_entry(110, Some(vec![forked_block]))]);
    crate::client::tests::write_response(server, to_send.as_bytes());

    server = crate::client::tests::mock_server_from_config(&config);
    let (pox_response, _) = build_get_pox_data_response(None, None, None, None);
    crate::client::tests::write_response(server, pox_response.as_bytes());

    h.join().unwrap();
}

/// Cold-start ordering: the state machine was initialized from the node's
/// live view at height 110 (whose burn block never arrived as an event, so it
/// has no signerdb row), then a queued canonical event at height 105 drains.
/// The node confirms the current view is still canonical, so the stale event
/// must be ignored and the state machine left intact.
#[test]
fn stale_burn_block_event_after_live_initialization_keeps_state_machine_initialized() {
    let outcome = drive_burn_block_arrival(
        100..=105,
        105,
        vec![
            peer_info_route(110, test_ch(110)),
            burn_height_route(110, test_ch(110)),
        ],
    );
    assert!(
        outcome.result.is_ok(),
        "Draining a stale queued burn-block event errored: {:?}",
        outcome.result.err()
    );
    assert_live_view_retained(&outcome);
}

/// Same as above, but the node tip advanced past the initialized view while
/// the queue drained. The prior view is still canonical (an ancestor of the
/// new tip), so the stale event must still be ignored; the newer tip's own
/// event is further back in the queue.
#[test]
fn stale_burn_block_event_with_advanced_node_tip_is_ignored() {
    let outcome = drive_burn_block_arrival(
        100..=105,
        105,
        vec![
            peer_info_route(111, test_ch(111)),
            burn_height_route(110, test_ch(110)),
        ],
    );
    assert!(
        outcome.result.is_ok(),
        "Draining a stale queued burn-block event errored: {:?}",
        outcome.result.err()
    );
    assert_live_view_retained(&outcome);
}

/// A failed canonicity query parks the event with the prior view. Once the
/// node confirms that view is canonical, the retry discards the stale event
/// and returns to `Initialized`.
#[test]
fn canonicity_check_failure_retries_canonical_event() {
    let stale_event = canonical_event_at(105);
    let outcome = drive_burn_block_scenario(
        100..=105,
        vec![
            peer_info_route(110, test_ch(110)),
            burn_height_failure_route(),
            peer_info_route(110, test_ch(110)),
            burn_height_route(110, test_ch(110)),
        ],
        |driver| {
            assert!(
                driver.process(stale_event.clone()).is_err(),
                "Expected the initial canonicity query to fail"
            );
            assert_event_pending(driver, &stale_event);
            driver.retry_pending()
        },
    );
    assert!(
        outcome.result.is_ok(),
        "Retrying the canonical event failed: {:?}",
        outcome.result.err()
    );
    assert_live_view_retained(&outcome);
}

/// If the retry instead shows that the prior view was orphaned, the parked
/// event must continue into fork handling.
#[test]
fn canonicity_check_failure_retries_non_canonical_event() {
    // The node reorged: its canonical chain at height 110 is now a competing
    // branch, orphaning the prior view.
    let fork_ch = ConsensusHash([0xfe; 20]);
    let (replay_tx, forked_block) = make_replay_tx_and_block(test_ch(110));
    // The node's post-reorg sortition view: the fork branch won at 110.
    let mut cur_sortition = sortition_info_at(110, Hash160([0xab; 20]));
    cur_sortition.consensus_hash = fork_ch.clone();
    let last_sortition = sortition_info_at(109, Hash160([0xab; 20]));
    let stale_event = canonical_event_at(105);
    let outcome = drive_burn_block_scenario(
        100..=110,
        vec![
            peer_info_route(110, fork_ch.clone()),
            burn_height_failure_route(),
            peer_info_route(110, fork_ch.clone()),
            burn_height_route(110, fork_ch),
            (
                "GET /v3/sortitions/latest_and_last",
                http_ok_json(&vec![cur_sortition, last_sortition]),
            ),
            (
                "GET /v3/tenures/fork_info",
                http_ok_json(&vec![
                    fork_info_entry(110, Some(vec![forked_block])),
                    fork_info_entry(105, None),
                ]),
            ),
            tenure_tip_route(test_ch(109)),
            (
                "GET /v2/pox",
                build_get_pox_data_response(None, None, None, None).0,
            ),
        ],
        |driver| {
            assert!(
                driver.process(stale_event.clone()).is_err(),
                "Expected the initial canonicity query to fail"
            );
            assert_event_pending(driver, &stale_event);
            driver.retry_pending()
        },
    );

    assert_successful_fork_replay(&outcome, &canonical_event_at(105), &replay_tx);
}

/// A newer event supersedes a parked lower-height event. Once the incoming
/// event reaches the prior view's height, it enters normal fork handling
/// without depending on the failed lower-height canonicity query.
#[test]
fn newer_event_supersedes_failed_canonicity_check() {
    let fork_ch = ConsensusHash([0xfe; 20]);
    let fork_event = NewBurnBlock {
        burn_block_height: 110,
        consensus_hash: fork_ch.clone(),
    };
    let (replay_tx, forked_block) = make_replay_tx_and_block(test_ch(110));
    let mut cur_sortition = sortition_info_at(110, Hash160([0xab; 20]));
    cur_sortition.consensus_hash = fork_ch.clone();
    let last_sortition = sortition_info_at(109, Hash160([0xab; 20]));
    let stale_event = canonical_event_at(105);
    let outcome = drive_burn_block_scenario(
        100..=110,
        vec![
            peer_info_route(110, fork_ch.clone()),
            burn_height_failure_route(),
            peer_info_route(110, fork_ch),
            (
                "GET /v3/tenures/fork_info",
                http_ok_json(&vec![fork_info_entry(110, Some(vec![forked_block]))]),
            ),
            (
                "GET /v3/sortitions/latest_and_last",
                http_ok_json(&vec![cur_sortition, last_sortition]),
            ),
            tenure_tip_route(test_ch(109)),
            (
                "GET /v2/pox",
                build_get_pox_data_response(None, None, None, None).0,
            ),
        ],
        |driver| {
            assert!(
                driver.process(stale_event.clone()).is_err(),
                "Expected the initial canonicity query to fail"
            );
            assert_event_pending(driver, &stale_event);
            driver.process(fork_event.clone())
        },
    );

    assert_successful_fork_replay(&outcome, &fork_event, &replay_tx);
}

/// When the node's live tip is below the prior state-machine height, the
/// prior-height canonicity query cannot provide a verdict: the queried height
/// is outside the node's current canonical fork. Preserve the pre-existing
/// fork path until the broader shorter-tip reconciliation policy is defined.
#[test]
fn shorter_node_tip_bypasses_canonicity_guard_and_triggers_fork_handling() {
    let (replay_tx, forked_block) = make_replay_tx_and_block(test_ch(110));
    let cur_sortition = sortition_info_at(105, Hash160([0xab; 20]));
    let last_sortition = sortition_info_at(104, Hash160([0xab; 20]));
    let outcome = drive_burn_block_arrival(
        100..=110,
        105,
        vec![
            peer_info_route(105, test_ch(105)),
            (
                "GET /v3/sortitions/latest_and_last",
                http_ok_json(&vec![cur_sortition, last_sortition]),
            ),
            (
                "GET /v3/tenures/fork_info",
                http_ok_json(&vec![
                    fork_info_entry(110, Some(vec![forked_block])),
                    fork_info_entry(105, None),
                ]),
            ),
            tenure_tip_route(test_ch(104)),
            (
                "GET /v2/pox",
                build_get_pox_data_response(None, None, None, None).0,
            ),
        ],
    );

    assert_successful_fork_replay(&outcome, &canonical_event_at(105), &replay_tx);
}
