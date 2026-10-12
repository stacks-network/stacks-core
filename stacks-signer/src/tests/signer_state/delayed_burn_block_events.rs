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

//! Regression coverage for queued burn-block events after live initialization.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
use blockstack_lib::chainstate::stacks::db::StacksBlockHeaderTypes;
use blockstack_lib::net::api::get_tenure_tip_meta::BlockHeaderWithMetadata;
use blockstack_lib::net::api::getsortition::SortitionInfo;
use clarity::types::chainstate::{BurnchainHeaderHash, ConsensusHash, SortitionId};
use clarity::util::hash::Hash160;
use libsigner::v0::signer_state::{GlobalStateEvaluator, MinerState, SignerStateMachine};

use super::test_proposal_eval_config;
use crate::chainstate::{ProposalEvalConfig, SignerChainstateError};
use crate::client::tests::{
    build_get_peer_info_response, build_get_tenure_tip_response, MockServerClient,
};
use crate::client::StacksClient;
use crate::signerdb::tests::tmp_db_path;
use crate::signerdb::SignerDb;
use crate::v0::signer_state::{
    LocalStateMachine, NewBurnBlock, PendingRetryBackoff, StateMachineUpdate,
};

/// Build an event with an independently chosen height and branch identifier.
fn event(height: u64, id: u8) -> NewBurnBlock {
    NewBurnBlock {
        burn_block_height: height,
        consensus_hash: ConsensusHash([id; 20]),
    }
}

/// Build the parent-tenure header served by a node on the given branch.
fn parent_header(id: u8) -> NakamotoBlockHeader {
    NakamotoBlockHeader {
        chain_length: 1,
        consensus_hash: ConsensusHash([id - 1; 20]),
        ..NakamotoBlockHeader::empty()
    }
}

/// The full initialized state expected from the canned node responses.
fn node_state(height: u64, id: u8) -> LocalStateMachine {
    let header = parent_header(id);
    LocalStateMachine::Initialized(SignerStateMachine {
        burn_block: ConsensusHash([id; 20]),
        burn_block_height: height,
        current_miner: MinerState::ActiveMiner {
            current_miner_pkh: Hash160([0xab; 20]),
            tenure_id: ConsensusHash([id; 20]),
            parent_tenure_id: header.consensus_hash.clone(),
            parent_tenure_last_block: header.block_id(),
            parent_tenure_last_block_height: header.chain_length,
        },
        active_signer_protocol_version: 0,
    })
}

/// Script the peer-info, sortition, and parent-tenure RPCs for one arrival.
fn node_responses(height: u64, id: u8) -> Vec<(String, String)> {
    let sortition = |height, id| SortitionInfo {
        burn_block_hash: BurnchainHeaderHash([id; 32]),
        burn_block_height: height,
        burn_header_timestamp: height,
        sortition_id: SortitionId([id; 32]),
        parent_sortition_id: SortitionId([id - 1; 32]),
        consensus_hash: ConsensusHash([id; 20]),
        was_sortition: true,
        miner_pk_hash160: Some(Hash160([0xab; 20])),
        last_sortition_ch: Some(ConsensusHash([id - 1; 20])),
        committed_block_hash: None,
        vrf_seed: None,
        stacks_parent_ch: Some(ConsensusHash([id - 1; 20])),
    };
    let sortitions = [sortition(height, id), sortition(height - 1, id - 1)];
    let header = parent_header(id);
    vec![
        (
            "/v2/info".into(),
            build_get_peer_info_response(Some(height), Some(ConsensusHash([id; 20]))).0,
        ),
        (
            "/v3/sortitions/latest_and_last".into(),
            format!(
                "HTTP/1.1 200 OK\n\n{}",
                serde_json::to_string(&sortitions).unwrap()
            ),
        ),
        (
            format!("/v3/tenures/tip_metadata/{}", header.consensus_hash),
            build_get_tenure_tip_response(&BlockHeaderWithMetadata {
                burn_view: Some(header.consensus_hash.clone()),
                anchored_header: StacksBlockHeaderTypes::Nakamoto(header),
            }),
        ),
    ]
}

/// Serve a finite RPC script, checking paths and bounding waits for missing requests.
fn serve_responses(server: TcpListener, responses: Vec<(String, String)>) {
    server.set_nonblocking(true).unwrap();
    for (path, response) in responses {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match server.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "Missing request for {path}");
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("Mock node accept failed: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut request = String::new();
        reader.read_line(&mut request).unwrap();
        loop {
            let mut header = String::new();
            assert_ne!(
                reader.read_line(&mut header).unwrap(),
                0,
                "Incomplete request"
            );
            if header == "\r\n" || header == "\n" {
                break;
            }
        }
        stream.write_all(response.as_bytes()).unwrap();
        assert_eq!(request.trim_end(), format!("GET {path} HTTP/1.1"));
    }
}

/// Local signer state shared by successive arrivals in a scenario.
struct BurnBlockDriver {
    /// Database containing only burn blocks whose events have drained.
    db: SignerDb,
    /// Client connected to the scripted node.
    client: StacksClient,
    /// Settings used to evaluate the node's sortitions.
    config: ProposalEvalConfig,
    /// Signer weights used by the state machine.
    eval: GlobalStateEvaluator,
    /// State retained between arrivals and retries.
    state: LocalStateMachine,
}

impl BurnBlockDriver {
    /// Process an event through the production arrival path.
    fn process(&mut self, event: NewBurnBlock) -> Result<(), SignerChainstateError> {
        self.state.bitcoin_block_arrival(
            &mut self.db,
            &self.client,
            &self.config,
            Some(event),
            &self.eval,
            0,
        )
    }

    /// Assert that a failed event retains the complete prior state for retry.
    #[track_caller]
    fn assert_pending(&self, event: &NewBurnBlock, prior: &LocalStateMachine) {
        let LocalStateMachine::Initialized(prior) = prior else {
            panic!("Expected an initialized prior state");
        };
        assert_eq!(
            self.state,
            LocalStateMachine::Pending {
                update: StateMachineUpdate::BurnBlock(event.clone()),
                prior: prior.clone(),
            }
        );
    }

    /// Retry a parked arrival through the production retry path.
    fn retry(&mut self) {
        self.state
            .handle_pending_update(
                &mut self.db,
                &self.client,
                &self.config,
                &self.eval,
                0,
                &mut PendingRetryBackoff::default(),
            )
            .unwrap();
    }
}

/// Initialize from the live node at height 110, then drain the scenario's events.
fn run_scenario(responses: Vec<(String, String)>, scenario: impl FnOnce(&mut BurnBlockDriver)) {
    let MockServerClient { server, client, .. } = MockServerClient::new();
    let mut db = SignerDb::new(tmp_db_path()).unwrap();
    // Startup has only drained events through 105; the live tip has no signerdb row.
    for height in 100..=105_u8 {
        db.insert_burn_block(
            &BurnchainHeaderHash([height; 32]),
            &ConsensusHash([height; 20]),
            u64::from(height),
            &SystemTime::now(),
            &BurnchainHeaderHash([height - 1; 32]),
        )
        .unwrap();
    }
    let mut config = test_proposal_eval_config();
    config.block_proposal_timeout = Duration::from_secs(600);
    let weights = HashMap::from([(client.get_signer_address().clone(), 10)]);
    let eval = GlobalStateEvaluator::new(HashMap::new(), weights);
    thread::scope(|scope| {
        let script = node_responses(110, 110)
            .into_iter()
            .chain(responses)
            .collect();
        let server = scope.spawn(move || serve_responses(server, script));
        let state = LocalStateMachine::new(&mut db, &client, &config, &eval, 0);
        assert_eq!(state, node_state(110, 110));
        scenario(&mut BurnBlockDriver {
            db,
            client,
            config,
            eval,
            state,
        });
        server.join().unwrap();
    });
}

/// Reordered, duplicate, and orphaned old events must reconcile to the live node tip.
#[test]
fn delayed_events_after_initialization_follow_live_node_tip() {
    let cases = [
        (event(105, 105), 110, 110),
        (event(103, 103), 111, 111),
        (event(105, 105), 111, 111),
        (event(105, 0xee), 111, 111),
    ];
    let responses = cases
        .iter()
        .flat_map(|(_, height, id)| node_responses(*height, *id))
        .collect();
    run_scenario(responses, |driver| {
        for (event, height, id) in cases {
            driver.process(event).unwrap();
            assert_eq!(driver.state, node_state(height, id));
        }
    });
}

/// Delayed events must also permit the live node's competing or shorter view to be adopted.
#[test]
fn delayed_events_reconcile_to_reorged_node_tip() {
    for height in [110, 105] {
        run_scenario(node_responses(height, 0xfe), |driver| {
            driver.process(event(104, 104)).unwrap_or_else(|error| {
                panic!("Reconciliation to node height {height} failed: {error}")
            });
            assert_eq!(driver.state, node_state(height, 0xfe));
        });
    }
}

/// An event on a competing branch at the prior height must still update the view.
#[test]
fn same_height_fork_event_updates_live_view() {
    run_scenario(node_responses(110, 0xfe), |driver| {
        driver.process(event(110, 0xfe)).unwrap();
        assert_eq!(driver.state, node_state(110, 0xfe));
    });
}

/// Failures at each RPC preserve the active miner; retries use the latest node view.
#[test]
fn delayed_event_rpc_failures_retry_against_live_node_tip() {
    for failure in 0..3 {
        for (height, id) in [(111, 111), (110, 0xfe)] {
            let mut responses = node_responses(110, 110);
            responses.truncate(failure + 1);
            responses[failure].1 = "HTTP/1.1 500 Internal Server Error\n\n".into();
            responses.extend(node_responses(height, id));
            run_scenario(responses, |driver| {
                let prior = driver.state.clone();
                let delayed = event(105, 105);
                assert!(
                    driver.process(delayed.clone()).is_err(),
                    "RPC {failure} must fail"
                );
                driver.assert_pending(&delayed, &prior);
                driver.retry();
                assert_eq!(driver.state, node_state(height, id));
            });
        }
    }
}

/// A new arrival supersedes a failed delayed event, including when it also needs a retry.
#[test]
fn newer_event_supersedes_failed_delayed_event() {
    let failure = || {
        (
            "/v2/info".into(),
            "HTTP/1.1 500 Internal Server Error\n\n".into(),
        )
    };
    let mut responses = vec![failure(), failure()];
    responses.extend(node_responses(111, 111));
    run_scenario(responses, |driver| {
        let prior = driver.state.clone();
        let delayed = event(105, 105);
        assert!(driver.process(delayed.clone()).is_err());
        driver.assert_pending(&delayed, &prior);
        let newer = event(111, 111);
        assert!(driver.process(newer.clone()).is_err());
        driver.assert_pending(&newer, &prior);
        driver.retry();
        assert_eq!(driver.state, node_state(111, 111));
    });
}
