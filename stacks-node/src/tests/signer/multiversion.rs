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
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

use libsigner::v0::messages::{
    BlockAccepted, BlockResponse, BlockResponseData, RejectReason, SignerMessage,
    SignerMessageMetadata,
};
use libsigner::v0::signer_state::{MinerState, ReplayTransactionSet, SignerStateMachine};
use libsigner_v3_3_0_0_4::v0::messages::SignerMessage as OldSignerMessage;
use signer_v3_3_0_0_4::v0::signer_state::SUPPORTED_SIGNER_PROTOCOL_VERSION as OldSupportedVersion;
use stacks::chainstate::stacks::StacksTransaction;
use stacks::util::hash::{Hash160, Sha512Trunc256Sum};
use stacks::util::secp256k1::{MessageSignature, Secp256k1PrivateKey};
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId};
use stacks_common_v3_3_0_0_4::codec::StacksMessageCodec as OldStacksMessageCodec;
use stacks_signer::runloop::{RewardCycleInfo, State, StateInfo};
use stacks_signer::v0::signer_state::{
    LocalStateMachine, SUPPORTED_SIGNER_PROTOCOL_VERSION as NewSupportedVersion,
};
use stacks_signer::v0::SpawnedSigner;
use {libsigner_v3_3_0_0_4, signer_v3_3_0_0_4, stacks_common_v3_3_0_0_4, stacks_v3_3_0_0_4};

use super::SpawnedSignerTrait;
use crate::stacks_common::codec::StacksMessageCodec;
use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::neon_integrations::{get_account, get_chain_info, test_observer};
use crate::tests::signer::SignerTest;
use crate::tests::{self};
use crate::Keychain;

pub enum MultiverSpawnedSigner {
    V33004(signer_v3_3_0_0_4::v0::SpawnedSigner),
    Current(SpawnedSigner),
}

pub enum ReceiveResult {
    V33004(Result<signer_v3_3_0_0_4::runloop::SignerResult, ()>),
    Current(Result<stacks_signer::runloop::SignerResult, TryRecvError>),
}

// Helper function to convert libsigner_v3_3_0_0_4 miner state to current miner state
pub fn miner_state_v3_3_0_0_4_to_current(
    miner_state: &libsigner_v3_3_0_0_4::v0::signer_state::MinerState,
) -> MinerState {
    match miner_state {
        libsigner_v3_3_0_0_4::v0::signer_state::MinerState::NoValidMiner => {
            MinerState::NoValidMiner
        }
        libsigner_v3_3_0_0_4::v0::signer_state::MinerState::ActiveMiner {
            current_miner_pkh,
            tenure_id,
            parent_tenure_id,
            parent_tenure_last_block,
            parent_tenure_last_block_height,
        } => MinerState::ActiveMiner {
            current_miner_pkh: Hash160(current_miner_pkh.0),
            tenure_id: ConsensusHash(tenure_id.0),
            parent_tenure_id: ConsensusHash(parent_tenure_id.0),
            parent_tenure_last_block: StacksBlockId(parent_tenure_last_block.0),
            parent_tenure_last_block_height: *parent_tenure_last_block_height,
        },
    }
}

// Helper function to convert from one to the other
pub fn stacks_transaction_v3_3_0_0_4_to_current(
    tx: &stacks_v3_3_0_0_4::chainstate::stacks::StacksTransaction,
) -> StacksTransaction {
    let tx_bytes = tx.serialize_to_vec();
    StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap()
}

// Helper function to convert libsigner_v3_3_0_0_4 signer state machine to current signer state machine
pub fn signer_state_update_v3_3_0_0_4_to_current(
    update: &signer_v3_3_0_0_4::v0::signer_state::StateMachineUpdate,
) -> stacks_signer::v0::signer_state::StateMachineUpdate {
    let serialized = serde_json::to_string(update).unwrap();
    serde_json::from_str(&serialized).unwrap()
}

// Helper function to convert libsigner_v3_3_0_0_4 signer state machine to current signer state machine
pub fn signer_state_machine_v3_3_0_0_4_to_current(
    machine: &libsigner_v3_3_0_0_4::v0::signer_state::SignerStateMachine,
) -> SignerStateMachine {
    SignerStateMachine {
        burn_block: ConsensusHash(machine.burn_block.0),
        burn_block_height: machine.burn_block_height,
        current_miner: miner_state_v3_3_0_0_4_to_current(&machine.current_miner),
        active_signer_protocol_version: machine.active_signer_protocol_version,
        tx_replay_set: ReplayTransactionSet::new(
            machine
                .tx_replay_set
                .clone()
                .unwrap_or_default()
                .iter()
                .map(stacks_transaction_v3_3_0_0_4_to_current)
                .collect(),
        ),
    }
}

// Helper function to convert signer_v3_3_0_0_4 local state machines to current local state machines
pub fn local_state_machine_v3_3_0_0_4_to_current(
    state_machine: &signer_v3_3_0_0_4::v0::signer_state::LocalStateMachine,
) -> LocalStateMachine {
    match state_machine {
        signer_v3_3_0_0_4::v0::signer_state::LocalStateMachine::Uninitialized => {
            LocalStateMachine::Uninitialized
        }
        signer_v3_3_0_0_4::v0::signer_state::LocalStateMachine::Pending { prior, update } => {
            LocalStateMachine::Pending {
                prior: signer_state_machine_v3_3_0_0_4_to_current(prior),
                update: signer_state_update_v3_3_0_0_4_to_current(update),
            }
        }
        signer_v3_3_0_0_4::v0::signer_state::LocalStateMachine::Initialized(machine) => {
            LocalStateMachine::Initialized(signer_state_machine_v3_3_0_0_4_to_current(machine))
        }
    }
}

impl SpawnedSignerTrait for MultiverSpawnedSigner {
    type ReceiveResult = ReceiveResult;
    type StopResult = ();

    fn new(c: stacks_signer::config::GlobalConfig) -> Self {
        if c.endpoint.port() % 2 == 0 {
            debug!(
                "Spawning current version signer for endpoint {}",
                c.endpoint
            );
            Self::Current(SpawnedSigner::new(c))
        } else {
            debug!(
                "Spawning v3_3_0_0_4 version signer for endpoint {}",
                c.endpoint
            );
            let config = signer_v3_3_0_0_4::config::GlobalConfig {
                node_host: c.node_host,
                endpoint: c.endpoint,
                stacks_private_key: serde_json::from_value(
                    serde_json::to_value(&c.stacks_private_key).unwrap(),
                )
                .unwrap(),
                stacks_address: serde_json::from_value(
                    serde_json::to_value(&c.stacks_address).unwrap(),
                )
                .unwrap(),
                network: signer_v3_3_0_0_4::config::Network::Testnet,
                event_timeout: c.event_timeout,
                auth_password: c.auth_password,
                db_path: c.db_path,
                metrics_endpoint: None,
                first_proposal_burn_block_timing: c.first_proposal_burn_block_timing,
                block_proposal_timeout: c.block_proposal_timeout,
                chain_id: c.chain_id,
                tenure_last_block_proposal_timeout: c.tenure_last_block_proposal_timeout,
                block_proposal_validation_timeout: c.block_proposal_validation_timeout,
                tenure_idle_timeout: c.tenure_idle_timeout,
                tenure_idle_timeout_buffer: c.tenure_idle_timeout_buffer,
                block_proposal_max_age_secs: c.block_proposal_max_age_secs,
                reorg_attempts_activity_timeout: c.reorg_attempts_activity_timeout,
                dry_run: c.dry_run,
                proposal_wait_for_parent_time: c.proposal_wait_for_parent_time,
                validate_with_replay_tx: c.validate_with_replay_tx,
                capitulate_miner_view_timeout: c.capitulate_miner_view_timeout,
                reset_replay_set_after_fork_blocks: c.reset_replay_set_after_fork_blocks,
                stackerdb_timeout: c.stackerdb_timeout,
                supported_signer_protocol_version: c.supported_signer_protocol_version,
                read_count_idle_timeout: c.read_count_idle_timeout,
            };
            Self::V33004(signer_v3_3_0_0_4::v0::SpawnedSigner::new(config))
        }
    }

    fn try_recv(&self) -> Self::ReceiveResult {
        match self {
            MultiverSpawnedSigner::V33004(spawned_signer) => {
                let result = spawned_signer.res_recv.try_recv().map_err(|_| ());
                ReceiveResult::V33004(result)
            }
            MultiverSpawnedSigner::Current(spawned_signer) => {
                ReceiveResult::Current(spawned_signer.res_recv.try_recv())
            }
        }
    }

    fn stop(self) -> Option<Self::StopResult> {
        match self {
            MultiverSpawnedSigner::V33004(spawned_signer) => spawned_signer.stop().map(|_| ()),
            MultiverSpawnedSigner::Current(spawned_signer) => spawned_signer.stop().map(|_| ()),
        }
    }

    fn state_info_from_recv_result(
        result: Self::ReceiveResult,
    ) -> Option<stacks_signer::runloop::StateInfo> {
        match result {
            ReceiveResult::V33004(signer_result) => {
                let Ok(signer_v3_3_0_0_4::runloop::SignerResult::StatusCheck(state_info)) =
                    signer_result
                else {
                    return None;
                };
                let signer_v3_3_0_0_4::runloop::StateInfo {
                    runloop_state,
                    reward_cycle_info,
                    running_signers,
                    signer_canonical_tips,
                    pending_proposals_count,
                    signer_state_machines,
                } = state_info;
                Some(StateInfo {
                    runloop_state: match runloop_state {
                        signer_v3_3_0_0_4::runloop::State::Uninitialized => State::Uninitialized,
                        signer_v3_3_0_0_4::runloop::State::NoRegisteredSigners => {
                            State::NoRegisteredSigners
                        }
                        signer_v3_3_0_0_4::runloop::State::RegisteredSigners => {
                            State::RegisteredSigners
                        }
                    },
                    reward_cycle_info: reward_cycle_info.map(|info| RewardCycleInfo {
                        reward_cycle: info.reward_cycle,
                        reward_cycle_length: info.reward_cycle_length,
                        prepare_phase_block_length: info.prepare_phase_block_length,
                        first_burnchain_block_height: info.first_burnchain_block_height,
                        last_burnchain_block_height: info.last_burnchain_block_height,
                    }),
                    running_signers,

                    // /// The local state machines for the running signers
                    // ///  as a pair of (reward-cycle, state-machine)
                    // pub signer_state_machines: Vec<(u64, Option<LocalStateMachine>)>,
                    // /// The number of pending block proposals for this signer
                    // pub pending_proposals_count: u64,
                    // /// The canonical tip block info according to the running signers
                    // /// as a pair of (reward-cycle, block-info)
                    // pub signer_canonical_tips: Vec<(u64, Option<BlockInfo>)>,
                    signer_state_machines: signer_state_machines
                        .iter()
                        .map(|(i, machine)| {
                            (
                                *i,
                                machine
                                    .as_ref()
                                    .map(local_state_machine_v3_3_0_0_4_to_current),
                            )
                        })
                        .collect(),
                    pending_proposals_count,
                    signer_canonical_tips: signer_canonical_tips
                        .into_iter()
                        .map(|(i, info)| {
                            (
                                i,
                                info.map(|info| {
                                    let serialized = serde_json::to_string(&info).unwrap();
                                    serde_json::from_str(&serialized).unwrap()
                                }),
                            )
                        })
                        .collect(),
                })
            }
            ReceiveResult::Current(signer_result) => {
                SpawnedSigner::state_info_from_recv_result(signer_result)
            }
        }
    }
}

#[test]
fn old_version_parses_new_messages() {
    let new_msg = BlockAccepted {
        signer_signature_hash: Sha512Trunc256Sum::from_data(&[0, 1, 2, 3]),
        signature: MessageSignature([0xf3; 65]),
        metadata: SignerMessageMetadata {
            server_version: "latest-version_signer".into(),
        },
        response_data: BlockResponseData {
            version: 4,
            tenure_extend_timestamp: 2049,
            reject_reason: RejectReason::NotRejected,
            tenure_extend_read_count_timestamp: 5058,
            unknown_bytes: vec![],
        },
    };

    let serialized_new_msg =
        SignerMessage::BlockResponse(BlockResponse::Accepted(new_msg.clone())).serialize_to_vec();
    let old_msg =
        OldSignerMessage::consensus_deserialize(&mut serialized_new_msg.as_slice()).unwrap();
    let OldSignerMessage::BlockResponse(ref old_block_response) = old_msg else {
        panic!("Old version should have parsed response to a block response");
    };
    let as_block_accepted = old_block_response.as_block_accepted().unwrap();
    assert_eq!(
        as_block_accepted.signer_signature_hash.0,
        new_msg.signer_signature_hash.0
    );
    assert_eq!(as_block_accepted.signature.0, new_msg.signature.0);
    assert_eq!(
        as_block_accepted.metadata.server_version,
        new_msg.metadata.server_version
    );
    assert_eq!(
        as_block_accepted.response_data.version,
        new_msg.response_data.version
    );
    assert_eq!(
        as_block_accepted.response_data.tenure_extend_timestamp,
        new_msg.response_data.tenure_extend_timestamp
    );
    assert_eq!(
        as_block_accepted.response_data.reject_reason.to_string(),
        new_msg.response_data.reject_reason.to_string()
    );
    let empty_vec: Vec<u8> = vec![];
    assert_eq!(
        as_block_accepted.response_data.unknown_bytes, // No difference between versions at the moment
        empty_vec
    );

    let serialized_old_msg = old_msg.serialize_to_vec();
    assert_eq!(serialized_new_msg, serialized_old_msg);
}

#[test]
#[ignore]
fn with_new_miner_and_old_signers() {
    with_new_miners::<MultiverSpawnedSigner>(2);
}

fn with_new_miners<S: SpawnedSignerTrait>(supported_signer_protocol_version: u64) {
    let sender_sk = Secp256k1PrivateKey::from_seed(&[0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb]);
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 1000;
    let send_fee = 180;

    let btc_miner_1_seed = vec![1, 1, 1, 1];
    let btc_miner_1_pk = Keychain::default(btc_miner_1_seed.clone()).get_pub_key();

    let node_1_rpc = 30411;
    let node_1_p2p = 30412;

    let localhost = "127.0.0.1";
    let num_transfer_txs = 20;
    let initial_balances = vec![(
        sender_addr.clone(),
        (send_amt + send_fee) * num_transfer_txs,
    )];
    let miner_1_sk = Secp256k1PrivateKey::from_seed(&[1]);

    let num_signers = 5;
    // partition the signer set so that ~half are listening and using node 1 for RPC and events,
    //  and the rest are using node 2
    let signer_test: SignerTest<S> = SignerTest::new_with_config_modifications(
        num_signers,
        initial_balances,
        |signer_config| {
            signer_config.supported_signer_protocol_version = supported_signer_protocol_version;
        },
        |config| {
            config.node.rpc_bind = format!("{localhost}:{node_1_rpc}");
            config.node.p2p_bind = format!("{localhost}:{node_1_p2p}");
            config.node.data_url = format!("http://{localhost}:{node_1_rpc}");
            config.node.p2p_address = format!("{localhost}:{node_1_p2p}");
            config.miner.wait_on_interim_blocks = Some(Duration::from_secs(5));
            config.node.pox_sync_sample_secs = 30;
            config.burnchain.pox_reward_length = Some(30);

            config.node.seed = btc_miner_1_seed.clone();
            config.node.local_peer_seed = btc_miner_1_seed.clone();
            config.burnchain.local_mining_public_key = Some(btc_miner_1_pk.to_hex());
            config.miner.mining_key = Some(miner_1_sk.clone());
        },
        Some(vec![btc_miner_1_pk.clone()]),
        None,
    );

    signer_test.boot_to_epoch_3();
    test_observer::clear();

    for i in 0..5 {
        info!(
            "--------------- Mining Tenure #{} and Tenure Start Block ---------------",
            i + 1
        );
        signer_test.mine_nakamoto_block(Duration::from_secs(60), false);
        // submit a transfer
        info!(
            "--------------- Mining #{} Transfer Block---------------",
            i + 1
        );
        let (_, nonce) = signer_test
            .submit_transfer_tx(&sender_sk, send_fee, send_amt)
            .unwrap();
        wait_for(120, || {
            Ok(get_account(&signer_test.running_nodes.rpc_origin(), &sender_addr).nonce > nonce)
        })
        .expect("Timed out waiting for interim block to be mined");
    }
    let stackerdb_events = test_observer::get_stackerdb_chunks();
    let old_updates_count = stackerdb_events
        .iter()
        .map(|ev| ev.modified_slots.iter())
        .flatten()
        .filter(|chunk| {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                return false;
            };
            let SignerMessage::BlockResponse(BlockResponse::Accepted(accepted)) = message else {
                return false;
            };
            accepted.response_data.version == 3
        })
        .count();
    let new_updates_count = stackerdb_events
        .iter()
        .map(|ev| ev.modified_slots.iter())
        .flatten()
        .filter(|chunk| {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                return false;
            };
            let SignerMessage::BlockResponse(BlockResponse::Accepted(accepted)) = message else {
                return false;
            };
            accepted.response_data.version == 4
        })
        .count();

    info!("--------------- Sent {old_updates_count} Old Responses ---------------");
    info!("--------------- Sent {new_updates_count} New Responses ---------------");
    assert_ne!(
        old_updates_count, 0,
        "Expected some signers to be configured to support only the old protocol version"
    );
    assert!(
        new_updates_count > old_updates_count,
        "Expected a majority of signers to be configured to support the new protocol version"
    );
    info!(
        "Final chain info: {:#?}",
        get_chain_info(&signer_test.running_nodes.conf)
    );
}

#[test]
#[ignore] // Remove when ready to run in CI
/// Test with 40% new signers and 60% old signers that the chain still progresses
/// with ALL signers signing the proposed blocks.
fn mixed_signer_set_40_percent_new_60_percent_old() {
    // We want: 40% new (current), 60% old (v3.3.0.0.4)
    // Let's use 10 signers total for clean percentages: 4 new, 6 old
    assert!(
        OldSupportedVersion < NewSupportedVersion,
        "Test setup error: old supported version should be less than new supported version"
    );
    let num_signers = 10;
    let num_new_signers = 4; // 40%
    let num_old_signers = 6; // 60%

    // Let's just do 3 tenures
    let nmb_tenures = 3;

    let btc_miner_seed = vec![2, 2, 2, 2];
    let btc_miner_pk = Keychain::default(btc_miner_seed.clone()).get_pub_key();

    let localhost = "127.0.0.1";
    let node_rpc_port = 30500;
    let node_p2p_port = 30501;

    // Custom signer config: decide old vs new based on signer index
    let signer_test: SignerTest<MultiverSpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![],
        |signer_config| {
            // Use port to determine version: even port -> current (new), odd -> old
            // Initially the signer port number is simply sequential
            let signer_index = signer_config.endpoint.port() % num_signers as u16;
            // Update the ports to enforce versioning
            let base_port = 40000 + signer_index * 10;
            let endpoint_port = if signer_index < num_new_signers as u16 {
                signer_config.supported_signer_protocol_version = NewSupportedVersion;
                base_port // even: new version
            } else {
                signer_config.supported_signer_protocol_version = OldSupportedVersion;
                base_port + 1 // odd: old version
            };
            signer_config.endpoint = format!("{localhost}:{endpoint_port}").parse().unwrap();
        },
        |node_config| {
            node_config.node.rpc_bind = format!("{localhost}:{node_rpc_port}");
            node_config.node.p2p_bind = format!("{localhost}:{node_p2p_port}");
            node_config.node.data_url = format!("http://{localhost}:{node_rpc_port}");
            node_config.node.p2p_address = format!("{localhost}:{node_p2p_port}");

            node_config.node.seed = btc_miner_seed.clone();
            node_config.node.local_peer_seed = btc_miner_seed.clone();
            node_config.burnchain.local_mining_public_key = Some(btc_miner_pk.to_hex());

            node_config.miner.wait_on_interim_blocks = Some(Duration::from_secs(10));
            node_config.burnchain.pox_reward_length = Some(30);
            node_config.node.pox_sync_sample_secs = 30;
        },
        Some(vec![btc_miner_pk.clone()]),
        None,
    );
    info!("--------------- Started mixed signer test: {num_new_signers} new, {num_old_signers} old signers ---------------");
    // Boot to Nakamoto (Epoch 3.0)
    signer_test.boot_to_epoch_3();
    let start_chain = get_chain_info(&signer_test.running_nodes.conf);
    test_observer::clear();

    // Mine several Nakamoto tenures to trigger signing rounds
    for tenure in 1..=nmb_tenures {
        info!("--------------- Mining Nakamoto tenure #{tenure} ---------------");

        // Mine a tenure-start block (should trigger signer voting)
        signer_test.mine_nakamoto_block(Duration::from_secs(60), false);
    }
    // Wait for all signatures to come in from every signer per tenure
    wait_for(60, || {
        let stackerdb_events = test_observer::get_stackerdb_chunks();
        let nmb_signatures = stackerdb_events
            .iter()
            .map(|ev| ev.modified_slots.iter())
            .flatten()
            .filter_map(|chunk| {
                let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                else {
                    return None;
                };
                let SignerMessage::BlockResponse(BlockResponse::Accepted(accepted)) = message
                else {
                    return None;
                };
                Some(accepted)
            })
            .count();
        Ok(nmb_signatures >= num_signers * nmb_tenures)
    })
    .expect("Expected every signer to sign every tenure-start block");
    // Now analyze stackerdb events to count old vs new BlockResponse versions
    let stackerdb_events = test_observer::get_stackerdb_chunks();
    let state_machine_updates = stackerdb_events
        .iter()
        .map(|ev| ev.modified_slots.iter())
        .flatten()
        .filter_map(|chunk| {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                return None;
            };
            let SignerMessage::StateMachineUpdate(update) = message else {
                return None;
            };
            Some(update)
        })
        .collect::<Vec<_>>();
    info!("--------------- StackerDB State Machine Updates ---------------");
    let nmb_old_versions = state_machine_updates
        .iter()
        .filter(|update| update.local_supported_signer_protocol_version == OldSupportedVersion)
        .count();
    let nmb_current_versions = state_machine_updates
        .iter()
        .filter(|update| update.local_supported_signer_protocol_version == NewSupportedVersion)
        .count();
    assert!(
        nmb_old_versions >= state_machine_updates.len() * 6 / 10,
        "Expected 60% of signers to be configured to support only the old protocol version"
    );
    assert!(
        nmb_current_versions >= state_machine_updates.len() * 4 / 10,
        "Expected 40% of signers to be configured to support the new protocol version"
    );

    let end_chain = get_chain_info(&signer_test.running_nodes.conf);
    info!("Final chain info: {end_chain:#?}",);

    assert_eq!(
        end_chain.burn_block_height,
        start_chain.burn_block_height + nmb_tenures as u64,
        "Chain should have progressed by {nmb_tenures} burn blocks"
    );
    assert_eq!(
        end_chain.stacks_tip_height,
        start_chain.stacks_tip_height + nmb_tenures as u64,
        "Chain should have progressed by {nmb_tenures} stacks blocks",
    );
    assert_ne!(end_chain.stacks_tip, start_chain.stacks_tip);
}

#[test]
#[ignore] // Remove when ready to run in CI
/// Test with 80% new signers and 20% old signers that the chain still progresses
/// with ALL signers signing the proposed blocks.
fn mixed_signer_set_80_percent_new_20_percent_old() {
    // We want: 80% new (current), 20% old (v3.3.0.0.4)
    // Let's use 10 signers total for clean percentages: 8 new, 2 old
    assert!(
        OldSupportedVersion < NewSupportedVersion,
        "Test setup error: old supported version should be less than new supported version"
    );
    let num_signers = 10;
    let num_new_signers = 8; // 80%
    let num_old_signers = 2; // 20%

    // Let's just do 3 tenures
    let nmb_tenures = 3;

    let btc_miner_seed = vec![2, 2, 2, 2];
    let btc_miner_pk = Keychain::default(btc_miner_seed.clone()).get_pub_key();

    let localhost = "127.0.0.1";
    let node_rpc_port = 30500;
    let node_p2p_port = 30501;

    // Custom signer config: decide old vs new based on signer index
    let signer_test: SignerTest<MultiverSpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![],
        |signer_config| {
            // Use port to determine version: even port -> current (new), odd -> old
            // Initially the signer port number is simply sequential
            let signer_index = signer_config.endpoint.port() % num_signers as u16;
            // Update the ports to enforce versioning
            let base_port = 40000 + signer_index * 10;
            let endpoint_port = if signer_index < num_new_signers as u16 {
                signer_config.supported_signer_protocol_version = NewSupportedVersion;
                base_port // even: new version
            } else {
                signer_config.supported_signer_protocol_version = OldSupportedVersion;
                base_port + 1 // odd: old version
            };
            signer_config.endpoint = format!("{localhost}:{endpoint_port}").parse().unwrap();
        },
        |node_config| {
            node_config.node.rpc_bind = format!("{localhost}:{node_rpc_port}");
            node_config.node.p2p_bind = format!("{localhost}:{node_p2p_port}");
            node_config.node.data_url = format!("http://{localhost}:{node_rpc_port}");
            node_config.node.p2p_address = format!("{localhost}:{node_p2p_port}");

            node_config.node.seed = btc_miner_seed.clone();
            node_config.node.local_peer_seed = btc_miner_seed.clone();
            node_config.burnchain.local_mining_public_key = Some(btc_miner_pk.to_hex());

            node_config.miner.wait_on_interim_blocks = Some(Duration::from_secs(10));
            node_config.burnchain.pox_reward_length = Some(30);
            node_config.node.pox_sync_sample_secs = 30;
        },
        Some(vec![btc_miner_pk.clone()]),
        None,
    );
    info!("--------------- Started mixed signer test: {num_new_signers} new, {num_old_signers} old signers ---------------");
    // Boot to Nakamoto (Epoch 3.0)
    signer_test.boot_to_epoch_3();
    let start_chain = get_chain_info(&signer_test.running_nodes.conf);
    test_observer::clear();

    // Mine several Nakamoto tenures to trigger signing rounds
    for tenure in 1..=nmb_tenures {
        info!("--------------- Mining Nakamoto tenure #{tenure} ---------------");

        // Mine a tenure-start block (should trigger signer voting)
        signer_test.mine_nakamoto_block(Duration::from_secs(60), false);
    }
    // Wait for all signatures to come in from every signer per tenure
    wait_for(60, || {
        let stackerdb_events = test_observer::get_stackerdb_chunks();
        let nmb_signatures = stackerdb_events
            .iter()
            .map(|ev| ev.modified_slots.iter())
            .flatten()
            .filter_map(|chunk| {
                let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                else {
                    return None;
                };
                let SignerMessage::BlockResponse(BlockResponse::Accepted(accepted)) = message
                else {
                    return None;
                };
                Some(accepted)
            })
            .count();
        Ok(nmb_signatures >= num_signers * nmb_tenures)
    })
    .expect("Expected every signer to sign every tenure-start block");
    // Now analyze stackerdb events to count old vs new BlockResponse versions
    let stackerdb_events = test_observer::get_stackerdb_chunks();
    let state_machine_updates = stackerdb_events
        .iter()
        .map(|ev| ev.modified_slots.iter())
        .flatten()
        .filter_map(|chunk| {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                return None;
            };
            let SignerMessage::StateMachineUpdate(update) = message else {
                return None;
            };
            Some(update)
        })
        .collect::<Vec<_>>();
    info!("--------------- StackerDB State Machine Updates ---------------");
    let nmb_old_versions = state_machine_updates
        .iter()
        .filter(|update| update.local_supported_signer_protocol_version == OldSupportedVersion)
        .count();
    let nmb_current_versions = state_machine_updates
        .iter()
        .filter(|update| update.local_supported_signer_protocol_version == NewSupportedVersion)
        .count();
    assert!(
        nmb_old_versions >= state_machine_updates.len() * 2 / 10,
        "Expected 20% of signers to be configured to support only the old protocol version"
    );
    assert!(
        nmb_current_versions >= state_machine_updates.len() * 8 / 10,
        "Expected 80% of signers to be configured to support the new protocol version"
    );

    let end_chain = get_chain_info(&signer_test.running_nodes.conf);
    info!("Final chain info: {end_chain:#?}",);

    assert_eq!(
        end_chain.burn_block_height,
        start_chain.burn_block_height + nmb_tenures as u64,
        "Chain should have progressed by {nmb_tenures} burn blocks"
    );
    assert_eq!(
        end_chain.stacks_tip_height,
        start_chain.stacks_tip_height + nmb_tenures as u64,
        "Chain should have progressed by {nmb_tenures} stacks blocks",
    );
    assert_ne!(end_chain.stacks_tip, start_chain.stacks_tip);
}
