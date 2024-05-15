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

/// The stacker db module for communicating with the stackerdb contract
mod stackerdb;
/// The stacks node client module for communicating with the stacks node
pub(crate) mod stacks_client;

use std::time::Duration;

use clarity::vm::errors::Error as ClarityError;
use clarity::vm::types::serialization::SerializationError;
use libstackerdb::Error as StackerDBError;
use slog::slog_debug;
pub use stackerdb::*;
pub use stacks_client::*;
use stacks_common::codec::Error as CodecError;
use stacks_common::debug;

/// Backoff timer initial interval in milliseconds
const BACKOFF_INITIAL_INTERVAL: u64 = 128;
/// Backoff timer max interval in milliseconds
const BACKOFF_MAX_INTERVAL: u64 = 16384;

#[derive(thiserror::Error, Debug)]
/// Client error type
pub enum ClientError {
    /// Error for when a response's format does not match the expected structure
    #[error("Unexpected response format: {0}")]
    UnexpectedResponseFormat(String),
    /// An error occurred serializing the message
    #[error("Unable to serialize stacker-db message: {0}")]
    StackerDBSerializationError(#[from] CodecError),
    /// Failed to sign stacker-db chunk
    #[error("Failed to sign stacker-db chunk: {0}")]
    FailToSign(#[from] StackerDBError),
    /// Stacker-db instance rejected the chunk
    #[error("Stacker-db rejected the chunk. Reason: {0}")]
    PutChunkRejected(String),
    /// Failed to call a read only function
    #[error("Failed to call read only function. {0}")]
    ReadOnlyFailure(String),
    /// Reqwest specific error occurred
    #[error("{0}")]
    ReqwestError(#[from] reqwest::Error),
    /// Failed to build and sign a new Stacks transaction.
    #[error("Failed to generate transaction from a transaction signer: {0}")]
    TransactionGenerationFailure(String),
    /// Stacks node client request failed
    #[error("Stacks node client request failed: {0}")]
    RequestFailure(reqwest::StatusCode),
    /// Failed to serialize a Clarity value
    #[error("Failed to serialize Clarity value: {0}")]
    ClaritySerializationError(#[from] SerializationError),
    /// Failed to parse a Clarity value
    #[error("Received a malformed clarity value: {0}")]
    MalformedClarityValue(String),
    /// Backoff retry timeout
    #[error("Backoff retry timeout occurred. Stacks node may be down.")]
    RetryTimeout,
    /// Not connected
    #[error("Not connected")]
    NotConnected,
    /// Clarity interpreter error
    #[error("Clarity interpreter error: {0}")]
    ClarityError(#[from] ClarityError),
    /// Malformed reward set
    #[error("Malformed contract data: {0}")]
    MalformedContractData(String),
    /// Stacks node does not support a feature we need
    #[error("Stacks node does not support a required feature: {0}")]
    UnsupportedStacksFeature(String),
    /// Invalid response from the stacks node
    #[error("Invalid response from the stacks node: {0}")]
    InvalidResponse(String),
}

/// Retry a function F with an exponential backoff and notification on transient failure
pub fn retry_with_exponential_backoff<F, E, T>(request_fn: F) -> Result<T, ClientError>
where
    F: FnMut() -> Result<T, backoff::Error<E>>,
    E: std::fmt::Debug,
{
    let notify = |err, dur| {
        debug!(
            "Failed to connect to stacks node and/or deserialize its response: {err:?}. Next attempt in {dur:?}"
        );
    };

    let backoff_timer = backoff::ExponentialBackoffBuilder::new()
        .with_initial_interval(Duration::from_millis(BACKOFF_INITIAL_INTERVAL))
        .with_max_interval(Duration::from_millis(BACKOFF_MAX_INTERVAL))
        .build();

    backoff::retry_notify(backoff_timer, request_fn, notify).map_err(|_| ClientError::RetryTimeout)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};

    use blockstack_lib::chainstate::stacks::boot::POX_4_NAME;
    use blockstack_lib::net::api::getaccount::AccountEntryResponse;
    use blockstack_lib::net::api::getinfo::RPCPeerInfoData;
    use blockstack_lib::net::api::getpoxinfo::{
        RPCPoxCurrentCycleInfo, RPCPoxEpoch, RPCPoxInfoData, RPCPoxNextCycleInfo,
    };
    use blockstack_lib::net::api::postfeerate::{RPCFeeEstimate, RPCFeeEstimateResponse};
    use blockstack_lib::util_lib::boot::boot_code_id;
    use clarity::vm::costs::ExecutionCost;
    use clarity::vm::types::TupleData;
    use clarity::vm::Value as ClarityValue;
    use hashbrown::{HashMap, HashSet};
    use libsigner::SignerEntries;
    use rand::distributions::Standard;
    use rand::{thread_rng, Rng};
    use rand_core::{OsRng, RngCore};
    use stacks_common::types::chainstate::{
        BlockHeaderHash, ConsensusHash, StacksAddress, StacksPrivateKey, StacksPublicKey,
    };
    use stacks_common::types::{StacksEpochId, StacksPublicKeyBuffer};
    use stacks_common::util::hash::{Hash160, Sha256Sum};
    use wsts::curve::ecdsa;
    use wsts::curve::point::{Compressed, Point};
    use wsts::curve::scalar::Scalar;
    use wsts::state_machine::PublicKeys;

    use super::*;
    use crate::config::{GlobalConfig, SignerConfig};

    pub struct MockServerClient {
        pub server: TcpListener,
        pub client: StacksClient,
        pub config: GlobalConfig,
    }

    impl MockServerClient {
        /// Construct a new MockServerClient on a random port
        pub fn new() -> Self {
            let mut config =
                GlobalConfig::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
            let (server, mock_server_addr) = mock_server_random();
            config.node_host = mock_server_addr.to_string();

            let client = StacksClient::from(&config);
            Self {
                server,
                client,
                config,
            }
        }

        /// Construct a new MockServerClient on the port specified in the config
        pub fn from_config(config: GlobalConfig) -> Self {
            let server = mock_server_from_config(&config);
            let client = StacksClient::from(&config);
            Self {
                server,
                client,
                config,
            }
        }
    }

    /// Create a mock server on a random port and return the socket addr
    pub fn mock_server_random() -> (TcpListener, SocketAddr) {
        let mut mock_server_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        // Ask the OS to assign a random port to listen on by passing 0
        let server = TcpListener::bind(mock_server_addr).unwrap();

        mock_server_addr.set_port(server.local_addr().unwrap().port());
        (server, mock_server_addr)
    }

    /// Create a mock server on a same port as in the config
    pub fn mock_server_from_config(config: &GlobalConfig) -> TcpListener {
        TcpListener::bind(config.node_host.to_string()).unwrap()
    }

    /// Write a response to the mock server and return the request bytes
    pub fn write_response(mock_server: TcpListener, bytes: &[u8]) -> [u8; 1024] {
        debug!("Writing a response...");
        let mut request_bytes = [0u8; 1024];
        {
            let mut stream = mock_server.accept().unwrap().0;
            let _ = stream.read(&mut request_bytes).unwrap();
            stream.write_all(bytes).unwrap();
        }
        request_bytes
    }

    pub fn generate_random_consensus_hash() -> ConsensusHash {
        let rng = rand::thread_rng();
        let bytes: Vec<u8> = rng.sample_iter(Standard).take(20).collect();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&bytes);
        ConsensusHash(hash)
    }

    /// Build a response for the get_last_round request
    pub fn build_get_last_round_response(round: u64) -> String {
        let value = ClarityValue::some(ClarityValue::UInt(round as u128))
            .expect("Failed to create response");
        build_read_only_response(&value)
    }

    /// Build a response for the get_account_nonce request
    pub fn build_account_nonce_response(nonce: u64) -> String {
        let account_nonce_entry = AccountEntryResponse {
            nonce,
            balance: "0x00000000000000000000000000000000".to_string(),
            locked: "0x00000000000000000000000000000000".to_string(),
            unlock_height: thread_rng().next_u64(),
            balance_proof: None,
            nonce_proof: None,
        };
        let account_nonce_entry_json = serde_json::to_string(&account_nonce_entry)
            .expect("Failed to serialize account nonce entry");
        format!("HTTP/1.1 200 OK\n\n{account_nonce_entry_json}")
    }

    /// Build a response to get_pox_data_with_retry where it returns a specific reward cycle id and block height
    pub fn build_get_pox_data_response(
        reward_cycle: Option<u64>,
        prepare_phase_start_height: Option<u64>,
        epoch_25_activation_height: Option<u64>,
        epoch_30_activation_height: Option<u64>,
    ) -> (String, RPCPoxInfoData) {
        // Populate some random data!
        let epoch_25_start = epoch_25_activation_height.unwrap_or(thread_rng().next_u64());
        let epoch_30_start =
            epoch_30_activation_height.unwrap_or(epoch_25_start.saturating_add(1000));
        let current_id = reward_cycle.unwrap_or(thread_rng().next_u64());
        let next_id = current_id.saturating_add(1);
        let pox_info = RPCPoxInfoData {
            contract_id: boot_code_id(POX_4_NAME, false).to_string(),
            pox_activation_threshold_ustx: thread_rng().next_u64(),
            first_burnchain_block_height: thread_rng().next_u64(),
            current_burnchain_block_height: thread_rng().next_u64(),
            prepare_phase_block_length: thread_rng().next_u64(),
            reward_phase_block_length: thread_rng().next_u64(),
            reward_slots: thread_rng().next_u64(),
            rejection_fraction: None,
            total_liquid_supply_ustx: thread_rng().next_u64(),
            current_cycle: RPCPoxCurrentCycleInfo {
                id: current_id,
                min_threshold_ustx: thread_rng().next_u64(),
                stacked_ustx: thread_rng().next_u64(),
                is_pox_active: true,
            },
            next_cycle: RPCPoxNextCycleInfo {
                id: next_id,
                min_threshold_ustx: thread_rng().next_u64(),
                min_increment_ustx: thread_rng().next_u64(),
                stacked_ustx: thread_rng().next_u64(),
                prepare_phase_start_block_height: prepare_phase_start_height
                    .unwrap_or(thread_rng().next_u64()),
                blocks_until_prepare_phase: thread_rng().next_u32() as i64,
                reward_phase_start_block_height: thread_rng().next_u64(),
                blocks_until_reward_phase: thread_rng().next_u64(),
                ustx_until_pox_rejection: None,
            },
            min_amount_ustx: thread_rng().next_u64(),
            prepare_cycle_length: thread_rng().next_u64(),
            reward_cycle_id: current_id,
            epochs: vec![
                RPCPoxEpoch {
                    start_height: epoch_25_start,
                    end_height: epoch_30_start,
                    block_limit: ExecutionCost {
                        write_length: thread_rng().next_u64(),
                        write_count: thread_rng().next_u64(),
                        read_length: thread_rng().next_u64(),
                        read_count: thread_rng().next_u64(),
                        runtime: thread_rng().next_u64(),
                    },
                    epoch_id: StacksEpochId::Epoch25,
                    network_epoch: 0,
                },
                RPCPoxEpoch {
                    start_height: epoch_30_start,
                    end_height: epoch_30_start.saturating_add(1000),
                    block_limit: ExecutionCost {
                        write_length: thread_rng().next_u64(),
                        write_count: thread_rng().next_u64(),
                        read_length: thread_rng().next_u64(),
                        read_count: thread_rng().next_u64(),
                        runtime: thread_rng().next_u64(),
                    },
                    epoch_id: StacksEpochId::Epoch30,
                    network_epoch: 0,
                },
            ],
            reward_cycle_length: thread_rng().next_u64(),
            rejection_votes_left_required: None,
            next_reward_cycle_in: thread_rng().next_u64(),
            contract_versions: vec![],
        };
        let pox_info_json = serde_json::to_string(&pox_info).expect("Failed to serialize pox info");
        (format!("HTTP/1.1 200 Ok\n\n{pox_info_json}"), pox_info)
    }

    /// Build a response for the get_approved_aggregate_key request
    pub fn build_get_approved_aggregate_key_response(point: Option<Point>) -> String {
        let clarity_value = if let Some(point) = point {
            ClarityValue::some(
                ClarityValue::buff_from(point.compress().as_bytes().to_vec())
                    .expect("BUG: Failed to create clarity value from point"),
            )
            .expect("BUG: Failed to create clarity value from point")
        } else {
            ClarityValue::none()
        };
        build_read_only_response(&clarity_value)
    }

    /// Build a response for the get_approved_aggregate_key request
    pub fn build_get_vote_for_aggregate_key_response(point: Option<Point>) -> String {
        let clarity_value = if let Some(point) = point {
            ClarityValue::some(ClarityValue::Tuple(
                TupleData::from_data(vec![
                    (
                        "aggregate-public-key".into(),
                        ClarityValue::buff_from(point.compress().as_bytes().to_vec())
                            .expect("BUG: Failed to create clarity value from point"),
                    ),
                    ("signer-weight".into(), ClarityValue::UInt(1)), // fixed for testing purposes
                ])
                .expect("BUG: Failed to create clarity value from tuple data"),
            ))
            .expect("BUG: Failed to create clarity value from tuple data")
        } else {
            ClarityValue::none()
        };
        build_read_only_response(&clarity_value)
    }

    /// Build a response for the get_peer_info_with_retry request with a specific stacks tip height and consensus hash
    pub fn build_get_peer_info_response(
        burn_block_height: Option<u64>,
        pox_consensus_hash: Option<ConsensusHash>,
    ) -> (String, RPCPeerInfoData) {
        // Generate some random info
        let private_key = StacksPrivateKey::new();
        let public_key = StacksPublicKey::from_private(&private_key);
        let public_key_buf = StacksPublicKeyBuffer::from_public_key(&public_key);
        let public_key_hash = Hash160::from_node_public_key(&public_key);
        let stackerdb_contract_ids =
            vec![boot_code_id("fake", false), boot_code_id("fake_2", false)];
        let peer_info = RPCPeerInfoData {
            peer_version: thread_rng().next_u32(),
            pox_consensus: pox_consensus_hash.unwrap_or(generate_random_consensus_hash()),
            burn_block_height: burn_block_height.unwrap_or(thread_rng().next_u64()),
            stable_pox_consensus: generate_random_consensus_hash(),
            stable_burn_block_height: 2,
            server_version: "fake version".to_string(),
            network_id: thread_rng().next_u32(),
            parent_network_id: thread_rng().next_u32(),
            stacks_tip_height: thread_rng().next_u64(),
            stacks_tip: BlockHeaderHash([0x06; 32]),
            stacks_tip_consensus_hash: generate_random_consensus_hash(),
            unanchored_tip: None,
            unanchored_seq: Some(0),
            exit_at_block_height: None,
            genesis_chainstate_hash: Sha256Sum::zero(),
            node_public_key: Some(public_key_buf),
            node_public_key_hash: Some(public_key_hash),
            affirmations: None,
            last_pox_anchor: None,
            stackerdbs: Some(
                stackerdb_contract_ids
                    .into_iter()
                    .map(|cid| format!("{}", cid))
                    .collect(),
            ),
        };
        let peer_info_json =
            serde_json::to_string(&peer_info).expect("Failed to serialize peer info");
        (format!("HTTP/1.1 200 OK\n\n{peer_info_json}"), peer_info)
    }

    /// Build a response to a read only clarity contract call
    pub fn build_read_only_response(value: &ClarityValue) -> String {
        let hex = value
            .serialize_to_hex()
            .expect("Failed to serialize hex value");
        format!("HTTP/1.1 200 OK\n\n{{\"okay\":true,\"result\":\"{hex}\"}}")
    }

    /// Build a response for the get_medium_estimated_fee_ustx_response request with a specific medium estimate
    pub fn build_get_medium_estimated_fee_ustx_response(
        medium_estimate: u64,
    ) -> (String, RPCFeeEstimateResponse) {
        // Generate some random info
        let fee_response = RPCFeeEstimateResponse {
            estimated_cost: ExecutionCost {
                write_length: thread_rng().next_u64(),
                write_count: thread_rng().next_u64(),
                read_length: thread_rng().next_u64(),
                read_count: thread_rng().next_u64(),
                runtime: thread_rng().next_u64(),
            },
            estimated_cost_scalar: thread_rng().next_u64(),
            cost_scalar_change_by_byte: thread_rng().next_u32() as f64,
            estimations: vec![
                RPCFeeEstimate {
                    fee_rate: thread_rng().next_u32() as f64,
                    fee: thread_rng().next_u64(),
                },
                RPCFeeEstimate {
                    fee_rate: thread_rng().next_u32() as f64,
                    fee: medium_estimate,
                },
                RPCFeeEstimate {
                    fee_rate: thread_rng().next_u32() as f64,
                    fee: thread_rng().next_u64(),
                },
            ],
        };
        let fee_response_json = serde_json::to_string(&fee_response)
            .expect("Failed to serialize fee estimate response");
        (
            format!("HTTP/1.1 200 OK\n\n{fee_response_json}"),
            fee_response,
        )
    }

    /// Generate a signer config with the given number of signers and keys where the first signer is
    /// obtained from the provided global config
    pub fn generate_signer_config(
        config: &GlobalConfig,
        num_signers: u32,
        num_keys: u32,
    ) -> SignerConfig {
        assert!(
            num_signers > 0,
            "Cannot generate 0 signers...Specify at least 1 signer."
        );
        assert!(
            num_keys > 0,
            "Cannot generate 0 keys for the provided signers...Specify at least 1 key."
        );
        let mut public_keys = PublicKeys {
            signers: HashMap::new(),
            key_ids: HashMap::new(),
        };
        let reward_cycle = thread_rng().next_u64();
        let rng = &mut OsRng;
        let num_keys = num_keys / num_signers;
        let remaining_keys = num_keys % num_signers;
        let mut coordinator_key_ids = HashMap::new();
        let mut signer_key_ids = HashMap::new();
        let mut signer_ids = HashMap::new();
        let mut start_key_id = 1u32;
        let mut end_key_id = start_key_id;
        let mut signer_public_keys = HashMap::new();
        let mut signer_slot_ids = vec![];
        let ecdsa_private_key = config.ecdsa_private_key;
        let ecdsa_public_key =
            ecdsa::PublicKey::new(&ecdsa_private_key).expect("Failed to create ecdsa public key");
        // Key ids start from 1 hence the wrapping adds everywhere
        for signer_id in 0..num_signers {
            end_key_id = if signer_id.wrapping_add(1) == num_signers {
                end_key_id.wrapping_add(remaining_keys)
            } else {
                end_key_id.wrapping_add(num_keys)
            };
            if signer_id == 0 {
                public_keys.signers.insert(signer_id, ecdsa_public_key);
                let signer_public_key =
                    Point::try_from(&Compressed::from(ecdsa_public_key.to_bytes())).unwrap();
                signer_public_keys.insert(signer_id, signer_public_key);
                public_keys.signers.insert(signer_id, ecdsa_public_key);
                for k in start_key_id..end_key_id {
                    public_keys.key_ids.insert(k, ecdsa_public_key);
                    coordinator_key_ids
                        .entry(signer_id)
                        .or_insert(HashSet::new())
                        .insert(k);
                    signer_key_ids
                        .entry(signer_id)
                        .or_insert(Vec::new())
                        .push(k);
                }
                start_key_id = end_key_id;
                let address = StacksAddress::p2pkh(
                    false,
                    &StacksPublicKey::from_slice(ecdsa_public_key.to_bytes().as_slice())
                        .expect("Failed to create stacks public key"),
                );
                signer_slot_ids.push(SignerSlotID(signer_id));
                signer_ids.insert(address, signer_id);

                continue;
            }
            let private_key = Scalar::random(rng);
            let public_key = ecdsa::PublicKey::new(&private_key).unwrap();
            let signer_public_key =
                Point::try_from(&Compressed::from(public_key.to_bytes())).unwrap();
            signer_public_keys.insert(signer_id, signer_public_key);
            public_keys.signers.insert(signer_id, public_key);
            for k in start_key_id..end_key_id {
                public_keys.key_ids.insert(k, public_key);
                coordinator_key_ids
                    .entry(signer_id)
                    .or_insert(HashSet::new())
                    .insert(k);
                signer_key_ids
                    .entry(signer_id)
                    .or_insert(Vec::new())
                    .push(k);
            }
            let address = StacksAddress::p2pkh(
                false,
                &StacksPublicKey::from_slice(public_key.to_bytes().as_slice())
                    .expect("Failed to create stacks public key"),
            );
            signer_slot_ids.push(SignerSlotID(signer_id));
            signer_ids.insert(address, signer_id);
            start_key_id = end_key_id;
        }
        SignerConfig {
            reward_cycle,
            signer_id: 0,
            signer_slot_id: SignerSlotID(rand::thread_rng().gen_range(0..num_signers)), // Give a random signer slot id between 0 and num_signers
            key_ids: signer_key_ids.get(&0).cloned().unwrap_or_default(),
            signer_entries: SignerEntries {
                public_keys,
                coordinator_key_ids,
                signer_key_ids,
                signer_ids,
                signer_public_keys,
            },
            signer_slot_ids,
            ecdsa_private_key: config.ecdsa_private_key,
            stacks_private_key: config.stacks_private_key,
            node_host: config.node_host.to_string(),
            mainnet: config.network.is_mainnet(),
            dkg_end_timeout: config.dkg_end_timeout,
            dkg_private_timeout: config.dkg_private_timeout,
            dkg_public_timeout: config.dkg_public_timeout,
            nonce_timeout: config.nonce_timeout,
            sign_timeout: config.sign_timeout,
            tx_fee_ustx: config.tx_fee_ustx,
            max_tx_fee_ustx: config.max_tx_fee_ustx,
            db_path: config.db_path.clone(),
        }
    }

    pub fn build_get_round_info_response(info: Option<(u64, u64)>) -> String {
        let clarity_value = if let Some((vote_count, vote_weight)) = info {
            ClarityValue::some(ClarityValue::Tuple(
                TupleData::from_data(vec![
                    ("votes-count".into(), ClarityValue::UInt(vote_count as u128)),
                    (
                        "votes-weight".into(),
                        ClarityValue::UInt(vote_weight as u128),
                    ),
                ])
                .expect("BUG: Failed to create clarity value from tuple data"),
            ))
            .expect("BUG: Failed to create clarity value from tuple data")
        } else {
            ClarityValue::none()
        };
        build_read_only_response(&clarity_value)
    }

    pub fn build_get_weight_threshold_response(threshold: u64) -> String {
        let clarity_value = ClarityValue::UInt(threshold as u128);
        build_read_only_response(&clarity_value)
    }
}
