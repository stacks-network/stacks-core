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
use libsigner::RPCError;
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
    /// Failed to write to stacker-db due to RPC error
    #[error("Failed to write to stacker-db instance: {0}")]
    PutChunkFailed(#[from] RPCError),
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
    /// Invalid Clarity Name
    #[error("Invalid Clarity Name: {0}")]
    InvalidClarityName(String),
    /// Backoff retry timeout
    #[error("Backoff retry timeout occurred. Stacks node may be down.")]
    RetryTimeout,
    /// Not connected
    #[error("Not connected")]
    NotConnected,
    /// Invalid signing key
    #[error("Signing key not represented in the list of signers")]
    InvalidSigningKey,
    /// Clarity interpreter error
    #[error("Clarity interpreter error: {0}")]
    ClarityError(#[from] ClarityError),
    /// Our stacks address does not belong to a registered signer
    #[error("Our stacks address does not belong to a registered signer")]
    NotRegistered,
    /// Reward set not yet calculated for the given reward cycle
    #[error("Reward set not yet calculated for reward cycle: {0}")]
    RewardSetNotYetCalculated(u64),
    /// Malformed reward set
    #[error("Malformed contract data: {0}")]
    MalformedContractData(String),
    /// No reward set exists for the given reward cycle
    #[error("No reward set exists for reward cycle {0}")]
    NoRewardSet(u64),
    /// Reward set contained corrupted data
    #[error("{0}")]
    CorruptedRewardSet(String),
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

    use clarity::vm::Value as ClarityValue;
    use hashbrown::{HashMap, HashSet};
    use rand::thread_rng;
    use rand_core::{OsRng, RngCore};
    use stacks_common::types::chainstate::{StacksAddress, StacksPublicKey};
    use wsts::curve::ecdsa;
    use wsts::curve::point::{Compressed, Point};
    use wsts::curve::scalar::Scalar;
    use wsts::state_machine::PublicKeys;

    use super::*;
    use crate::config::{GlobalConfig, RewardCycleConfig};

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
            config.node_host = mock_server_addr;

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
        TcpListener::bind(config.node_host).unwrap()
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

    /// Build a response for the get_last_round request
    pub fn build_get_last_round_response(round: u64) -> String {
        let value = ClarityValue::okay(ClarityValue::UInt(round as u128))
            .expect("Failed to create response");
        build_read_only_response(&value)
    }

    /// Build a response for the get_account_nonce request
    pub fn build_account_nonce_response(nonce: u64) -> String {
        format!("HTTP/1.1 200 OK\n\n{{\"nonce\":{nonce},\"balance\":\"0x00000000000000000000000000000000\",\"locked\":\"0x00000000000000000000000000000000\",\"unlock_height\":0}}")
    }

    /// Build a response to get_pox_data where it returns a specific reward cycle id and block height
    pub fn build_get_pox_data_response(
        reward_cycle: u64,
        prepare_phase_start_block_height: u64,
    ) -> String {
        format!("HTTP/1.1 200 Ok\n\n{{\"contract_id\":\"ST000000000000000000002AMW42H.pox-3\",\"pox_activation_threshold_ustx\":829371801288885,\"first_burnchain_block_height\":2000000,\"current_burnchain_block_height\":2572192,\"prepare_phase_block_length\":50,\"reward_phase_block_length\":1000,\"reward_slots\":2000,\"rejection_fraction\":12,\"total_liquid_supply_ustx\":41468590064444294,\"current_cycle\":{{\"id\":544,\"min_threshold_ustx\":5190000000000,\"stacked_ustx\":853258144644000,\"is_pox_active\":true}},\"next_cycle\":{{\"id\":545,\"min_threshold_ustx\":5190000000000,\"min_increment_ustx\":5183573758055,\"stacked_ustx\":847278759574000,\"prepare_phase_start_block_height\":{prepare_phase_start_block_height},\"blocks_until_prepare_phase\":8,\"reward_phase_start_block_height\":2572250,\"blocks_until_reward_phase\":58,\"ustx_until_pox_rejection\":4976230807733304}},\"min_amount_ustx\":5190000000000,\"prepare_cycle_length\":50,\"reward_cycle_id\":{reward_cycle},\"reward_cycle_length\":1050,\"rejection_votes_left_required\":4976230807733304,\"next_reward_cycle_in\":58,\"contract_versions\":[{{\"contract_id\":\"ST000000000000000000002AMW42H.pox\",\"activation_burnchain_block_height\":2000000,\"first_reward_cycle_id\":0}},{{\"contract_id\":\"ST000000000000000000002AMW42H.pox-2\",\"activation_burnchain_block_height\":2422102,\"first_reward_cycle_id\":403}},{{\"contract_id\":\"ST000000000000000000002AMW42H.pox-3\",\"activation_burnchain_block_height\":2432545,\"first_reward_cycle_id\":412}}]}}")
    }

    /// Build a response for the get_aggregate_public_key request
    pub fn build_get_aggregate_public_key_response(point: Point) -> String {
        let clarity_value = ClarityValue::some(
            ClarityValue::buff_from(point.compress().as_bytes().to_vec())
                .expect("BUG: Failed to create clarity value from point"),
        )
        .expect("BUG: Failed to create clarity value from point");
        build_read_only_response(&clarity_value)
    }

    /// Build a response for the get_peer_info request with a specific stacks tip height and consensus hash
    pub fn build_get_peer_info_response(stacks_tip_height: u64, consensus_hash: String) -> String {
        format!(
            "HTTP/1.1 200 OK\n\n{{\"stacks_tip_height\":{stacks_tip_height},\"stacks_tip_consensus_hash\":\"{consensus_hash}\",\"peer_version\":4207599113,\"pox_consensus\":\"64c8c3049ff6b939c65828e3168210e6bb32d880\",\"burn_block_height\":2575799,\"stable_pox_consensus\":\"72277bf9a3b115e13c0942825480d6cee0e9a0e8\",\"stable_burn_block_height\":2575792,\"server_version\":\"stacks-node d657bdd (feat/epoch-2.4:d657bdd, release build, linux [x86_64])\",\"network_id\":2147483648,\"parent_network_id\":118034699,\"stacks_tip\":\"77219884fe434c0fa270d65592b4f082ab3e5d9922ac2bdaac34310aedc3d298\",\"genesis_chainstate_hash\":\"74237aa39aa50a83de11a4f53e9d3bb7d43461d1de9873f402e5453ae60bc59b\",\"unanchored_tip\":\"dde44222b6e6d81583b6b9c55db83e8716943ae9d0dc332fc39448ddd9b99dc2\",\"unanchored_seq\":0,\"exit_at_block_height\":null,\"node_public_key\":\"023c940136d5795d9dd82c0e87f4dd6a2a1db245444e7d70e34bb9605c3c3917b0\",\"node_public_key_hash\":\"e26cce8f6abe06b9fc81c3b11bcc821d2f1b8fd0\"}}",
        )
    }

    /// Build a response to a read only clarity contract call
    pub fn build_read_only_response(value: &ClarityValue) -> String {
        let hex = value
            .serialize_to_hex()
            .expect("Failed to serialize hex value");
        format!("HTTP/1.1 200 OK\n\n{{\"okay\":true,\"result\":\"{hex}\"}}")
    }

    /// Generate a random reward cycle config
    /// Optionally include a signer pubilc key to set as the first signer id with signer id 0 and signer slot id 0
    pub fn generate_reward_cycle_config(
        num_signers: u32,
        num_keys: u32,
        signer_key: Option<ecdsa::PublicKey>,
    ) -> (RewardCycleConfig, Vec<StacksAddress>) {
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
        let signer_set = u32::try_from(reward_cycle % 2)
            .expect("Failed to convert reward cycle signer set to u32");
        let rng = &mut OsRng;
        let num_keys = num_keys / num_signers;
        let remaining_keys = num_keys % num_signers;
        let mut coordinator_key_ids = HashMap::new();
        let mut signer_key_ids = HashMap::new();
        let mut addresses = vec![];
        let mut start_key_id = 1u32;
        let mut end_key_id = start_key_id;
        let mut signer_public_keys = HashMap::new();
        // Key ids start from 1 hence the wrapping adds everywhere
        for signer_id in 0..num_signers {
            end_key_id = if signer_id.wrapping_add(1) == num_signers {
                end_key_id.wrapping_add(remaining_keys)
            } else {
                end_key_id.wrapping_add(num_keys)
            };
            if signer_id == 0 {
                if let Some(signer_key) = signer_key {
                    let address = StacksAddress::p2pkh(
                        false,
                        &StacksPublicKey::from_slice(signer_key.to_bytes().as_slice())
                            .expect("Failed to create stacks public key"),
                    );
                    addresses.push(address);
                    public_keys.signers.insert(signer_id, signer_key);
                    let signer_public_key =
                        Point::try_from(&Compressed::from(signer_key.to_bytes())).unwrap();
                    signer_public_keys.insert(signer_id, signer_public_key);
                    public_keys.signers.insert(signer_id, signer_key.clone());
                    for k in start_key_id..end_key_id {
                        public_keys.key_ids.insert(k, signer_key);
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
                    continue;
                }
            }
            let private_key = Scalar::random(rng);
            let public_key = ecdsa::PublicKey::new(&private_key).unwrap();
            let signer_public_key =
                Point::try_from(&Compressed::from(public_key.to_bytes())).unwrap();
            signer_public_keys.insert(signer_id, signer_public_key);
            public_keys.signers.insert(signer_id, public_key.clone());
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
            addresses.push(address);
            start_key_id = end_key_id;
        }
        (
            RewardCycleConfig {
                public_keys,
                key_ids: signer_key_ids.get(&0).cloned().unwrap_or_default(),
                signer_key_ids,
                coordinator_key_ids,
                signer_slot_id: 0,
                signer_id: 0,
                signer_set,
                reward_cycle,
                signer_addresses: addresses.iter().cloned().collect(),
                signer_public_keys,
            },
            addresses,
        )
    }
}
