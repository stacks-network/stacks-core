use std::time::Duration;

use bincode::Error as BincodeError;
use blockstack_lib::{
    burnchains::Txid,
    chainstate::stacks::{
        StacksTransaction, StacksTransactionSigner, TransactionAnchorMode, TransactionAuth,
        TransactionContractCall, TransactionPayload, TransactionPostConditionMode,
        TransactionSpendingCondition, TransactionVersion,
    },
};
use clarity::vm::{
    types::{serialization::SerializationError, QualifiedContractIdentifier, SequenceData},
    Value as ClarityValue, {ClarityName, ContractName},
};
use hashbrown::HashMap;
use libsigner::{RPCError, SignerSession, StackerDBSession};
use libstackerdb::{Error as StackerDBError, StackerDBChunkAckData, StackerDBChunkData};
use serde_json::json;
use slog::{slog_debug, slog_warn};
use stacks_common::{
    codec::StacksMessageCodec,
    debug,
    types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey},
    warn,
};
use wsts::{
    net::{Message, Packet},
    Point, Scalar,
};

use crate::config::Config;

/// Backoff timer initial interval in milliseconds
const BACKOFF_INITIAL_INTERVAL: u64 = 128;
/// Backoff timer max interval in milliseconds
const BACKOFF_MAX_INTERVAL: u64 = 16384;

/// Temporary placeholder for the number of slots allocated to a stacker-db writer. This will be retrieved from the stacker-db instance in the future
/// See: https://github.com/stacks-network/stacks-blockchain/issues/3921
/// Is equal to the number of message types
pub const SLOTS_PER_USER: u32 = 10;

#[derive(thiserror::Error, Debug)]
/// Client error type
pub enum ClientError {
    /// An error occurred serializing the message
    #[error("Unable to serialize stacker-db message: {0}")]
    StackerDBSerializationError(#[from] BincodeError),
    /// Failed to sign stacker-db chunk
    #[error("Failed to sign stacker-db chunk: {0}")]
    FailToSign(#[from] StackerDBError),
    /// Failed to write to stacker-db due to RPC error
    #[error("Failed to write to stacker-db instance: {0}")]
    PutChunkFailed(#[from] RPCError),
    /// Stacker-db instance rejected the chunk
    #[error("Stacker-db rejected the chunk. Reason: {0}")]
    PutChunkRejected(String),
    /// Failed to find a given json entry
    #[error("Invalid JSON entry: {0}")]
    InvalidJsonEntry(String),
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
    #[error("Recieved a malformed clarity value: {0}")]
    MalformedClarityValue(ClarityValue),
    /// Invalid Clarity Name
    #[error("Invalid Clarity Name: {0}")]
    InvalidClarityName(String),
    /// Backoff retry timeout
    #[error("Backoff retry timeout occurred. Stacks node may be down.")]
    RetryTimeout,
}

/// The Stacks signer client used to communicate with the stacker-db instance
pub struct StacksClient {
    /// The stacker-db session
    stackerdb_session: StackerDBSession,
    /// The stacks address of the signer
    stacks_address: StacksAddress,
    /// The private key used in all stacks node communications
    stacks_private_key: StacksPrivateKey,
    /// A map of a slot ID to last chunk version
    slot_versions: HashMap<u32, u32>,
    /// The stacks node HTTP base endpoint
    http_origin: String,
    /// The types of transactions
    tx_version: TransactionVersion,
    /// The chain we are interacting with
    chain_id: u32,
    /// The Client used to make HTTP connects
    stacks_node_client: reqwest::blocking::Client,
    /// The pox contract ID
    pox_contract_id: Option<QualifiedContractIdentifier>,
}

impl From<&Config> for StacksClient {
    fn from(config: &Config) -> Self {
        Self {
            stackerdb_session: StackerDBSession::new(
                config.node_host,
                config.stackerdb_contract_id.clone(),
            ),
            stacks_private_key: config.stacks_private_key,
            stacks_address: config.stacks_address,
            slot_versions: HashMap::new(),
            http_origin: format!("http://{}", config.node_host),
            tx_version: config.network.to_transaction_version(),
            chain_id: config.network.to_chain_id(),
            stacks_node_client: reqwest::blocking::Client::new(),
            pox_contract_id: config.pox_contract_id.clone(),
        }
    }
}

impl StacksClient {
    /// Sends messages to the stacker-db with an exponential backoff retry
    pub fn send_message_with_retry(
        &mut self,
        id: u32,
        message: Packet,
    ) -> Result<StackerDBChunkAckData, ClientError> {
        let message_bytes = bincode::serialize(&message)?;
        let slot_id = slot_id(id, &message.msg);

        loop {
            let slot_version = *self.slot_versions.entry(slot_id).or_insert(0) + 1;
            let mut chunk = StackerDBChunkData::new(slot_id, slot_version, message_bytes.clone());
            chunk.sign(&self.stacks_private_key)?;
            debug!("Sending a chunk to stackerdb!\n{:?}", chunk.clone());
            let send_request = || {
                self.stackerdb_session
                    .put_chunk(chunk.clone())
                    .map_err(backoff::Error::transient)
            };
            let chunk_ack: StackerDBChunkAckData = retry_with_exponential_backoff(send_request)?;
            self.slot_versions.insert(slot_id, slot_version);

            if chunk_ack.accepted {
                debug!("Chunk accepted by stackerdb: {:?}", chunk_ack);
                return Ok(chunk_ack);
            } else {
                warn!("Chunk rejected by stackerdb: {:?}", chunk_ack);
            }
            if let Some(reason) = chunk_ack.reason {
                // TODO: fix this jankiness. Update stackerdb to use an error code mapping instead of just a string
                // See: https://github.com/stacks-network/stacks-blockchain/issues/3917
                if reason == "Data for this slot and version already exist" {
                    warn!("Failed to send message to stackerdb due to wrong version number {}. Incrementing and retrying...", slot_version);
                } else {
                    warn!("Failed to send message to stackerdb: {}", reason);
                    return Err(ClientError::PutChunkRejected(reason));
                }
            }
        }
    }

    /// Retrieve the current DKG aggregate public key
    pub fn get_aggregate_public_key(&self) -> Result<Option<Point>, ClientError> {
        let reward_cycle = self.get_current_reward_cycle()?;
        let function_name_str = "get-aggregate-public-key"; // FIXME: this may need to be modified to match .pox-4
        let function_name = ClarityName::try_from(function_name_str)
            .map_err(|_| ClientError::InvalidClarityName(function_name_str.to_string()))?;
        let (contract_addr, contract_name) = self.get_pox_contract()?;
        let function_args = &[ClarityValue::UInt(reward_cycle as u128)];
        let contract_response_hex = self.read_only_contract_call_with_retry(
            &contract_addr,
            &contract_name,
            &function_name,
            function_args,
        )?;
        self.parse_aggregate_public_key(&contract_response_hex)
    }

    /// Retrieve the total number of slots allocated to a stacker-db writer
    #[allow(dead_code)]
    pub fn slots_per_user(&self) -> u32 {
        // TODO: retrieve this from the stackerdb instance and make it a function of a given signer public key
        // See: https://github.com/stacks-network/stacks-blockchain/issues/3921
        SLOTS_PER_USER
    }

    /// Helper function to retrieve the current reward cycle number from the stacks node
    fn get_current_reward_cycle(&self) -> Result<u64, ClientError> {
        let send_request = || {
            self.stacks_node_client
                .get(self.pox_path())
                .send()
                .map_err(backoff::Error::transient)
        };
        let response = retry_with_exponential_backoff(send_request)?;
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let json_response = response.json::<serde_json::Value>()?;
        let entry = "current_cycle";
        json_response
            .get(entry)
            .and_then(|cycle: &serde_json::Value| cycle.get("id"))
            .and_then(|id| id.as_u64())
            .ok_or_else(|| ClientError::InvalidJsonEntry(format!("{}.id", entry)))
    }

    /// Helper function to retrieve the next possible nonce for the signer from the stacks node
    #[allow(dead_code)]
    fn get_next_possible_nonce(&self) -> Result<u64, ClientError> {
        //FIXME: use updated RPC call to get mempool nonces. Depends on https://github.com/stacks-network/stacks-blockchain/issues/4000
        todo!("Get the next possible nonce from the stacks node");
    }

    /// Helper function to retrieve the pox contract address and name from the stacks node
    fn get_pox_contract(&self) -> Result<(StacksAddress, ContractName), ClientError> {
        // Check if we have overwritten the pox contract ID in the config
        if let Some(pox_contract) = self.pox_contract_id.clone() {
            return Ok((pox_contract.issuer.into(), pox_contract.name));
        }
        // TODO: we may want to cache the pox contract inside the client itself (calling this function once on init)
        // https://github.com/stacks-network/stacks-blockchain/issues/4005
        let send_request = || {
            self.stacks_node_client
                .get(self.pox_path())
                .send()
                .map_err(backoff::Error::transient)
        };
        let response = retry_with_exponential_backoff(send_request)?;
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let json_response = response.json::<serde_json::Value>()?;
        let entry = "contract_id";
        let contract_id_string = json_response
            .get(entry)
            .and_then(|id: &serde_json::Value| id.as_str())
            .ok_or_else(|| ClientError::InvalidJsonEntry(entry.to_string()))?;
        let id = QualifiedContractIdentifier::parse(contract_id_string).unwrap();
        Ok((id.issuer.into(), id.name))
    }

    /// Helper function that attempts to deserialize a clarity hex string as the aggregate public key
    fn parse_aggregate_public_key(&self, hex: &str) -> Result<Option<Point>, ClientError> {
        let public_key_clarity_value = ClarityValue::try_deserialize_hex_untyped(hex)?;
        if let ClarityValue::Optional(optional_data) = public_key_clarity_value.clone() {
            if let Some(ClarityValue::Sequence(SequenceData::Buffer(public_key))) =
                optional_data.data.map(|boxed| *boxed)
            {
                if public_key.data.len() != 32 {
                    return Err(ClientError::MalformedClarityValue(public_key_clarity_value));
                }
                let mut bytes = [0_u8; 32];
                bytes.copy_from_slice(&public_key.data);
                Ok(Some(Point::from(Scalar::from(bytes))))
            } else {
                Ok(None)
            }
        } else {
            Err(ClientError::MalformedClarityValue(public_key_clarity_value))
        }
    }

    /// Sends a transaction to the stacks node for a modifying contract call
    #[allow(dead_code)]
    fn transaction_contract_call(
        &self,
        contract_addr: &StacksAddress,
        contract_name: ContractName,
        function_name: ClarityName,
        function_args: &[ClarityValue],
    ) -> Result<Txid, ClientError> {
        debug!("Making a contract call to {contract_addr}.{contract_name}...");
        let signed_tx = self.build_signed_transaction(
            contract_addr,
            contract_name,
            function_name,
            function_args,
        )?;
        self.submit_tx(&signed_tx)
    }

    /// Helper function to create a stacks transaction for a modifying contract call
    fn build_signed_transaction(
        &self,
        contract_addr: &StacksAddress,
        contract_name: ContractName,
        function_name: ClarityName,
        function_args: &[ClarityValue],
    ) -> Result<StacksTransaction, ClientError> {
        let tx_payload = TransactionPayload::ContractCall(TransactionContractCall {
            address: *contract_addr,
            contract_name,
            function_name,
            function_args: function_args.to_vec(),
        });
        let public_key = StacksPublicKey::from_private(&self.stacks_private_key);
        let tx_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_singlesig_p2pkh(public_key).ok_or(
                ClientError::TransactionGenerationFailure(format!(
                    "Failed to create spending condition from public key: {}",
                    public_key.to_hex()
                )),
            )?,
        );

        let mut unsigned_tx = StacksTransaction::new(self.tx_version, tx_auth, tx_payload);

        // FIXME: Because signers are given priority, we can put down a tx fee of 0
        // https://github.com/stacks-network/stacks-blockchain/issues/4006
        // Note: if set to 0 now, will cause a failure (MemPoolRejection::FeeTooLow)
        unsigned_tx.set_tx_fee(10_000);
        unsigned_tx.set_origin_nonce(self.get_next_possible_nonce()?);

        unsigned_tx.anchor_mode = TransactionAnchorMode::Any;
        unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;
        unsigned_tx.chain_id = self.chain_id;

        let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
        tx_signer
            .sign_origin(&self.stacks_private_key)
            .map_err(|e| ClientError::TransactionGenerationFailure(e.to_string()))?;

        tx_signer
            .get_tx()
            .ok_or(ClientError::TransactionGenerationFailure(
                "Failed to generate transaction from a transaction signer".to_string(),
            ))
    }

    /// Helper function to submit a transaction to the Stacks node
    fn submit_tx(&self, tx: &StacksTransaction) -> Result<Txid, ClientError> {
        let txid = tx.txid();
        let tx = tx.serialize_to_vec();
        let send_request = || {
            self.stacks_node_client
                .post(self.transaction_path())
                .header("Content-Type", "application/octet-stream")
                .body(tx.clone())
                .send()
                .map_err(backoff::Error::transient)
        };
        let response = retry_with_exponential_backoff(send_request)?;
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        Ok(txid)
    }

    /// Makes a read only contract call to a stacks contract
    pub fn read_only_contract_call_with_retry(
        &self,
        contract_addr: &StacksAddress,
        contract_name: &ContractName,
        function_name: &ClarityName,
        function_args: &[ClarityValue],
    ) -> Result<String, ClientError> {
        debug!("Calling read-only function {}...", function_name);
        let args = function_args
            .iter()
            .map(|arg| arg.serialize_to_hex())
            .collect::<Vec<String>>();
        let body =
            json!({"sender": self.stacks_address.to_string(), "arguments": args}).to_string();
        let path = self.read_only_path(contract_addr, contract_name, function_name);
        let send_request = || {
            self.stacks_node_client
                .post(path.clone())
                .header("Content-Type", "application/json")
                .body(body.clone())
                .send()
                .map_err(backoff::Error::transient)
        };
        let response = retry_with_exponential_backoff(send_request)?;
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let response = response.json::<serde_json::Value>()?;
        if !response
            .get("okay")
            .map(|val| val.as_bool().unwrap_or(false))
            .unwrap_or(false)
        {
            let cause = response
                .get("cause")
                .ok_or(ClientError::InvalidJsonEntry("cause".to_string()))?;
            return Err(ClientError::ReadOnlyFailure(format!(
                "{}: {}",
                function_name, cause
            )));
        }
        let result = response
            .get("result")
            .ok_or(ClientError::InvalidJsonEntry("result".to_string()))?
            .as_str()
            .ok_or_else(|| ClientError::ReadOnlyFailure("Expected string result.".to_string()))?
            .to_string();
        Ok(result)
    }

    fn pox_path(&self) -> String {
        format!("{}/v2/pox", self.http_origin)
    }

    fn transaction_path(&self) -> String {
        format!("{}/v2/transactions", self.http_origin)
    }

    fn read_only_path(
        &self,
        contract_addr: &StacksAddress,
        contract_name: &ContractName,
        function_name: &ClarityName,
    ) -> String {
        format!(
            "{}/v2/contracts/call-read/{contract_addr}/{contract_name}/{function_name}",
            self.http_origin
        )
    }
}

/// Retry a function F with an exponential backoff and notification on transient failure
pub fn retry_with_exponential_backoff<F, E, T>(request_fn: F) -> Result<T, ClientError>
where
    F: FnMut() -> Result<T, backoff::Error<E>>,
{
    let notify = |_err, dur| {
        debug!(
            "Failed to connect to stacks-node. Next attempt in {:?}",
            dur
        );
    };

    let backoff_timer = backoff::ExponentialBackoffBuilder::new()
        .with_initial_interval(Duration::from_millis(BACKOFF_INITIAL_INTERVAL))
        .with_max_interval(Duration::from_millis(BACKOFF_MAX_INTERVAL))
        .build();

    backoff::retry_notify(backoff_timer, request_fn, notify).map_err(|_| ClientError::RetryTimeout)
}

/// Helper function to determine the slot ID for the provided stacker-db writer id and the message type
fn slot_id(id: u32, message: &Message) -> u32 {
    let slot_id = match message {
        Message::DkgBegin(_) => 0,
        Message::DkgPrivateBegin(_) => 1,
        Message::DkgEnd(_) => 2,
        Message::DkgPublicShares(_) => 4,
        Message::DkgPrivateShares(_) => 5,
        Message::NonceRequest(_) => 6,
        Message::NonceResponse(_) => 7,
        Message::SignatureShareRequest(_) => 8,
        Message::SignatureShareResponse(_) => 9,
    };
    SLOTS_PER_USER * id + slot_id
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufWriter, Read, Write},
        net::{SocketAddr, TcpListener},
        thread::spawn,
    };

    use super::*;

    struct TestConfig {
        mock_server: TcpListener,
        client: StacksClient,
    }

    impl TestConfig {
        pub fn new() -> Self {
            let mut config = Config::load_from_file("./src/tests/conf/signer-0.toml").unwrap();

            let mut mock_server_addr = SocketAddr::from(([127, 0, 0, 1], 0));
            // Ask the OS to assign a random port to listen on by passing 0
            let mock_server = TcpListener::bind(mock_server_addr).unwrap();

            // Update the config to use this port
            mock_server_addr.set_port(mock_server.local_addr().unwrap().port());
            config.node_host = mock_server_addr;

            let client = StacksClient::from(&config);
            Self {
                mock_server,
                client,
            }
        }
    }

    fn write_response(mock_server: TcpListener, bytes: &[u8]) -> [u8; 1024] {
        debug!("Writing a response...");
        let mut request_bytes = [0u8; 1024];
        {
            let mut stream = mock_server.accept().unwrap().0;
            let _ = stream.read(&mut request_bytes).unwrap();
            stream.write_all(bytes).unwrap();
        }
        request_bytes
    }

    #[test]
    fn read_only_contract_call_200_success() {
        let config = TestConfig::new();
        let h = spawn(move || {
            config.client.read_only_contract_call_with_retry(
                &config.client.stacks_address,
                &ContractName::try_from("contract-name").unwrap(),
                &ClarityName::try_from("function-name").unwrap(),
                &[],
            )
        });
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 OK\n\n{\"okay\":true,\"result\":\"0x070d0000000473425443\"}",
        );
        let result = h.join().unwrap().unwrap();
        assert_eq!(result, "0x070d0000000473425443");
    }

    #[test]
    fn read_only_contract_call_with_function_args_200_success() {
        let config = TestConfig::new();
        let h = spawn(move || {
            config.client.read_only_contract_call_with_retry(
                &config.client.stacks_address,
                &ContractName::try_from("contract-name").unwrap(),
                &ClarityName::try_from("function-name").unwrap(),
                &[ClarityValue::UInt(10_u128)],
            )
        });
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 OK\n\n{\"okay\":true,\"result\":\"0x070d0000000473425443\"}",
        );
        let result = h.join().unwrap().unwrap();
        assert_eq!(result, "0x070d0000000473425443");
    }

    #[test]
    fn read_only_contract_call_200_failure() {
        let config = TestConfig::new();
        let h = spawn(move || {
            config.client.read_only_contract_call_with_retry(
                &config.client.stacks_address,
                &ContractName::try_from("contract-name").unwrap(),
                &ClarityName::try_from("function-name").unwrap(),
                &[],
            )
        });
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 OK\n\n{\"okay\":false,\"cause\":\"Some reason\"}",
        );
        let result = h.join().unwrap();
        assert!(matches!(result, Err(ClientError::ReadOnlyFailure(_))));
    }

    #[test]
    fn read_only_contract_call_400_failure() {
        let config = TestConfig::new();
        // Simulate a 400 Bad Request response
        let h = spawn(move || {
            config.client.read_only_contract_call_with_retry(
                &config.client.stacks_address,
                &ContractName::try_from("contract-name").unwrap(),
                &ClarityName::try_from("function-name").unwrap(),
                &[],
            )
        });
        write_response(config.mock_server, b"HTTP/1.1 400 Bad Request\n\n");
        let result = h.join().unwrap();
        assert!(matches!(
            result,
            Err(ClientError::RequestFailure(
                reqwest::StatusCode::BAD_REQUEST
            ))
        ));
    }

    #[test]
    fn read_only_contract_call_404_failure() {
        let config = TestConfig::new();
        // Simulate a 400 Bad Request response
        let h = spawn(move || {
            config.client.read_only_contract_call_with_retry(
                &config.client.stacks_address,
                &ContractName::try_from("contract-name").unwrap(),
                &ClarityName::try_from("function-name").unwrap(),
                &[],
            )
        });
        write_response(config.mock_server, b"HTTP/1.1 404 Not Found\n\n");
        let result = h.join().unwrap();
        assert!(matches!(
            result,
            Err(ClientError::RequestFailure(reqwest::StatusCode::NOT_FOUND))
        ));
    }

    #[test]
    fn pox_contract_success() {
        let config = TestConfig::new();
        let h = spawn(move || config.client.get_pox_contract());
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 Ok\n\n{\"contract_id\":\"ST000000000000000000002AMW42H.pox-3\"}",
        );
        let (address, name) = h.join().unwrap().unwrap();
        assert_eq!(
            (address.to_string().as_str(), name.to_string().as_str()),
            ("ST000000000000000000002AMW42H", "pox-3")
        );
    }

    #[test]
    fn valid_reward_cycle_should_succeed() {
        let config = TestConfig::new();
        let h = spawn(move || config.client.get_current_reward_cycle());
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 Ok\n\n{\"current_cycle\":{\"id\":506,\"min_threshold_ustx\":5190000000000,\"stacked_ustx\":5690000000000,\"is_pox_active\":false}}",
        );
        let current_cycle_id = h.join().unwrap().unwrap();
        assert_eq!(506, current_cycle_id);
    }

    #[test]
    fn invalid_reward_cycle_should_fail() {
        let config = TestConfig::new();
        let h = spawn(move || config.client.get_current_reward_cycle());
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 Ok\n\n{\"current_cycle\":{\"id\":\"fake id\", \"is_pox_active\":false}}",
        );
        let res = h.join().unwrap();
        assert!(matches!(res, Err(ClientError::InvalidJsonEntry(_))));
    }

    #[test]
    fn missing_reward_cycle_should_fail() {
        let config = TestConfig::new();
        let h = spawn(move || config.client.get_current_reward_cycle());
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 Ok\n\n{\"current_cycle\":{\"is_pox_active\":false}}",
        );
        let res = h.join().unwrap();
        assert!(matches!(res, Err(ClientError::InvalidJsonEntry(_))));
    }

    #[test]
    fn parse_valid_aggregate_public_key_should_succeed() {
        let config = TestConfig::new();
        let clarity_value_hex =
            "0x0a0200000020b8c8b0652cb2851a52374c7acd47181eb031e8fa5c62883f636e0d4fe695d6ca";
        let result = config
            .client
            .parse_aggregate_public_key(clarity_value_hex)
            .unwrap();
        assert_eq!(
            result.map(|point| point.to_string()),
            Some("yzwdjwPz36Has1MSkg8JGwo38avvATkiTZvRiH1e5MLd".to_string())
        );

        let clarity_value_hex = "0x09";
        let result = config
            .client
            .parse_aggregate_public_key(clarity_value_hex)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_invalid_aggregate_public_key_should_fail() {
        let config = TestConfig::new();
        let clarity_value_hex = "0x00";
        let result = config.client.parse_aggregate_public_key(clarity_value_hex);
        assert!(matches!(
            result,
            Err(ClientError::ClaritySerializationError(..))
        ));
        // TODO: add further tests for malformed clarity values (an optional of any other type for example)
    }

    #[ignore]
    #[test]
    fn transaction_contract_call_should_send_bytes_to_node() {
        let config = TestConfig::new();
        let tx = config
            .client
            .build_signed_transaction(
                &config.client.stacks_address,
                ContractName::try_from("contract-name").unwrap(),
                ClarityName::try_from("function-name").unwrap(),
                &[],
            )
            .unwrap();

        let mut tx_bytes = [0u8; 1024];
        {
            let mut tx_bytes_writer = BufWriter::new(&mut tx_bytes[..]);
            tx.consensus_serialize(&mut tx_bytes_writer).unwrap();
            tx_bytes_writer.flush().unwrap();
        }

        let bytes_len = tx_bytes
            .iter()
            .enumerate()
            .rev()
            .find(|(_, &x)| x != 0)
            .unwrap()
            .0
            + 1;

        let tx_clone = tx.clone();
        let h = spawn(move || config.client.submit_tx(&tx_clone));

        let request_bytes = write_response(
            config.mock_server,
            format!("HTTP/1.1 200 OK\n\n{}", tx.txid()).as_bytes(),
        );
        let returned_txid = h.join().unwrap().unwrap();

        assert_eq!(returned_txid, tx.txid());
        assert!(
            request_bytes
                .windows(bytes_len)
                .any(|window| window == &tx_bytes[..bytes_len]),
            "Request bytes did not contain the transaction bytes"
        );
    }

    #[ignore]
    #[test]
    fn transaction_contract_call_should_succeed() {
        let config = TestConfig::new();
        let h = spawn(move || {
            config.client.transaction_contract_call(
                &config.client.stacks_address,
                ContractName::try_from("contract-name").unwrap(),
                ClarityName::try_from("function-name").unwrap(),
                &[],
            )
        });
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 OK\n\n4e99f99bc4a05437abb8c7d0c306618f45b203196498e2ebe287f10497124958",
        );
        assert!(h.join().unwrap().is_ok());
    }
}
