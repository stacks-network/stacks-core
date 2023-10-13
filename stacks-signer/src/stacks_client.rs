use bincode::Error as BincodeError;
use blockstack_lib::chainstate::stacks::{
    StacksTransaction, StacksTransactionSigner, TransactionAnchorMode, TransactionAuth,
    TransactionContractCall, TransactionPayload, TransactionPostConditionMode,
    TransactionSpendingCondition, TransactionVersion,
};
use clarity::vm::{
    Value as ClarityValue, {ClarityName, ContractName},
};
use hashbrown::HashMap;
use libsigner::{RPCError, SignerSession, StackerDBSession};
use libstackerdb::{Error as StackerDBError, StackerDBChunkAckData, StackerDBChunkData};
use serde_json::json;
use slog::{slog_debug, slog_warn};
use stacks_common::{
    codec,
    codec::StacksMessageCodec,
    debug,
    types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey},
    warn,
};
use wsts::net::{Message, Packet};

use crate::config::Config;

/// Temporary placeholder for the number of slots allocated to a stacker-db writer. This will be retrieved from the stacker-db instance in the future
/// See: https://github.com/stacks-network/stacks-blockchain/issues/3921
/// Is equal to the number of message types
pub const SLOTS_PER_USER: u32 = 10;

#[derive(thiserror::Error, Debug)]
/// Client error type
pub enum ClientError {
    /// An error occurred serializing the message
    #[error("Unable to serialize stacker-db message: {0}")]
    Serialize(#[from] BincodeError),
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
    /// Failure to submit a read only contract call
    #[error("Failure to submit tx")]
    TransactionSubmissionFailure,
    /// Failed to sign with the provided private key
    #[error("Failed to sign with the given private key")]
    SignatureGenerationFailure,
    /// Failed to sign with the provided private key
    #[error("Failed to sign with the sponsor private key")]
    SponsorSignatureGenerationFailure,
    /// Failed to sign with the provided private key
    #[error("Failed to serialize tx {0}")]
    FailureToSerializeTx(String),
    /// Failed to sign with the provided private key
    #[error("{0}")]
    FailureToDeserializeTx(#[from] codec::Error),
    /// Failed to create a p2pkh spending condition
    #[error("Failed to create p2pkh spending condition from public key {0}")]
    FailureToCreateSpendingFromPublicKey(String),
    /// Stacks node client request failed
    #[error("Stacks node client request failed: {0}")]
    RequestFailure(reqwest::StatusCode),
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
    /// The RPC endpoint used to communicate HTTP endpoints with
    http_origin: String,
    /// The types of transactions
    tx_version: TransactionVersion,
    /// The chain we are interacting with
    chain_id: u32,
    /// The Client used to make HTTP connects
    stacks_node_client: reqwest::blocking::Client,
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
        }
    }
}

impl StacksClient {
    /// Sends messages to the stacker-db
    pub fn send_message(
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
            let chunk_ack = self.stackerdb_session.put_chunk(chunk)?;
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

    /// Retrieve the total number of slots allocated to a stacker-db writer
    #[allow(dead_code)]
    pub fn slots_per_user(&self) -> u32 {
        // TODO: retrieve this from the stackerdb instance and make it a function of a given signer public key
        // See: https://github.com/stacks-network/stacks-blockchain/issues/3921
        SLOTS_PER_USER
    }

    fn serialize_sign_sig_tx_anchor_mode_version(
        &self,
        payload: TransactionPayload,
        sender_nonce: u64,
        tx_fee: u64,
        anchor_mode: TransactionAnchorMode,
    ) -> Result<Vec<u8>, ClientError> {
        self.seralize_sign_sponsored_tx_anchor_mode_version(
            payload,
            None,
            sender_nonce,
            None,
            tx_fee,
            anchor_mode,
        )
    }

    fn seralize_sign_sponsored_tx_anchor_mode_version(
        &self,
        payload: TransactionPayload,
        payer: Option<&StacksPrivateKey>,
        sender_nonce: u64,
        payer_nonce: Option<u64>,
        tx_fee: u64,
        anchor_mode: TransactionAnchorMode,
    ) -> Result<Vec<u8>, ClientError> {
        let pubkey = StacksPublicKey::from_private(&self.stacks_private_key);
        let mut sender_spending_condition =
            TransactionSpendingCondition::new_singlesig_p2pkh(pubkey).ok_or(
                ClientError::FailureToCreateSpendingFromPublicKey(pubkey.to_hex()),
            )?;
        sender_spending_condition.set_nonce(sender_nonce);

        let auth = match (payer, payer_nonce) {
            (Some(payer), Some(payer_nonce)) => {
                let pubkey = StacksPublicKey::from_private(payer);
                let mut payer_spending_condition =
                    TransactionSpendingCondition::new_singlesig_p2pkh(pubkey).ok_or(
                        ClientError::FailureToCreateSpendingFromPublicKey(pubkey.to_hex()),
                    )?;
                payer_spending_condition.set_nonce(payer_nonce);
                payer_spending_condition.set_tx_fee(tx_fee);
                TransactionAuth::Sponsored(sender_spending_condition, payer_spending_condition)
            }
            _ => {
                sender_spending_condition.set_tx_fee(tx_fee);
                TransactionAuth::Standard(sender_spending_condition)
            }
        };
        let mut unsigned_tx = StacksTransaction::new(self.tx_version, auth, payload);
        unsigned_tx.anchor_mode = anchor_mode;
        unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;
        unsigned_tx.chain_id = self.chain_id;

        let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
        tx_signer
            .sign_origin(&self.stacks_private_key)
            .map_err(|_| ClientError::SignatureGenerationFailure)?;
        if let (Some(payer), Some(_)) = (payer, payer_nonce) {
            tx_signer
                .sign_sponsor(payer)
                .map_err(|_| ClientError::SponsorSignatureGenerationFailure)?;
        }

        let Some(tx) = tx_signer.get_tx() else {
            return Err(ClientError::SignatureGenerationFailure);
        };

        Ok(tx.serialize_to_vec())
    }

    /// Creates a transaction for a contract call that can be submitted to a stacks node
    pub fn transaction_contract_call(
        &self,
        nonce: u64,
        contract_addr: &StacksAddress,
        contract_name: ContractName,
        function_name: ClarityName,
        function_args: &[ClarityValue],
    ) -> Result<Vec<u8>, ClientError> {
        let payload = TransactionContractCall {
            address: *contract_addr,
            contract_name,
            function_name,
            function_args: function_args.to_vec(),
        };

        let tx_fee = 0;

        self.serialize_sign_sig_tx_anchor_mode_version(
            payload.into(),
            nonce,
            tx_fee,
            TransactionAnchorMode::OnChainOnly,
        )
    }

    /// Submits a transaction to the Stacks node
    pub fn submit_tx(&self, tx: Vec<u8>) -> Result<String, ClientError> {
        let path = format!("{}/v2/transactions", self.http_origin);
        let res = self
            .stacks_node_client
            .post(path)
            .header("Content-Type", "application/octet-stream")
            .body(tx.clone())
            .send()?;
        if res.status().is_success() {
            let res: String = res.json()?;
            let tx_deserialized = StacksTransaction::consensus_deserialize(&mut &tx[..])?;
            assert_eq!(res, tx_deserialized.txid().to_string());
            Ok(res)
        } else {
            Err(ClientError::TransactionSubmissionFailure)
        }
    }

    /// Makes a read only contract call to a stacks contract
    pub fn read_only_contract_call(
        &self,
        contract_addr: &StacksAddress,
        contract_name: ContractName,
        function_name: ClarityName,
        function_args: &[ClarityValue],
    ) -> Result<String, ClientError> {
        debug!("Calling read-only function {}...", function_name);
        let body = json!({"sender": self.stacks_address.to_string(), "arguments": function_args})
            .to_string();
        let path = format!(
            "{}/v2/contracts/call-read/{contract_addr}/{contract_name}/{function_name}",
            self.http_origin
        );
        let response = self
            .stacks_node_client
            .post(path)
            .header("Content-Type", "application/json")
            .body(body)
            .send()?;
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
        io::{Read, Write},
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
            config.client.read_only_contract_call(
                &config.client.stacks_address,
                ContractName::try_from("contract-name").unwrap(),
                ClarityName::try_from("function-name").unwrap(),
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
    fn read_only_contract_call_200_failure() {
        let config = TestConfig::new();
        let h = spawn(move || {
            config.client.read_only_contract_call(
                &config.client.stacks_address,
                ContractName::try_from("contract-name").unwrap(),
                ClarityName::try_from("function-name").unwrap(),
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
            config.client.read_only_contract_call(
                &config.client.stacks_address,
                ContractName::try_from("contract-name").unwrap(),
                ClarityName::try_from("function-name").unwrap(),
                &[],
            )
        });
        write_response(config.mock_server, b"HTTP/1.1 400 Bad Request\n\n");
        let result = h.join().unwrap();
        assert!(matches!(
            dbg!(result),
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
            config.client.read_only_contract_call(
                &config.client.stacks_address,
                ContractName::try_from("contract-name").unwrap(),
                ClarityName::try_from("function-name").unwrap(),
                &[],
            )
        });
        write_response(config.mock_server, b"HTTP/1.1 404 Not Found\n\n");
        let result = h.join().unwrap();
        assert!(matches!(
            dbg!(result),
            Err(ClientError::RequestFailure(reqwest::StatusCode::NOT_FOUND))
        ));
    }
}
