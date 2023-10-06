use bincode::Error as BincodeError;
use blockstack_lib::chainstate::stacks::{
    StacksTransaction, StacksTransactionSigner, TransactionAnchorMode, TransactionAuth,
    TransactionContractCall, TransactionPayload, TransactionPostConditionMode,
    TransactionSpendingCondition, TransactionVersion,
};
use clarity::vm::Value as ClarityValue;
use clarity::vm::{ClarityName, ContractName};
use hashbrown::HashMap;
use libsigner::{RPCError, SignerSession, StackerDBSession};
use libstackerdb::{Error as StackerDBError, StackerDBChunkAckData, StackerDBChunkData};
use serde_json::json;
use slog::{slog_debug, slog_warn};
use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_MAINNET_SINGLESIG};
use stacks_common::{
    codec::StacksMessageCodec,
    debug,
    types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey},
    warn,
};
use wsts::net::{Message, Packet};

use crate::config::{Config, Network};

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
    /// A request sent to the Stacks Node sent an invalid response
    #[error("Unable to parse JSON response from url {0}, error response was {1}")]
    UnableToParseResponseJSON(String, String),
    /// Failure to submit a read only contract call
    #[error("Failure to submit read only contract call to {0} for function {1}")]
    ReadOnlyContractCallFailure(StacksAddress, String),
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
    #[error("Failed to ")]
    FailureToSerializeTx,
}

/// The Stacks signer client used to communicate with the stacker-db instance
pub struct StacksClient {
    /// The stacker-db session
    stackerdb_session: StackerDBSession,
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
            slot_versions: HashMap::new(),
            http_origin: "0.0.0.0:5001".to_string(),
            tx_version: TransactionVersion::Testnet,
            chain_id: Network::Testnet.to_chain_id(),
            stacks_node_client: reqwest::blocking::Client::new(),
        }
    }
}

/// Trait used to make interact with Clarity contracts for use in the signing process
pub trait InteractWithStacksContracts {
    /// Submits a transaction to a node RPC server
    fn submit_tx(&self, tx: &Vec<u8>) -> Result<String, ClientError>;

    /// Call read only tx
    fn read_only_contract_call(
        &self,
        contract_addr: &StacksAddress,
        contract_name: &str,
        function_name: &str,
        function_args: &[ClarityValue],
    ) -> Result<String, ClientError>;

    /// Creates a contract call transaction
    fn transaction_contract_call(
        &self,
        nonce: u64,
        contract_addr: &StacksAddress,
        contract_name: &str,
        function_name: &str,
        function_args: &[ClarityValue],
    ) -> Result<Vec<u8>, ClientError>;
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
        let mut sender_spending_condition = TransactionSpendingCondition::new_singlesig_p2pkh(
            StacksPublicKey::from_private(&self.stacks_private_key),
        )
        .expect("Failed to create p2pkh spending condition from public key.");
        sender_spending_condition.set_nonce(sender_nonce);

        let auth = match (payer, payer_nonce) {
            (Some(payer), Some(payer_nonce)) => {
                let mut payer_spending_condition =
                    TransactionSpendingCondition::new_singlesig_p2pkh(
                        StacksPublicKey::from_private(payer),
                    )
                    .expect("Failed to create p2pkh spending condition from public key.");
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

        let Some(tx )= tx_signer
            .get_tx() else {
                return Err(ClientError::SignatureGenerationFailure);
            };
        
        Ok(tx.serialize_to_vec())
    }
}

impl InteractWithStacksContracts for StacksClient {
    fn transaction_contract_call(
        &self,
        nonce: u64,
        contract_addr: &StacksAddress,
        contract_name: &str,
        function_name: &str,
        function_args: &[ClarityValue],
    ) -> Result<Vec<u8>, ClientError> {
        let contract_name = ContractName::from(contract_name);
        let function_name = ClarityName::from(function_name);

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

    fn submit_tx(&self, tx: &Vec<u8>) -> Result<String, ClientError> {
        let path = format!("{}/v2/transactions", self.http_origin);
        let res = self
            .stacks_node_client
            .post(path)
            .header("Content-Type", "application/octet-stream")
            .body(tx.clone())
            .send()
            .unwrap();
        if res.status().is_success() {
            let res: String = res.json().unwrap();
            assert_eq!(
                res,
                StacksTransaction::consensus_deserialize(&mut &tx[..])
                    .unwrap()
                    .txid()
                    .to_string()
            );
            Ok(res)
        } else {
            Err(ClientError::TransactionSubmissionFailure)
        }
    }

    fn read_only_contract_call(
        &self,
        contract_addr: &StacksAddress,
        contract_name: &str,
        function_name: &str,
        function_args: &[ClarityValue],
    ) -> Result<String, ClientError> {
        let sender_address = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&self.stacks_private_key)],
        )
        .unwrap();
        let body = json!({
            "sender": sender_address.to_string(),
            "arguments": function_args
        })
        .to_string();

        let path = format!(
            "{}/v2/contracts/call-read/{contract_addr}/{contract_name}/{function_name}",
            self.http_origin
        );
        let res = self
            .stacks_node_client
            .post(path)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .unwrap();
        if res.status().is_success() {
            let res: String = res.json().unwrap();
            Ok(res)
        } else {
            Err(ClientError::ReadOnlyContractCallFailure(
                *contract_addr,
                function_name.to_string(),
            ))
        }
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
