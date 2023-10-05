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
use stacks_common::{
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
    /// A request sent to the Stacks Node sent an invalid response
    #[error("Unable to parse JSON response from url {0}, error response was {1}")]
    UnableToParseResponseJSON(String, String),
}

/// TODO: Add stacks node communication to this
/// The Stacks signer client used to communicate with the stacker-db instance
pub struct StacksClient {
    /// The stacker-db session
    stackerdb_session: StackerDBSession,
    /// The private key used in all stacks node communications
    stacks_private_key: StacksPrivateKey,
    /// A map of a slot ID to last chunk version
    slot_versions: HashMap<u32, u32>,
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
        }
    }
}

/// Trait used to make interact with Clarity contracts for use in the signing process
pub trait InteractWithStacksContracts {
    /// Submits a transaction to a node RPC server
    fn submit_tx(http_origin: &str, tx: &Vec<u8>) -> String;

    /// Call read only tx
    fn read_only_contract_call(
        http_origin: &str,
        sender: &StacksAddress,
        contract_addr: &StacksAddress,
        contract_name: &str,
        function_name: &str,
        function_args: &[ClarityValue],
    ) -> String;

    /// Creates a contract call transaction
    fn transaction_contract_call(
        sender: &StacksPrivateKey,
        nonce: u64,
        contract_addr: &StacksAddress,
        contract_name: &str,
        function_name: &str,
        function_args: &[ClarityValue],
        tx_version: TransactionVersion,
        chain_id: u32,
    ) -> Vec<u8>;
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

    fn seralize_sign_tx_anchor_mode_version(
        payload: TransactionPayload,
        sender: &StacksPrivateKey,
        payer: Option<&StacksPrivateKey>,
        sender_nonce: u64,
        payer_nonce: Option<u64>,
        tx_fee: u64,
        anchor_mode: TransactionAnchorMode,
        version: TransactionVersion,
        chain_id: u32,
    ) -> Vec<u8> {
        let mut sender_spending_condition = TransactionSpendingCondition::new_singlesig_p2pkh(
            StacksPublicKey::from_private(sender),
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
        let mut unsigned_tx = StacksTransaction::new(version, auth, payload);
        unsigned_tx.anchor_mode = anchor_mode;
        unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;
        unsigned_tx.chain_id = chain_id;

        let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
        tx_signer.sign_origin(sender).unwrap();
        if let (Some(payer), Some(_)) = (payer, payer_nonce) {
            tx_signer.sign_sponsor(payer).unwrap();
        }

        let mut buf = vec![];
        tx_signer
            .get_tx()
            .unwrap()
            .consensus_serialize(&mut buf)
            .unwrap();
        buf
    }
}

impl InteractWithStacksContracts for StacksClient {
    fn transaction_contract_call(
        sender: &StacksPrivateKey,
        nonce: u64,
        contract_addr: &StacksAddress,
        contract_name: &str,
        function_name: &str,
        function_args: &[ClarityValue],
        tx_version: TransactionVersion,
        chain_id: u32,
    ) -> Vec<u8> {
        let contract_name = ContractName::from(contract_name);
        let function_name = ClarityName::from(function_name);

        let payload = TransactionContractCall {
            address: contract_addr.clone(),
            contract_name,
            function_name,
            function_args: function_args.iter().map(|x| x.clone()).collect(),
        };

        let tx_fee = 0;

        Self::seralize_sign_tx_anchor_mode_version(
            payload.into(),
            sender,
            None,
            nonce,
            None,
            tx_fee,
            TransactionAnchorMode::OnChainOnly,
            tx_version,
            chain_id,
        )
    }

    fn submit_tx(http_origin: &str, tx: &Vec<u8>) -> String {
        let client = reqwest::blocking::Client::new();
        let path = format!("{http_origin}/v2/transactions");
        let res = client
            .post(&path)
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
            return res;
        } else {
            // FIXME (https://github.com/stacks-network/stacks-blockchain/issues/3993): this needs to handled better
            eprintln!("Submit tx error: {}", res.text().unwrap());
            panic!("");
        }
    }

    fn read_only_contract_call(
        http_origin: &str,
        sender: &StacksAddress,
        contract_addr: &StacksAddress,
        contract_name: &str,
        function_name: &str,
        function_args: &[ClarityValue],
    ) -> String {
        let body = json!({
            "sender": sender.to_string(),
            "arguments": function_args
        })
        .to_string();

        let client = reqwest::blocking::Client::new();
        let path = format!(
            "{http_origin}/v2/contracts/call-read/{contract_addr}/{contract_name}/{function_name}"
        );
        let res = client
            .post(&path)
            .header("Content-TYpe", "application/json")
            .body(body)
            .send()
            .unwrap();
        if res.status().is_success() {
            let res: String = res.json().unwrap();
            return res;
        } else {
            // FIXME (https://github.com/stacks-network/stacks-blockchain/issues/3993): this needs to handled better
            eprintln!("Submit tx error: {}", res.text().unwrap());
            panic!("");
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
