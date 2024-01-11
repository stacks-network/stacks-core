use blockstack_lib::burnchains::Txid;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::net::api::postblock_proposal::ValidateRejectCode;
use clarity::vm::types::QualifiedContractIdentifier;
use hashbrown::HashMap;
use libsigner::{SignerSession, StackerDBSession};
use libstackerdb::{StackerDBChunkAckData, StackerDBChunkData};
use serde_derive::{Deserialize, Serialize};
use slog::{slog_debug, slog_warn};
use stacks_common::types::chainstate::StacksPrivateKey;
use stacks_common::{debug, warn};
use wsts::net::{Message, Packet};

use super::ClientError;
use crate::client::retry_with_exponential_backoff;
use crate::config::Config;

/// Temporary placeholder for the number of slots allocated to a stacker-db writer. This will be retrieved from the stacker-db instance in the future
/// See: https://github.com/stacks-network/stacks-blockchain/issues/3921
/// Is equal to the number of message types
pub const SIGNER_SLOTS_PER_USER: u32 = 10;

// The slot IDS for each message type
const DKG_BEGIN_SLOT_ID: u32 = 0;
const DKG_PRIVATE_BEGIN_SLOT_ID: u32 = 1;
const DKG_END_SLOT_ID: u32 = 2;
const DKG_PUBLIC_SHARES_SLOT_ID: u32 = 3;
const DKG_PRIVATE_SHARES_SLOT_ID: u32 = 4;
const NONCE_REQUEST_SLOT_ID: u32 = 5;
const NONCE_RESPONSE_SLOT_ID: u32 = 6;
const SIGNATURE_SHARE_REQUEST_SLOT_ID: u32 = 7;
const SIGNATURE_SHARE_RESPONSE_SLOT_ID: u32 = 8;
const BLOCK_SLOT_ID: u32 = 9;

/// The messages being sent through the stacker db contracts
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum SignerMessage {
    /// The signed/validated Nakamoto block for miners to observe
    BlockResponse(BlockResponse),
    /// DKG and Signing round data for other signers to observe
    Packet(Packet),
}

/// The response that a signer sends back to observing miners
/// either accepting or rejecting a Nakamoto block with the corresponding reason
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum BlockResponse {
    /// The Nakamoto block was accepted and therefore signed
    Accepted(NakamotoBlock),
    /// The Nakamoto block was rejected and therefore not signed
    Rejected(BlockRejection),
}

/// A rejection response from a signer for a proposed block
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlockRejection {
    /// The reason for the rejection
    pub reason: String,
    /// The reason code for the rejection
    pub reason_code: RejectCode,
    /// The block that was rejected
    pub block: NakamotoBlock,
}

/// This enum is used to supply a `reason_code` for block rejections
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RejectCode {
    /// RPC endpoint Validation failed
    ValidationFailed(ValidateRejectCode),
    /// Missing expected transactions
    MissingTransactions(Vec<Txid>),
}

impl From<Packet> for SignerMessage {
    fn from(packet: Packet) -> Self {
        Self::Packet(packet)
    }
}

impl From<BlockResponse> for SignerMessage {
    fn from(block_response: BlockResponse) -> Self {
        Self::BlockResponse(block_response)
    }
}

impl SignerMessage {
    /// Helper function to determine the slot ID for the provided stacker-db writer id
    pub fn slot_id(&self, id: u32) -> u32 {
        let slot_id = match self {
            Self::Packet(packet) => match packet.msg {
                Message::DkgBegin(_) => DKG_BEGIN_SLOT_ID,
                Message::DkgPrivateBegin(_) => DKG_PRIVATE_BEGIN_SLOT_ID,
                Message::DkgEnd(_) => DKG_END_SLOT_ID,
                Message::DkgPublicShares(_) => DKG_PUBLIC_SHARES_SLOT_ID,
                Message::DkgPrivateShares(_) => DKG_PRIVATE_SHARES_SLOT_ID,
                Message::NonceRequest(_) => NONCE_REQUEST_SLOT_ID,
                Message::NonceResponse(_) => NONCE_RESPONSE_SLOT_ID,
                Message::SignatureShareRequest(_) => SIGNATURE_SHARE_REQUEST_SLOT_ID,
                Message::SignatureShareResponse(_) => SIGNATURE_SHARE_RESPONSE_SLOT_ID,
            },
            Self::BlockResponse(_) => BLOCK_SLOT_ID,
        };
        SIGNER_SLOTS_PER_USER * id + slot_id
    }
}

/// The StackerDB client for communicating with the .signers contract
pub struct StackerDB {
    /// The stacker-db session for the signer StackerDB
    signers_stackerdb_session: StackerDBSession,
    /// The private key used in all stacks node communications
    stacks_private_key: StacksPrivateKey,
    /// A map of a slot ID to last chunk version
    slot_versions: HashMap<u32, u32>,
}

impl From<&Config> for StackerDB {
    fn from(config: &Config) -> Self {
        Self {
            signers_stackerdb_session: StackerDBSession::new(
                config.node_host,
                config.signers_stackerdb_contract_id.clone(),
            ),
            stacks_private_key: config.stacks_private_key,
            slot_versions: HashMap::new(),
        }
    }
}

impl StackerDB {
    /// Sends messages to the .signers stacker-db with an exponential backoff retry
    pub fn send_message_with_retry(
        &mut self,
        id: u32,
        message: SignerMessage,
    ) -> Result<StackerDBChunkAckData, ClientError> {
        let message_bytes = bincode::serialize(&message).unwrap();
        let slot_id = message.slot_id(id);

        loop {
            let slot_version = *self.slot_versions.entry(slot_id).or_insert(0) + 1;
            let mut chunk = StackerDBChunkData::new(slot_id, slot_version, message_bytes.clone());
            chunk.sign(&self.stacks_private_key)?;
            debug!("Sending a chunk to stackerdb!\n{:?}", &chunk);
            let send_request = || {
                self.signers_stackerdb_session
                    .put_chunk(&chunk)
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

    /// Retrieve the signer contract id
    pub fn signers_contract_id(&self) -> &QualifiedContractIdentifier {
        &self.signers_stackerdb_session.stackerdb_contract_id
    }
}
