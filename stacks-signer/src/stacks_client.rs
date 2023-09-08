use bincode::Error as BincodeError;
use frost_signer::{net::Message, signing_round::MessageTypes};
use hashbrown::HashMap;
use libsigner::{RPCError, SignerSession, StackerDBSession};
use libstackerdb::{Error as StackerDBError, StackerDBChunkAckData, StackerDBChunkData};
use slog::{slog_debug, slog_warn, slog_info};
use stacks_common::{debug, types::chainstate::StacksPrivateKey, warn, info};

use crate::config::Config;

const SLOTS_PER_USER: u32 = 16;

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

impl StacksClient {
    /// Sends messages to the stacker-db
    pub fn send_message(
        &mut self,
        id: u32,
        message: Message,
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
            info!("ACK: {:?}", &chunk_ack);
            if chunk_ack.accepted {
                debug!("Chunk accepted by stackerdb! ACK: {:?}", chunk_ack);
                return Ok(chunk_ack);
            }
            if let Some(reason) = chunk_ack.reason {
                // TODO: fix this jankiness. Update stackerdb to use an error code mapping instead of just a string
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
        // TODO: retrieve this from the stackerdb instance?
        SLOTS_PER_USER
    }
}

/// Helper function to determine the slot ID for the provided stacker-db writer id and the message type
fn slot_id(id: u32, message: &MessageTypes) -> u32 {
    let slot_id = match message {
        MessageTypes::DkgBegin(_) => 0,
        MessageTypes::DkgPrivateBegin(_) => 1,
        MessageTypes::DkgEnd(_) => 2,
        MessageTypes::DkgPublicEnd(_) => 3,
        MessageTypes::DkgPublicShare(_) => 4,
        MessageTypes::DkgPrivateShares(_) => 5,
        MessageTypes::NonceRequest(_) => 6,
        MessageTypes::NonceResponse(_) => 7,
        MessageTypes::SignShareRequest(_) => 8,
        MessageTypes::SignShareResponse(_) => 9,
    };
    SLOTS_PER_USER * id + slot_id
}
