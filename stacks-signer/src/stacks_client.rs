use bincode::Error as BincodeError;
use frost_signer::{net::Message, signing_round::MessageTypes};
use libsigner::{RPCError, SignerSession, StackerDBSession};
use libstackerdb::{Error as StackerDBError, StackerDBChunkAckData, StackerDBChunkData};
use slog::slog_debug;
use stacks_common::{debug, types::chainstate::StacksPrivateKey};

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
}

/// TODO: Add stacks node communication to this
/// The Stacks signer client used to communicate with the stacker-db instance
pub struct StacksClient {
    /// The stacker-db session
    stackerdb_session: StackerDBSession,
    /// The private key used in all stacks node communications
    stacks_private_key: StacksPrivateKey,
}

impl From<&Config> for StacksClient {
    fn from(config: &Config) -> Self {
        Self {
            stackerdb_session: StackerDBSession::new(
                config.node_host,
                config.stackerdb_contract_id.clone(),
            ),
            stacks_private_key: config.stacks_private_key,
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

        let mut chunk = StackerDBChunkData::new(slot_id(id, &message.msg), 1, message_bytes);
        chunk.sign(&self.stacks_private_key)?;
        let chunk_ack = self.stackerdb_session.put_chunk(chunk)?;
        debug!("{:?}", chunk_ack.clone());
        Ok(chunk_ack)
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
