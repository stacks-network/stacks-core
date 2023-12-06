use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use clarity::vm::types::QualifiedContractIdentifier;
use hashbrown::HashMap;
use libsigner::{SignerSession, StackerDBSession};
use libstackerdb::{StackerDBChunkAckData, StackerDBChunkData};
use slog::{slog_debug, slog_warn};
use stacks_common::codec::{Error as CodecError, StacksMessageCodec};
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
/// The number of miner slots available per miner
pub const MINER_SLOTS_PER_USER: u32 = 1;

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

/// The StackerDB messages that can be sent through the .signers contract
pub enum StackerDBMessage {
    /// The latest Nakamoto block for miners to observe
    // TODO: update this to use a struct that lists optional error code if the block is invalid
    // to prove that the signers have considered the block but rejected it. This should include
    // hints about how to fix the block
    Block(NakamotoBlock),
    /// DKG and Signing round data for other signers to observe
    Packet(Packet),
}

impl From<Packet> for StackerDBMessage {
    fn from(packet: Packet) -> Self {
        Self::Packet(packet)
    }
}

impl StacksMessageCodec for StackerDBMessage {
    fn consensus_serialize<W: std::io::Write>(&self, _fd: &mut W) -> Result<(), CodecError> {
        todo!()
    }

    fn consensus_deserialize<R: std::io::Read>(_fd: &mut R) -> Result<Self, CodecError> {
        todo!()
    }
}

impl StackerDBMessage {
    /// Helper function to determine the slot ID for the provided stacker-db writer id
    pub fn slot_id(&self, id: u32) -> u32 {
        let slot_id = match self {
            StackerDBMessage::Packet(packet) => match packet.msg {
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
            Self::Block(_block) => BLOCK_SLOT_ID,
        };
        SIGNER_SLOTS_PER_USER * id + slot_id
    }
}
/// The StackerDB client for communicating with both .signers and .miners contracts
pub struct StackerDB {
    /// The stacker-db session for the signer StackerDB
    signers_stackerdb_session: StackerDBSession,
    /// The stacker-db session for the .miners StackerDB
    miners_stackerdb_session: StackerDBSession,
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
            miners_stackerdb_session: StackerDBSession::new(
                config.node_host,
                config.miners_stackerdb_contract_id.clone(),
            ),
            stacks_private_key: config.stacks_private_key,
            slot_versions: HashMap::new(),
        }
    }
}

impl StackerDB {
    /// Sends messages to the stacker-db with an exponential backoff retry
    pub fn send_message_with_retry(
        &mut self,
        id: u32,
        message: StackerDBMessage,
    ) -> Result<StackerDBChunkAckData, ClientError> {
        let message_bytes = message.serialize_to_vec();
        let slot_id = message.slot_id(id);

        loop {
            let slot_version = *self.slot_versions.entry(slot_id).or_insert(0) + 1;
            let mut chunk = StackerDBChunkData::new(slot_id, slot_version, message_bytes.clone());
            chunk.sign(&self.stacks_private_key)?;
            debug!("Sending a chunk to stackerdb!\n{:?}", chunk.clone());
            let send_request = || {
                self.signers_stackerdb_session
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

    /// Retrieve the miner contract id
    pub fn miners_contract_id(&self) -> &QualifiedContractIdentifier {
        &self.miners_stackerdb_session.stackerdb_contract_id
    }

    /// Retrieve the signer contract id
    pub fn signers_contract_id(&self) -> &QualifiedContractIdentifier {
        &self.signers_stackerdb_session.stackerdb_contract_id
    }
}

#[cfg(test)]
mod tests {}
