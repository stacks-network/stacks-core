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

/// This is required for easy serialization of the various StackerDBMessage types
#[repr(u8)]
enum TypePrefix {
    Block,
    Packet,
}

impl TypePrefix {
    /// Convert a u8 to a TypePrefix
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Block),
            1 => Some(Self::Packet),
            _ => None,
        }
    }
}

impl From<&StackerDBMessage> for TypePrefix {
    fn from(message: &StackerDBMessage) -> TypePrefix {
        match message {
            StackerDBMessage::Block(_) => TypePrefix::Block,
            StackerDBMessage::Packet(_) => TypePrefix::Packet,
        }
    }
}

/// The StackerDB messages that can be sent through the .signers contract
pub enum StackerDBMessage {
    /// The latest Nakamoto block for miners to observe
    // TODO: update this to use a struct that lists optional error code if the block is invalid
    // to prove that the signers have considered the block but rejected it. This should include
    // hints about how to fix the block
    // Update to use NakamotoBlockProposal. Depends on https://github.com/stacks-network/stacks-core/pull/4084
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
    fn consensus_serialize<W: std::io::Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        fd.write_all(&[TypePrefix::from(self) as u8])
            .map_err(CodecError::WriteError)?;
        match self {
            StackerDBMessage::Packet(packet) => {
                let message_bytes = bincode::serialize(&packet)
                    .map_err(|e| CodecError::SerializeError(e.to_string()))?;
                message_bytes.consensus_serialize(fd)
            }
            StackerDBMessage::Block(block) => block.consensus_serialize(fd),
        }
    }

    fn consensus_deserialize<R: std::io::Read>(fd: &mut R) -> Result<Self, CodecError> {
        let mut prefix = [0];
        fd.read_exact(&mut prefix)
            .map_err(|e| CodecError::DeserializeError(e.to_string()))?;
        let prefix = TypePrefix::from_u8(prefix[0]).ok_or(CodecError::DeserializeError(
            "Bad StackerDBMessage prefix".into(),
        ))?;

        match prefix {
            TypePrefix::Packet => {
                let message_bytes = Vec::<u8>::consensus_deserialize(fd)?;
                let packet = bincode::deserialize(&message_bytes)
                    .map_err(|e| CodecError::DeserializeError(e.to_string()))?;
                Ok(Self::Packet(packet))
            }
            TypePrefix::Block => {
                let block = NakamotoBlock::consensus_deserialize(fd)?;
                Ok(StackerDBMessage::Block(block))
            }
        }
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
mod tests {
    use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
    use blockstack_lib::chainstate::stacks::StacksTransaction;
    use rand_core::OsRng;
    use stacks_common::codec::StacksMessageCodec;
    use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId, TrieHash};
    use stacks_common::util::hash::{MerkleTree, Sha512Trunc256Sum};
    use stacks_common::util::secp256k1::{MessageSignature, SchnorrSignature};
    use wsts::curve::scalar::Scalar;
    use wsts::net::{Message, Packet, Signable, SignatureShareRequest};

    use super::StackerDBMessage;

    #[test]
    fn serde_stackerdb_message_block() {
        let txs: Vec<StacksTransaction> = vec![];
        let mut header = NakamotoBlockHeader {
            version: 1,
            chain_length: 2,
            burn_spent: 3,
            consensus_hash: ConsensusHash([0x04; 20]),
            parent_block_id: StacksBlockId([0x05; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0x06; 32]),
            state_index_root: TrieHash([0x07; 32]),
            miner_signature: MessageSignature::empty(),
            signer_signature: SchnorrSignature::default(),
        };
        let txid_vecs = txs.iter().map(|tx| tx.txid().as_bytes().to_vec()).collect();

        let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
        let tx_merkle_root = merkle_tree.root();

        header.tx_merkle_root = tx_merkle_root;

        let block = NakamotoBlock { header, txs };

        let msg = StackerDBMessage::Block(block.clone());
        let serialized_bytes = msg.serialize_to_vec();
        let deserialized_msg =
            StackerDBMessage::consensus_deserialize(&mut &serialized_bytes[..]).unwrap();
        match deserialized_msg {
            StackerDBMessage::Block(deserialized_block) => {
                assert_eq!(deserialized_block, block);
            }
            _ => panic!("Wrong message type. Expected StackerDBMessage::Block"),
        }
    }

    #[test]
    fn serde_stackerdb_message_packet() {
        let mut rng = OsRng;
        let private_key = Scalar::random(&mut rng);
        let to_sign = "One, two, three, four, five? That's amazing. I've got the same combination on my luggage.".as_bytes();
        let sig_share_request = SignatureShareRequest {
            dkg_id: 1,
            sign_id: 5,
            sign_iter_id: 4,
            nonce_responses: vec![],
            message: to_sign.to_vec(),
            is_taproot: false,
            merkle_root: None,
        };
        let packet = Packet {
            sig: sig_share_request
                .sign(&private_key)
                .expect("Failed to sign SignatureShareRequest"),
            msg: Message::SignatureShareRequest(sig_share_request),
        };

        let msg = StackerDBMessage::Packet(packet.clone());
        let serialized_bytes = msg.serialize_to_vec();
        let deserialized_msg =
            StackerDBMessage::consensus_deserialize(&mut &serialized_bytes[..]).unwrap();
        match deserialized_msg {
            StackerDBMessage::Packet(deserialized_packet) => {
                assert_eq!(deserialized_packet.sig, packet.sig);
                match deserialized_packet.msg {
                    Message::SignatureShareRequest(deserialized_message) => {
                        assert_eq!(deserialized_message.dkg_id, 1);
                        assert_eq!(deserialized_message.sign_id, 5);
                        assert_eq!(deserialized_message.sign_iter_id, 4);
                        assert!(deserialized_message.nonce_responses.is_empty());
                        assert_eq!(deserialized_message.message.as_slice(), to_sign);
                        assert!(!deserialized_message.is_taproot);
                        assert!(deserialized_message.merkle_root.is_none());
                    }
                    _ => panic!("Wrong message type. Expected Message::SignatureShareRequest"),
                }
            }
            _ => panic!("Wrong message type. Expected StackerDBMessage::Packet."),
        }
    }
}
