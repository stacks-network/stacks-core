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

//! Messages in the signer-miner interaction have a multi-level hierarchy.
//! Signers send messages to each other through Packet messages. These messages,
//! as well as `BlockResponse`, `Transactions`, and `DkgResults` messages are stored
//! StackerDBs based on the `MessageSlotID` for the particular message type. This is a
//! shared identifier space between the four message kinds and their subtypes.
//!
//! These four message kinds are differentiated with a `SignerMessageTypePrefix`
//! and the `SignerMessage` enum.

use std::fmt::{Debug, Display};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;

use blockstack_lib::chainstate::nakamoto::signer_set::NakamotoSigners;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::events::StackerDBChunksEvent;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::net::api::postblock_proposal::{
    BlockValidateReject, BlockValidateResponse, ValidateRejectCode,
};
use blockstack_lib::util_lib::boot::boot_code_id;
use clarity::util::retry::BoundReader;
use clarity::util::secp256k1::MessageSignature;
use clarity::vm::types::serialization::SerializationError;
use clarity::vm::types::QualifiedContractIdentifier;
use hashbrown::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use stacks_common::codec::{
    read_next, read_next_at_most, read_next_exact, write_next, Error as CodecError,
    StacksMessageCodec,
};
use stacks_common::consts::SIGNER_SLOTS_PER_USER;
use stacks_common::util::hash::Sha512Trunc256Sum;
use tiny_http::{
    Method as HttpMethod, Request as HttpRequest, Response as HttpResponse, Server as HttpServer,
};

use crate::http::{decode_http_body, decode_http_request};
use crate::{BlockProposal, EventError};

define_u8_enum!(
/// Enum representing the stackerdb message identifier: this is
///  the contract index in the signers contracts (i.e., X in signers-0-X)
MessageSlotID {
    /// Block Proposal message from miners
    BlockProposal = 0,
    /// Block Response message from signers
    BlockResponse = 1
});

define_u8_enum!(
/// Enum representing the SignerMessage type prefix
SignerMessageTypePrefix {
    /// Block Proposal message from miners
    BlockProposal = 0,
    /// Block Response message from signers
    BlockResponse = 1
});

#[cfg_attr(test, mutants::skip)]
impl MessageSlotID {
    /// Return the StackerDB contract corresponding to messages of this type
    pub fn stacker_db_contract(
        &self,
        mainnet: bool,
        reward_cycle: u64,
    ) -> QualifiedContractIdentifier {
        NakamotoSigners::make_signers_db_contract_id(reward_cycle, self.to_u32(), mainnet)
    }

    /// Return the u32 identifier for the message slot (used to index the contract that stores it)
    pub fn to_u32(self) -> u32 {
        self.to_u8().into()
    }
}

#[cfg_attr(test, mutants::skip)]
impl Display for MessageSlotID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}({})", self, self.to_u8())
    }
}

impl TryFrom<u8> for SignerMessageTypePrefix {
    type Error = CodecError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_u8(value).ok_or_else(|| {
            CodecError::DeserializeError(format!("Unknown signer message type prefix: {value}"))
        })
    }
}

impl From<&SignerMessage> for SignerMessageTypePrefix {
    #[cfg_attr(test, mutants::skip)]
    fn from(message: &SignerMessage) -> Self {
        match message {
            SignerMessage::BlockProposal(_) => SignerMessageTypePrefix::BlockProposal,
            SignerMessage::BlockResponse(_) => SignerMessageTypePrefix::BlockResponse,
        }
    }
}

/// The messages being sent through the stacker db contracts
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum SignerMessage {
    /// The block proposal from miners for signers to observe and sign
    BlockProposal(BlockProposal),
    /// The block response from signers for miners to observe
    BlockResponse(BlockResponse),
}

impl Debug for SignerMessage {
    #[cfg_attr(test, mutants::skip)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlockProposal(b) => Debug::fmt(b, f),
            Self::BlockResponse(b) => Debug::fmt(b, f),
        }
    }
}

impl SignerMessage {
    /// Helper function to determine the slot ID for the provided stacker-db writer id
    #[cfg_attr(test, mutants::skip)]
    pub fn msg_id(&self) -> MessageSlotID {
        match self {
            Self::BlockProposal(_) => MessageSlotID::BlockProposal,
            Self::BlockResponse(_) => MessageSlotID::BlockResponse,
        }
    }
}

impl StacksMessageCodec for SignerMessage {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &(SignerMessageTypePrefix::from(self) as u8))?;
        match self {
            SignerMessage::BlockProposal(block_proposal) => {
                write_next(fd, block_proposal)?;
            }
            SignerMessage::BlockResponse(block_response) => {
                write_next(fd, block_response)?;
            }
        };
        Ok(())
    }

    #[cfg_attr(test, mutants::skip)]
    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let type_prefix_byte = read_next::<u8, _>(fd)?;
        let type_prefix = SignerMessageTypePrefix::try_from(type_prefix_byte)?;
        let message = match type_prefix {
            SignerMessageTypePrefix::BlockProposal => {
                let block_proposal = read_next::<BlockProposal, _>(fd)?;
                SignerMessage::BlockProposal(block_proposal)
            }
            SignerMessageTypePrefix::BlockResponse => {
                let block_response = read_next::<BlockResponse, _>(fd)?;
                SignerMessage::BlockResponse(block_response)
            }
        };
        Ok(message)
    }
}

/// Work around for the fact that a lot of the structs being desierialized are not defined in messages.rs
pub trait StacksMessageCodecExtensions: Sized {
    /// Serialize the struct to the provided writer
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError>;
    /// Deserialize the struct from the provided reader
    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError>;
}

define_u8_enum!(
/// Enum representing the reject code type prefix
RejectCodeTypePrefix {
    /// The block was rejected due to validation issues
    ValidationFailed = 0,
    /// The block was rejected due to connectivity issues with the signer
    ConnectivityIssues = 1
});

impl TryFrom<u8> for RejectCodeTypePrefix {
    type Error = CodecError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_u8(value).ok_or_else(|| {
            CodecError::DeserializeError(format!("Unknown reject code type prefix: {value}"))
        })
    }
}

impl From<&RejectCode> for RejectCodeTypePrefix {
    fn from(reject_code: &RejectCode) -> Self {
        match reject_code {
            RejectCode::ValidationFailed(_) => RejectCodeTypePrefix::ValidationFailed,
            RejectCode::ConnectivityIssues => RejectCodeTypePrefix::ConnectivityIssues,
        }
    }
}

/// This enum is used to supply a `reason_code` for block rejections
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RejectCode {
    /// RPC endpoint Validation failed
    ValidationFailed(ValidateRejectCode),
    /// The block was rejected due to connectivity issues with the signer
    ConnectivityIssues,
}

define_u8_enum!(
/// Enum representing the BlockResponse type prefix
BlockResponseTypePrefix {
    /// An accepted block response
    Accepted = 0,
    /// A rejected block response
    Rejected = 1
});

impl TryFrom<u8> for BlockResponseTypePrefix {
    type Error = CodecError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_u8(value).ok_or_else(|| {
            CodecError::DeserializeError(format!("Unknown block response type prefix: {value}"))
        })
    }
}

impl From<&BlockResponse> for BlockResponseTypePrefix {
    fn from(block_response: &BlockResponse) -> Self {
        match block_response {
            BlockResponse::Accepted(_) => BlockResponseTypePrefix::Accepted,
            BlockResponse::Rejected(_) => BlockResponseTypePrefix::Rejected,
        }
    }
}

/// The response that a signer sends back to observing miners
/// either accepting or rejecting a Nakamoto block with the corresponding reason
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum BlockResponse {
    /// The Nakamoto block was accepted and therefore signed
    Accepted((Sha512Trunc256Sum, MessageSignature)),
    /// The Nakamoto block was rejected and therefore not signed
    Rejected(BlockRejection),
}

#[cfg_attr(test, mutants::skip)]
impl std::fmt::Display for BlockResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockResponse::Accepted(a) => {
                write!(
                    f,
                    "BlockAccepted: signer_sighash = {}, signature = {}",
                    a.0, a.1
                )
            }
            BlockResponse::Rejected(r) => {
                write!(
                    f,
                    "BlockRejected: signer_sighash = {}, code = {}, reason = {}",
                    r.reason_code, r.reason, r.signer_signature_hash
                )
            }
        }
    }
}

impl BlockResponse {
    /// Create a new accepted BlockResponse for the provided block signer signature hash and signature
    pub fn accepted(hash: Sha512Trunc256Sum, sig: MessageSignature) -> Self {
        Self::Accepted((hash, sig))
    }

    /// Create a new rejected BlockResponse for the provided block signer signature hash and rejection code
    pub fn rejected(hash: Sha512Trunc256Sum, reject_code: RejectCode) -> Self {
        Self::Rejected(BlockRejection::new(hash, reject_code))
    }
}

impl StacksMessageCodec for BlockResponse {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &(BlockResponseTypePrefix::from(self) as u8))?;
        match self {
            BlockResponse::Accepted((hash, sig)) => {
                write_next(fd, hash)?;
                write_next(fd, sig)?;
            }
            BlockResponse::Rejected(rejection) => {
                write_next(fd, rejection)?;
            }
        };
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let type_prefix_byte = read_next::<u8, _>(fd)?;
        let type_prefix = BlockResponseTypePrefix::try_from(type_prefix_byte)?;
        let response = match type_prefix {
            BlockResponseTypePrefix::Accepted => {
                let hash = read_next::<Sha512Trunc256Sum, _>(fd)?;
                let sig = read_next::<MessageSignature, _>(fd)?;
                BlockResponse::Accepted((hash, sig))
            }
            BlockResponseTypePrefix::Rejected => {
                let rejection = read_next::<BlockRejection, _>(fd)?;
                BlockResponse::Rejected(rejection)
            }
        };
        Ok(response)
    }
}

/// A rejection response from a signer for a proposed block
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlockRejection {
    /// The reason for the rejection
    pub reason: String,
    /// The reason code for the rejection
    pub reason_code: RejectCode,
    /// The signer signature hash of the block that was rejected
    pub signer_signature_hash: Sha512Trunc256Sum,
}

impl BlockRejection {
    /// Create a new BlockRejection for the provided block and reason code
    pub fn new(signer_signature_hash: Sha512Trunc256Sum, reason_code: RejectCode) -> Self {
        Self {
            reason: reason_code.to_string(),
            reason_code,
            signer_signature_hash,
        }
    }
}

impl StacksMessageCodec for BlockRejection {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.reason.as_bytes().to_vec())?;
        write_next(fd, &self.reason_code)?;
        write_next(fd, &self.signer_signature_hash)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let reason_bytes = read_next::<Vec<u8>, _>(fd)?;
        let reason = String::from_utf8(reason_bytes).map_err(|e| {
            CodecError::DeserializeError(format!("Failed to decode reason string: {:?}", &e))
        })?;
        let reason_code = read_next::<RejectCode, _>(fd)?;
        let signer_signature_hash = read_next::<Sha512Trunc256Sum, _>(fd)?;
        Ok(Self {
            reason,
            reason_code,
            signer_signature_hash,
        })
    }
}

impl From<BlockValidateReject> for BlockRejection {
    fn from(reject: BlockValidateReject) -> Self {
        Self {
            reason: reject.reason,
            reason_code: RejectCode::ValidationFailed(reject.reason_code),
            signer_signature_hash: reject.signer_signature_hash,
        }
    }
}

impl StacksMessageCodec for RejectCode {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &(RejectCodeTypePrefix::from(self) as u8))?;
        // Do not do a single match here as we may add other variants in the future and don't want to miss adding it
        match self {
            RejectCode::ValidationFailed(code) => write_next(fd, &(*code as u8))?,
            RejectCode::ConnectivityIssues => {
                // No additional data to serialize / deserialize
            }
        };
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let type_prefix_byte = read_next::<u8, _>(fd)?;
        let type_prefix = RejectCodeTypePrefix::try_from(type_prefix_byte)?;
        let code = match type_prefix {
            RejectCodeTypePrefix::ValidationFailed => RejectCode::ValidationFailed(
                ValidateRejectCode::try_from(read_next::<u8, _>(fd)?).map_err(|e| {
                    CodecError::DeserializeError(format!(
                        "Failed to decode validation reject code: {:?}",
                        &e
                    ))
                })?,
            ),
            RejectCodeTypePrefix::ConnectivityIssues => RejectCode::ConnectivityIssues,
        };
        Ok(code)
    }
}

#[cfg_attr(test, mutants::skip)]
impl std::fmt::Display for RejectCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RejectCode::ValidationFailed(code) => write!(f, "Validation failed: {:?}", code),
            RejectCode::ConnectivityIssues => write!(
                f,
                "The block was rejected due to connectivity issues with the signer."
            ),
        }
    }
}

impl From<BlockResponse> for SignerMessage {
    fn from(block_response: BlockResponse) -> Self {
        Self::BlockResponse(block_response)
    }
}

impl From<BlockRejection> for SignerMessage {
    fn from(block_rejection: BlockRejection) -> Self {
        Self::BlockResponse(BlockResponse::Rejected(block_rejection))
    }
}

impl From<BlockValidateReject> for SignerMessage {
    fn from(rejection: BlockValidateReject) -> Self {
        Self::BlockResponse(BlockResponse::Rejected(rejection.into()))
    }
}

#[cfg(test)]
mod test {
    use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
    use blockstack_lib::chainstate::stacks::{
        ThresholdSignature, TransactionAnchorMode, TransactionAuth, TransactionPayload,
        TransactionPostConditionMode, TransactionSmartContract, TransactionVersion,
    };
    use blockstack_lib::util_lib::strings::StacksString;
    use clarity::types::chainstate::{ConsensusHash, StacksBlockId, TrieHash};
    use clarity::util::hash::MerkleTree;
    use clarity::util::secp256k1::MessageSignature;
    use rand::{thread_rng, Rng, RngCore};
    use rand_core::OsRng;
    use stacks_common::bitvec::BitVec;
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use stacks_common::types::chainstate::StacksPrivateKey;

    use super::{StacksMessageCodecExtensions, *};

    #[test]
    fn signer_slots_count_is_sane() {
        let slot_identifiers_len = MessageSlotID::ALL.len();
        assert!(
            SIGNER_SLOTS_PER_USER as usize >= slot_identifiers_len,
            "stacks_common::SIGNER_SLOTS_PER_USER ({}) must be >= slot identifiers ({})",
            SIGNER_SLOTS_PER_USER,
            slot_identifiers_len,
        );
    }

    #[test]
    fn serde_reject_code() {
        let code = RejectCode::ValidationFailed(ValidateRejectCode::InvalidBlock);
        let serialized_code = code.serialize_to_vec();
        let deserialized_code = read_next::<RejectCode, _>(&mut &serialized_code[..])
            .expect("Failed to deserialize RejectCode");
        assert_eq!(code, deserialized_code);

        let code = RejectCode::ConnectivityIssues;
        let serialized_code = code.serialize_to_vec();
        let deserialized_code = read_next::<RejectCode, _>(&mut &serialized_code[..])
            .expect("Failed to deserialize RejectCode");
        assert_eq!(code, deserialized_code);
    }

    #[test]
    fn serde_block_rejection() {
        let rejection = BlockRejection::new(
            Sha512Trunc256Sum([0u8; 32]),
            RejectCode::ValidationFailed(ValidateRejectCode::InvalidBlock),
        );
        let serialized_rejection = rejection.serialize_to_vec();
        let deserialized_rejection = read_next::<BlockRejection, _>(&mut &serialized_rejection[..])
            .expect("Failed to deserialize BlockRejection");
        assert_eq!(rejection, deserialized_rejection);

        let rejection =
            BlockRejection::new(Sha512Trunc256Sum([1u8; 32]), RejectCode::ConnectivityIssues);
        let serialized_rejection = rejection.serialize_to_vec();
        let deserialized_rejection = read_next::<BlockRejection, _>(&mut &serialized_rejection[..])
            .expect("Failed to deserialize BlockRejection");
        assert_eq!(rejection, deserialized_rejection);
    }

    #[test]
    fn serde_block_response() {
        let response =
            BlockResponse::Accepted((Sha512Trunc256Sum([0u8; 32]), MessageSignature::empty()));
        let serialized_response = response.serialize_to_vec();
        let deserialized_response = read_next::<BlockResponse, _>(&mut &serialized_response[..])
            .expect("Failed to deserialize BlockResponse");
        assert_eq!(response, deserialized_response);

        let response = BlockResponse::Rejected(BlockRejection::new(
            Sha512Trunc256Sum([1u8; 32]),
            RejectCode::ValidationFailed(ValidateRejectCode::InvalidBlock),
        ));
        let serialized_response = response.serialize_to_vec();
        let deserialized_response = read_next::<BlockResponse, _>(&mut &serialized_response[..])
            .expect("Failed to deserialize BlockResponse");
        assert_eq!(response, deserialized_response);
    }

    #[test]
    fn serde_signer_message() {
        let signer_message = SignerMessage::BlockResponse(BlockResponse::Accepted((
            Sha512Trunc256Sum([2u8; 32]),
            MessageSignature::empty(),
        )));
        let serialized_signer_message = signer_message.serialize_to_vec();
        let deserialized_signer_message =
            read_next::<SignerMessage, _>(&mut &serialized_signer_message[..])
                .expect("Failed to deserialize SignerMessage");
        assert_eq!(signer_message, deserialized_signer_message);

        let header = NakamotoBlockHeader::empty();
        let mut block = NakamotoBlock {
            header,
            txs: vec![],
        };
        let tx_merkle_root = {
            let txid_vecs = block
                .txs
                .iter()
                .map(|tx| tx.txid().as_bytes().to_vec())
                .collect();

            MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
        };
        block.header.tx_merkle_root = tx_merkle_root;

        let block_proposal = BlockProposal {
            block,
            burn_height: thread_rng().next_u64(),
            reward_cycle: thread_rng().next_u64(),
        };
        let signer_message = SignerMessage::BlockProposal(block_proposal);
        let serialized_signer_message = signer_message.serialize_to_vec();
        let deserialized_signer_message =
            read_next::<SignerMessage, _>(&mut &serialized_signer_message[..])
                .expect("Failed to deserialize SignerMessage");
        assert_eq!(signer_message, deserialized_signer_message);
    }
}
