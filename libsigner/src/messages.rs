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

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::boot::{MINERS_NAME, SIGNERS_NAME};
use blockstack_lib::chainstate::stacks::events::StackerDBChunksEvent;
use blockstack_lib::chainstate::stacks::{StacksTransaction, ThresholdSignature};
use blockstack_lib::net::api::postblock_proposal::{
    BlockValidateReject, BlockValidateResponse, ValidateRejectCode,
};
use blockstack_lib::util_lib::boot::boot_code_id;
use clarity::vm::types::serialization::SerializationError;
use clarity::vm::types::QualifiedContractIdentifier;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use stacks_common::codec::{
    read_next, read_next_at_most, read_next_exact, write_next, Error as CodecError,
    StacksMessageCodec,
};
use stacks_common::util::hash::Sha512Trunc256Sum;
use tiny_http::{
    Method as HttpMethod, Request as HttpRequest, Response as HttpResponse, Server as HttpServer,
};
use wsts::common::{PolyCommitment, PublicNonce, Signature, SignatureShare};
use wsts::curve::point::{Compressed, Point};
use wsts::curve::scalar::Scalar;
use wsts::net::{
    DkgBegin, DkgEnd, DkgEndBegin, DkgPrivateBegin, DkgPrivateShares, DkgPublicShares, DkgStatus,
    Message, NonceRequest, NonceResponse, Packet, SignatureShareRequest, SignatureShareResponse,
};
use wsts::schnorr::ID;
use wsts::state_machine::signer;

use crate::http::{decode_http_body, decode_http_request};
use crate::EventError;

/// Temporary placeholder for the number of slots allocated to a stacker-db writer. This will be retrieved from the stacker-db instance in the future
/// See: https://github.com/stacks-network/stacks-blockchain/issues/3921
/// Is equal to the number of message types
pub const SIGNER_SLOTS_PER_USER: u32 = 12;

// The slot IDS for each message type
const DKG_BEGIN_SLOT_ID: u32 = 0;
const DKG_PRIVATE_BEGIN_SLOT_ID: u32 = 1;
const DKG_END_BEGIN_SLOT_ID: u32 = 2;
const DKG_END_SLOT_ID: u32 = 3;
const DKG_PUBLIC_SHARES_SLOT_ID: u32 = 4;
const DKG_PRIVATE_SHARES_SLOT_ID: u32 = 5;
const NONCE_REQUEST_SLOT_ID: u32 = 6;
const NONCE_RESPONSE_SLOT_ID: u32 = 7;
const SIGNATURE_SHARE_REQUEST_SLOT_ID: u32 = 8;
const SIGNATURE_SHARE_RESPONSE_SLOT_ID: u32 = 9;
/// The slot ID for the block response for miners to observe
pub const BLOCK_SLOT_ID: u32 = 10;
/// The slot ID for the transactions list for miners and signers to observe
pub const TRANSACTIONS_SLOT_ID: u32 = 11;

define_u8_enum!(SignerMessageTypePrefix {
    BlockResponse = 0,
    Packet = 1,
    Transactions = 2
});

impl TryFrom<u8> for SignerMessageTypePrefix {
    type Error = CodecError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_u8(value).ok_or_else(|| {
            CodecError::DeserializeError(format!("Unknown signer message type prefix: {value}"))
        })
    }
}

impl From<&SignerMessage> for SignerMessageTypePrefix {
    fn from(message: &SignerMessage) -> Self {
        match message {
            SignerMessage::Packet(_) => SignerMessageTypePrefix::Packet,
            SignerMessage::BlockResponse(_) => SignerMessageTypePrefix::BlockResponse,
            SignerMessage::Transactions(_) => SignerMessageTypePrefix::Transactions,
        }
    }
}

define_u8_enum!(MessageTypePrefix {
    DkgBegin = 0,
    DkgPrivateBegin = 1,
    DkgEndBegin = 2,
    DkgEnd = 3,
    DkgPublicShares = 4,
    DkgPrivateShares = 5,
    NonceRequest = 6,
    NonceResponse = 7,
    SignatureShareRequest = 8,
    SignatureShareResponse = 9
});

impl From<&Message> for MessageTypePrefix {
    fn from(msg: &Message) -> Self {
        match msg {
            Message::DkgBegin(_) => MessageTypePrefix::DkgBegin,
            Message::DkgPrivateBegin(_) => MessageTypePrefix::DkgPrivateBegin,
            Message::DkgEndBegin(_) => MessageTypePrefix::DkgEndBegin,
            Message::DkgEnd(_) => MessageTypePrefix::DkgEnd,
            Message::DkgPublicShares(_) => MessageTypePrefix::DkgPublicShares,
            Message::DkgPrivateShares(_) => MessageTypePrefix::DkgPrivateShares,
            Message::NonceRequest(_) => MessageTypePrefix::NonceRequest,
            Message::NonceResponse(_) => MessageTypePrefix::NonceResponse,
            Message::SignatureShareRequest(_) => MessageTypePrefix::SignatureShareRequest,
            Message::SignatureShareResponse(_) => MessageTypePrefix::SignatureShareResponse,
        }
    }
}

impl TryFrom<u8> for MessageTypePrefix {
    type Error = CodecError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_u8(value).ok_or_else(|| {
            CodecError::DeserializeError(format!("Unknown packet type prefix: {value}"))
        })
    }
}

define_u8_enum!(RejectCodeTypePrefix{
    ValidationFailed = 0,
    SignedRejection = 1,
    InsufficientSigners = 2,
    MissingTransactions = 3,
    ConnectivityIssues = 4
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
            RejectCode::SignedRejection(_) => RejectCodeTypePrefix::SignedRejection,
            RejectCode::InsufficientSigners(_) => RejectCodeTypePrefix::InsufficientSigners,
            RejectCode::MissingTransactions(_) => RejectCodeTypePrefix::MissingTransactions,
            RejectCode::ConnectivityIssues => RejectCodeTypePrefix::ConnectivityIssues,
        }
    }
}

/// The messages being sent through the stacker db contracts
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum SignerMessage {
    /// The signed/validated Nakamoto block for miners to observe
    BlockResponse(BlockResponse),
    /// DKG and Signing round data for other signers to observe
    Packet(Packet),
    /// The list of transactions for miners and signers to observe that this signer cares about
    Transactions(Vec<StacksTransaction>),
}

impl StacksMessageCodec for SignerMessage {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &(SignerMessageTypePrefix::from(self) as u8))?;
        match self {
            SignerMessage::Packet(packet) => {
                packet.inner_consensus_serialize(fd)?;
            }
            SignerMessage::BlockResponse(block_response) => {
                write_next(fd, block_response)?;
            }
            SignerMessage::Transactions(transactions) => {
                write_next(fd, transactions)?;
            }
        };
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let type_prefix_byte = read_next::<u8, _>(fd)?;
        let type_prefix = SignerMessageTypePrefix::try_from(type_prefix_byte)?;
        let message = match type_prefix {
            SignerMessageTypePrefix::Packet => {
                let packet = Packet::inner_consensus_deserialize(fd)?;
                SignerMessage::Packet(packet)
            }
            SignerMessageTypePrefix::BlockResponse => {
                let block_response = read_next::<BlockResponse, _>(fd)?;
                SignerMessage::BlockResponse(block_response)
            }
            SignerMessageTypePrefix::Transactions => {
                let transactions = read_next::<Vec<StacksTransaction>, _>(fd)?;
                SignerMessage::Transactions(transactions)
            }
        };
        Ok(message)
    }
}

/// Work around for the fact that a lot of the structs being desierialized are not defined in messages.rs
pub trait StacksMessageCodecExtensions: Sized {
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError>;
    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError>;
}

impl StacksMessageCodecExtensions for Scalar {
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.to_bytes())
    }
    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let scalar_bytes = read_next::<[u8; 32], _>(fd)?;
        Ok(Scalar::from(scalar_bytes))
    }
}

impl StacksMessageCodecExtensions for Point {
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.compress().as_bytes().to_vec())
    }
    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let compressed_bytes: Vec<u8> = read_next(fd)?;
        let compressed = Compressed::try_from(compressed_bytes.as_slice())
            .map_err(|e| CodecError::DeserializeError(e.to_string()))?;
        Ok(
            Point::try_from(&compressed)
                .map_err(|e| CodecError::DeserializeError(e.to_string()))?,
        )
    }
}

impl StacksMessageCodecExtensions for DkgBegin {
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.dkg_id)
    }
    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let dkg_id = read_next::<u64, _>(fd)?;
        Ok(DkgBegin { dkg_id })
    }
}

impl StacksMessageCodecExtensions for DkgPrivateBegin {
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.dkg_id)?;
        write_next(fd, &self.signer_ids)?;
        write_next(fd, &self.key_ids)
    }
    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let dkg_id = read_next::<u64, _>(fd)?;
        let signer_ids = read_next::<Vec<u32>, _>(fd)?;
        let key_ids = read_next::<Vec<u32>, _>(fd)?;
        Ok(DkgPrivateBegin {
            dkg_id,
            signer_ids,
            key_ids,
        })
    }
}

impl StacksMessageCodecExtensions for DkgEndBegin {
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.dkg_id)?;
        write_next(fd, &self.signer_ids)?;
        write_next(fd, &self.key_ids)
    }
    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let dkg_id = read_next::<u64, _>(fd)?;
        let signer_ids = read_next::<Vec<u32>, _>(fd)?;
        let key_ids = read_next::<Vec<u32>, _>(fd)?;
        Ok(DkgEndBegin {
            dkg_id,
            signer_ids,
            key_ids,
        })
    }
}

impl StacksMessageCodecExtensions for DkgEnd {
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.dkg_id)?;
        write_next(fd, &self.signer_id)?;
        match &self.status {
            DkgStatus::Success => write_next(fd, &0u8),
            DkgStatus::Failure(failure) => {
                write_next(fd, &1u8)?;
                write_next(fd, &failure.as_bytes().to_vec())
            }
        }
    }
    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let dkg_id = read_next::<u64, _>(fd)?;
        let signer_id = read_next::<u32, _>(fd)?;
        let status_type_prefix = read_next::<u8, _>(fd)?;
        let status = match status_type_prefix {
            0 => DkgStatus::Success,
            1 => {
                let failure_bytes: Vec<u8> = read_next(fd)?;
                let failure = String::from_utf8(failure_bytes)
                    .map_err(|e| CodecError::DeserializeError(e.to_string()))?;
                DkgStatus::Failure(failure)
            }
            _ => {
                return Err(CodecError::DeserializeError(format!(
                    "Unknown DKG status type prefix: {}",
                    status_type_prefix
                )))
            }
        };
        Ok(DkgEnd {
            dkg_id,
            signer_id,
            status,
        })
    }
}

impl StacksMessageCodecExtensions for DkgPublicShares {
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.dkg_id)?;
        write_next(fd, &self.signer_id)?;
        write_next(fd, &(self.comms.len() as u32))?;
        for (id, comm) in &self.comms {
            write_next(fd, id)?;
            comm.id.id.inner_consensus_serialize(fd)?;
            comm.id.kG.inner_consensus_serialize(fd)?;
            comm.id.kca.inner_consensus_serialize(fd)?;
            write_next(fd, &(comm.poly.len() as u32))?;
            for poly in comm.poly.iter() {
                poly.inner_consensus_serialize(fd)?
            }
        }
        Ok(())
    }

    #[allow(non_snake_case)]
    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let dkg_id = read_next::<u64, _>(fd)?;
        let signer_id = read_next::<u32, _>(fd)?;
        let num_shares = read_next::<u32, _>(fd)?;
        let mut comms = Vec::new();
        for _ in 0..num_shares {
            let id = read_next::<u32, _>(fd)?;
            let scalar_id = Scalar::inner_consensus_deserialize(fd)?;
            let kG = Point::inner_consensus_deserialize(fd)?;
            let kca = Scalar::inner_consensus_deserialize(fd)?;
            let num_poly_coeffs = read_next::<u32, _>(fd)?;
            let mut poly = Vec::new();
            for _ in 0..num_poly_coeffs {
                poly.push(Point::inner_consensus_deserialize(fd)?);
            }
            comms.push((
                id,
                PolyCommitment {
                    id: ID {
                        id: scalar_id,
                        kG,
                        kca,
                    },
                    poly,
                },
            ));
        }
        Ok(DkgPublicShares {
            dkg_id,
            signer_id,
            comms,
        })
    }
}

impl StacksMessageCodecExtensions for DkgPrivateShares {
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.dkg_id)?;
        write_next(fd, &self.signer_id)?;
        write_next(fd, &(self.shares.len() as u32))?;
        for (id, share_map) in &self.shares {
            write_next(fd, id)?;
            write_next(fd, &(share_map.len() as u32))?;
            for (id, share) in share_map {
                write_next(fd, id)?;
                write_next(fd, share)?;
            }
        }
        Ok(())
    }

    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let dkg_id = read_next::<u64, _>(fd)?;
        let signer_id = read_next::<u32, _>(fd)?;
        let num_shares = read_next::<u32, _>(fd)?;
        let mut shares = Vec::new();
        for _ in 0..num_shares {
            let id = read_next::<u32, _>(fd)?;
            let num_share_map = read_next::<u32, _>(fd)?;
            let mut share_map = HashMap::new();
            for _ in 0..num_share_map {
                let id = read_next::<u32, _>(fd)?;
                let share: Vec<u8> = read_next(fd)?;
                share_map.insert(id, share);
            }
            shares.push((id, share_map));
        }
        Ok(DkgPrivateShares {
            dkg_id,
            signer_id,
            shares,
        })
    }
}

impl StacksMessageCodecExtensions for NonceRequest {
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.dkg_id)?;
        write_next(fd, &self.sign_id)?;
        write_next(fd, &self.sign_iter_id)?;
        write_next(fd, &self.message)?;
        write_next(fd, &(self.is_taproot as u8))?;
        write_next(fd, &(self.merkle_root.is_some() as u8))?;
        if let Some(merkle_root) = self.merkle_root {
            write_next(fd, &merkle_root)?;
        }
        Ok(())
    }

    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let dkg_id = read_next::<u64, _>(fd)?;
        let sign_id = read_next::<u64, _>(fd)?;
        let sign_iter_id = read_next::<u64, _>(fd)?;
        let message = read_next::<Vec<u8>, _>(fd)?;
        let is_taproot = read_next::<u8, _>(fd)? != 0;
        let has_merkle_root = read_next::<u8, _>(fd)? != 0;
        let merkle_root = if has_merkle_root {
            Some(read_next::<[u8; 32], _>(fd)?)
        } else {
            None
        };

        Ok(NonceRequest {
            dkg_id,
            sign_id,
            sign_iter_id,
            message,
            is_taproot,
            merkle_root,
        })
    }
}

impl StacksMessageCodecExtensions for NonceResponse {
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.dkg_id)?;
        write_next(fd, &self.sign_id)?;
        write_next(fd, &self.sign_iter_id)?;
        write_next(fd, &self.signer_id)?;
        write_next(fd, &self.key_ids)?;
        write_next(fd, &(self.nonces.len() as u32))?;
        for nonce in &self.nonces {
            nonce.D.inner_consensus_serialize(fd)?;
            nonce.E.inner_consensus_serialize(fd)?;
        }
        write_next(fd, &self.message)?;
        Ok(())
    }

    #[allow(non_snake_case)]
    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let dkg_id = read_next::<u64, _>(fd)?;
        let sign_id = read_next::<u64, _>(fd)?;
        let sign_iter_id = read_next::<u64, _>(fd)?;
        let signer_id = read_next::<u32, _>(fd)?;
        let key_ids = read_next::<Vec<u32>, _>(fd)?;
        let num_nonces = read_next::<u32, _>(fd)?;
        let mut nonces = Vec::new();
        for _ in 0..num_nonces {
            let D = Point::inner_consensus_deserialize(fd)?;
            let E = Point::inner_consensus_deserialize(fd)?;
            nonces.push(PublicNonce { D, E });
        }
        let message = read_next::<Vec<u8>, _>(fd)?;

        Ok(NonceResponse {
            dkg_id,
            sign_id,
            sign_iter_id,
            signer_id,
            key_ids,
            nonces,
            message,
        })
    }
}

impl StacksMessageCodecExtensions for SignatureShareRequest {
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.dkg_id)?;
        write_next(fd, &self.sign_id)?;
        write_next(fd, &self.sign_iter_id)?;
        write_next(fd, &(self.nonce_responses.len() as u32))?;
        for nonce_response in &self.nonce_responses {
            nonce_response.inner_consensus_serialize(fd)?;
        }
        write_next(fd, &self.message)?;
        write_next(fd, &(self.is_taproot as u8))?;
        write_next(fd, &(self.merkle_root.is_some() as u8))?;
        if let Some(merkle_root) = self.merkle_root {
            write_next(fd, &merkle_root)?;
        }
        Ok(())
    }

    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let dkg_id = read_next::<u64, _>(fd)?;
        let sign_id = read_next::<u64, _>(fd)?;
        let sign_iter_id = read_next::<u64, _>(fd)?;
        let num_nonce_responses = read_next::<u32, _>(fd)?;
        let mut nonce_responses = Vec::new();
        for _ in 0..num_nonce_responses {
            nonce_responses.push(NonceResponse::inner_consensus_deserialize(fd)?);
        }
        let message = read_next::<Vec<u8>, _>(fd)?;
        let is_taproot = read_next::<u8, _>(fd)? != 0;
        let has_merkle_root = read_next::<u8, _>(fd)? != 0;
        let merkle_root = if has_merkle_root {
            Some(read_next::<[u8; 32], _>(fd)?)
        } else {
            None
        };

        Ok(SignatureShareRequest {
            dkg_id,
            sign_id,
            sign_iter_id,
            nonce_responses,
            message,
            is_taproot,
            merkle_root,
        })
    }
}

impl StacksMessageCodecExtensions for SignatureShareResponse {
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.dkg_id)?;
        write_next(fd, &self.sign_id)?;
        write_next(fd, &self.sign_iter_id)?;
        write_next(fd, &self.signer_id)?;
        write_next(fd, &(self.signature_shares.len() as u32))?;
        for share in &self.signature_shares {
            write_next(fd, &share.id)?;
            share.z_i.inner_consensus_serialize(fd)?;
            write_next(fd, &share.key_ids)?;
        }
        Ok(())
    }

    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let dkg_id = read_next::<u64, _>(fd)?;
        let sign_id = read_next::<u64, _>(fd)?;
        let sign_iter_id = read_next::<u64, _>(fd)?;
        let signer_id = read_next::<u32, _>(fd)?;
        let num_shares = read_next::<u32, _>(fd)?;
        let mut signature_shares = Vec::new();
        for _ in 0..num_shares {
            let id = read_next::<u32, _>(fd)?;
            let z_i = Scalar::inner_consensus_deserialize(fd)?;
            let key_ids = read_next::<Vec<u32>, _>(fd)?;
            signature_shares.push(SignatureShare { id, z_i, key_ids });
        }
        Ok(SignatureShareResponse {
            dkg_id,
            sign_id,
            sign_iter_id,
            signer_id,
            signature_shares,
        })
    }
}

impl StacksMessageCodecExtensions for Message {
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &(MessageTypePrefix::from(self) as u8))?;
        match self {
            Message::DkgBegin(dkg_begin) => {
                dkg_begin.inner_consensus_serialize(fd)?;
            }
            Message::DkgPrivateBegin(dkg_private_begin) => {
                dkg_private_begin.inner_consensus_serialize(fd)?;
            }
            Message::DkgEndBegin(dkg_end_begin) => {
                dkg_end_begin.inner_consensus_serialize(fd)?;
            }
            Message::DkgEnd(dkg_end) => {
                dkg_end.inner_consensus_serialize(fd)?;
            }
            Message::DkgPublicShares(dkg_public_shares) => {
                dkg_public_shares.inner_consensus_serialize(fd)?;
            }
            Message::DkgPrivateShares(dkg_private_shares) => {
                dkg_private_shares.inner_consensus_serialize(fd)?;
            }
            Message::NonceRequest(nonce_request) => {
                nonce_request.inner_consensus_serialize(fd)?;
            }
            Message::NonceResponse(nonce_response) => {
                nonce_response.inner_consensus_serialize(fd)?;
            }
            Message::SignatureShareRequest(signature_share_request) => {
                signature_share_request.inner_consensus_serialize(fd)?;
            }
            Message::SignatureShareResponse(signature_share_response) => {
                signature_share_response.inner_consensus_serialize(fd)?;
            }
        }
        Ok(())
    }

    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let type_prefix_byte = read_next::<u8, _>(fd)?;
        let type_prefix = MessageTypePrefix::try_from(type_prefix_byte)?;
        let message = match type_prefix {
            MessageTypePrefix::DkgBegin => {
                Message::DkgBegin(DkgBegin::inner_consensus_deserialize(fd)?)
            }
            MessageTypePrefix::DkgPrivateBegin => {
                Message::DkgPrivateBegin(DkgPrivateBegin::inner_consensus_deserialize(fd)?)
            }
            MessageTypePrefix::DkgEndBegin => {
                Message::DkgEndBegin(DkgEndBegin::inner_consensus_deserialize(fd)?)
            }
            MessageTypePrefix::DkgEnd => Message::DkgEnd(DkgEnd::inner_consensus_deserialize(fd)?),
            MessageTypePrefix::DkgPublicShares => {
                Message::DkgPublicShares(DkgPublicShares::inner_consensus_deserialize(fd)?)
            }
            MessageTypePrefix::DkgPrivateShares => {
                Message::DkgPrivateShares(DkgPrivateShares::inner_consensus_deserialize(fd)?)
            }
            MessageTypePrefix::NonceRequest => {
                Message::NonceRequest(NonceRequest::inner_consensus_deserialize(fd)?)
            }
            MessageTypePrefix::NonceResponse => {
                Message::NonceResponse(NonceResponse::inner_consensus_deserialize(fd)?)
            }
            MessageTypePrefix::SignatureShareRequest => Message::SignatureShareRequest(
                SignatureShareRequest::inner_consensus_deserialize(fd)?,
            ),
            MessageTypePrefix::SignatureShareResponse => Message::SignatureShareResponse(
                SignatureShareResponse::inner_consensus_deserialize(fd)?,
            ),
        };
        Ok(message)
    }
}

impl StacksMessageCodecExtensions for Packet {
    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        self.msg.inner_consensus_serialize(fd)?;
        write_next(fd, &self.sig)?;
        Ok(())
    }

    fn inner_consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let msg = Message::inner_consensus_deserialize(fd)?;
        let sig: Vec<u8> = read_next(fd)?;
        Ok(Packet { msg, sig })
    }
}

/// The response that a signer sends back to observing miners
/// either accepting or rejecting a Nakamoto block with the corresponding reason
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum BlockResponse {
    /// The Nakamoto block was accepted and therefore signed
    Accepted((Sha512Trunc256Sum, ThresholdSignature)),
    /// The Nakamoto block was rejected and therefore not signed
    Rejected(BlockRejection),
}

impl BlockResponse {
    /// Create a new accepted BlockResponse for the provided block signer signature hash and signature
    pub fn accepted(hash: Sha512Trunc256Sum, sig: Signature) -> Self {
        Self::Accepted((hash, ThresholdSignature(sig)))
    }

    /// Create a new rejected BlockResponse for the provided block signer signature hash and signature
    pub fn rejected(hash: Sha512Trunc256Sum, sig: Signature) -> Self {
        Self::Rejected(BlockRejection::new(
            hash,
            RejectCode::SignedRejection(ThresholdSignature(sig)),
        ))
    }
}

impl StacksMessageCodec for BlockResponse {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        match self {
            BlockResponse::Accepted((hash, sig)) => {
                write_next(fd, &0u8)?;
                write_next(fd, hash)?;
                write_next(fd, sig)?;
            }
            BlockResponse::Rejected(rejection) => {
                write_next(fd, &1u8)?;
                write_next(fd, rejection)?;
            }
        };
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let type_prefix = read_next::<u8, _>(fd)?;
        let response = match type_prefix {
            0 => {
                let hash = read_next::<Sha512Trunc256Sum, _>(fd)?;
                let sig = read_next::<ThresholdSignature, _>(fd)?;
                BlockResponse::Accepted((hash, sig))
            }
            1 => {
                let rejection = read_next::<BlockRejection, _>(fd)?;
                BlockResponse::Rejected(rejection)
            }
            _ => {
                return Err(CodecError::DeserializeError(format!(
                    "Unknown block response type prefix: {}",
                    type_prefix
                )))
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

/// This enum is used to supply a `reason_code` for block rejections
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RejectCode {
    /// RPC endpoint Validation failed
    ValidationFailed(ValidateRejectCode),
    /// Signers signed a block rejection
    SignedRejection(ThresholdSignature),
    /// Insufficient signers agreed to sign the block
    InsufficientSigners(Vec<u32>),
    /// Missing the following expected transactions
    MissingTransactions(Vec<StacksTransaction>),
    /// The block was rejected due to connectivity issues with the signer
    ConnectivityIssues,
}

impl StacksMessageCodec for RejectCode {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &(RejectCodeTypePrefix::from(self) as u8))?;
        match self {
            RejectCode::ValidationFailed(code) => write_next(fd, &(code.clone() as u8))?,
            RejectCode::SignedRejection(sig) => write_next(fd, sig)?,
            RejectCode::InsufficientSigners(malicious_signers) => {
                write_next(fd, malicious_signers)?
            }
            RejectCode::MissingTransactions(missing_transactions) => {
                write_next(fd, missing_transactions)?
            }
            RejectCode::ConnectivityIssues => write_next(fd, &4u8)?,
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
            RejectCodeTypePrefix::SignedRejection => {
                RejectCode::SignedRejection(read_next::<ThresholdSignature, _>(fd)?)
            }
            RejectCodeTypePrefix::InsufficientSigners => {
                RejectCode::InsufficientSigners(read_next::<Vec<u32>, _>(fd)?)
            }
            RejectCodeTypePrefix::MissingTransactions => {
                RejectCode::MissingTransactions(read_next::<Vec<StacksTransaction>, _>(fd)?)
            }
            RejectCodeTypePrefix::ConnectivityIssues => RejectCode::ConnectivityIssues,
        };
        Ok(code)
    }
}

impl std::fmt::Display for RejectCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RejectCode::ValidationFailed(code) => write!(f, "Validation failed: {:?}", code),
            RejectCode::SignedRejection(sig) => {
                write!(f, "A threshold number of signers rejected the block with the following signature: {:?}.", sig)
            }
            RejectCode::InsufficientSigners(malicious_signers) => write!(
                f,
                "Insufficient signers agreed to sign the block. The following signers are malicious: {:?}",
                malicious_signers
            ),
            RejectCode::MissingTransactions(missing_transactions) => write!(
                f,
                "Missing the following expected transactions: {:?}",
                missing_transactions.iter().map(|tx| tx.txid()).collect::<Vec<_>>()
            ),
            RejectCode::ConnectivityIssues => write!(
                f,
                "The block was rejected due to connectivity issues with the signer."
            ),
        }
    }
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

impl SignerMessage {
    /// Helper function to determine the slot ID for the provided stacker-db writer id
    pub fn slot_id(&self, id: u32) -> u32 {
        let slot_id = match self {
            Self::Packet(packet) => match packet.msg {
                Message::DkgBegin(_) => DKG_BEGIN_SLOT_ID,
                Message::DkgPrivateBegin(_) => DKG_PRIVATE_BEGIN_SLOT_ID,
                Message::DkgEndBegin(_) => DKG_END_BEGIN_SLOT_ID,
                Message::DkgEnd(_) => DKG_END_SLOT_ID,
                Message::DkgPublicShares(_) => DKG_PUBLIC_SHARES_SLOT_ID,
                Message::DkgPrivateShares(_) => DKG_PRIVATE_SHARES_SLOT_ID,
                Message::NonceRequest(_) => NONCE_REQUEST_SLOT_ID,
                Message::NonceResponse(_) => NONCE_RESPONSE_SLOT_ID,
                Message::SignatureShareRequest(_) => SIGNATURE_SHARE_REQUEST_SLOT_ID,
                Message::SignatureShareResponse(_) => SIGNATURE_SHARE_RESPONSE_SLOT_ID,
            },
            Self::BlockResponse(_) => BLOCK_SLOT_ID,
            Self::Transactions(_) => TRANSACTIONS_SLOT_ID,
        };
        SIGNER_SLOTS_PER_USER * id + slot_id
    }
}

#[cfg(test)]
mod test {

    use blockstack_lib::chainstate::stacks::{
        TransactionAnchorMode, TransactionAuth, TransactionPayload, TransactionPostConditionMode,
        TransactionSmartContract, TransactionVersion,
    };
    use blockstack_lib::util_lib::strings::StacksString;
    use rand::Rng;
    use rand_core::OsRng;
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use stacks_common::types::chainstate::StacksPrivateKey;
    use wsts::common::Signature;

    use super::{StacksMessageCodecExtensions, *};
    #[test]
    fn serde_reject_code() {
        let code = RejectCode::ValidationFailed(ValidateRejectCode::InvalidBlock);
        let serialized_code = code.serialize_to_vec();
        let deserialized_code = read_next::<RejectCode, _>(&mut &serialized_code[..])
            .expect("Failed to deserialize RejectCode");
        assert_eq!(code, deserialized_code);

        let code = RejectCode::SignedRejection(ThresholdSignature::empty());
        let serialized_code = code.serialize_to_vec();
        let deserialized_code = read_next::<RejectCode, _>(&mut &serialized_code[..])
            .expect("Failed to deserialize RejectCode");
        assert_eq!(code, deserialized_code);

        let code = RejectCode::InsufficientSigners(vec![0, 1, 2]);
        let serialized_code = code.serialize_to_vec();
        let deserialized_code = read_next::<RejectCode, _>(&mut &serialized_code[..])
            .expect("Failed to deserialize RejectCode");
        assert_eq!(code, deserialized_code);

        let sk = StacksPrivateKey::new();
        let tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: CHAIN_ID_TESTNET,
            auth: TransactionAuth::from_p2pkh(&sk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: "test-contract".into(),
                    code_body: StacksString::from_str("(/ 1 0)").unwrap(),
                },
                None,
            ),
        };
        let code = RejectCode::MissingTransactions(vec![tx]);
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

        let rejection = BlockRejection::new(
            Sha512Trunc256Sum([1u8; 32]),
            RejectCode::SignedRejection(ThresholdSignature::empty()),
        );
        let serialized_rejection = rejection.serialize_to_vec();
        let deserialized_rejection = read_next::<BlockRejection, _>(&mut &serialized_rejection[..])
            .expect("Failed to deserialize BlockRejection");
        assert_eq!(rejection, deserialized_rejection);

        let rejection = BlockRejection::new(
            Sha512Trunc256Sum([2u8; 32]),
            RejectCode::InsufficientSigners(vec![0, 1, 2]),
        );
        let serialized_rejection = rejection.serialize_to_vec();
        let deserialized_rejection = read_next::<BlockRejection, _>(&mut &serialized_rejection[..])
            .expect("Failed to deserialize BlockRejection");
        assert_eq!(rejection, deserialized_rejection);
    }

    #[test]
    fn serde_block_response() {
        let response =
            BlockResponse::Accepted((Sha512Trunc256Sum([0u8; 32]), ThresholdSignature::empty()));
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
    fn serde_point_scalar() {
        let mut rng = OsRng;
        let scalar = Scalar::random(&mut rng);
        let mut serialized_scalar = vec![];
        scalar
            .inner_consensus_serialize(&mut serialized_scalar)
            .expect("serialization to buffer failed.");
        let deserialized_scalar = Scalar::inner_consensus_deserialize(&mut &serialized_scalar[..])
            .expect("Failed to deserialize Scalar");
        assert_eq!(scalar, deserialized_scalar);

        let point = Point::from(scalar);
        let mut serialized_point = vec![];
        point
            .inner_consensus_serialize(&mut serialized_point)
            .expect("serialization to buffer failed.");
        let deserialized_point = Point::inner_consensus_deserialize(&mut &serialized_point[..])
            .expect("Failed to deserialize Point");
        assert_eq!(point, deserialized_point);
    }

    fn test_fixture_packet(msg: Message) {
        let packet = Packet {
            msg,
            sig: vec![1u8; 20],
        };
        let mut serialized_packet = vec![];
        packet
            .inner_consensus_serialize(&mut serialized_packet)
            .expect("serialization to buffer failed.");
        let deserialized_packet = Packet::inner_consensus_deserialize(&mut &serialized_packet[..])
            .expect("Failed to deserialize Packet");
        assert_eq!(packet, deserialized_packet);
    }

    #[test]
    fn serde_packet() {
        // Test DKG begin Packet
        test_fixture_packet(Message::DkgBegin(DkgBegin { dkg_id: 0 }));

        let dkg_id = rand::thread_rng().gen();
        let signer_id = rand::thread_rng().gen();
        let sign_id = rand::thread_rng().gen();
        let sign_iter_id = rand::thread_rng().gen();
        let mut signer_ids = [0u32; 100];
        rand::thread_rng().fill(&mut signer_ids[..]);

        let mut key_ids = [0u32; 100];
        rand::thread_rng().fill(&mut key_ids[..]);
        let nmb_items = rand::thread_rng().gen_range(1..100);

        // Test DKG private begin Packet
        test_fixture_packet(Message::DkgPrivateBegin(DkgPrivateBegin {
            dkg_id,
            signer_ids: signer_ids.to_vec(),
            key_ids: key_ids.to_vec(),
        }));

        // Test DKG end begin Packet
        test_fixture_packet(Message::DkgEndBegin(DkgEndBegin {
            dkg_id,
            signer_ids: signer_ids.to_vec(),
            key_ids: key_ids.to_vec(),
        }));

        // Test DKG end Packet Success
        test_fixture_packet(Message::DkgEnd(DkgEnd {
            dkg_id,
            signer_id,
            status: DkgStatus::Success,
        }));

        // Test DKG end Packet Failure
        test_fixture_packet(Message::DkgEnd(DkgEnd {
            dkg_id,
            signer_id,
            status: DkgStatus::Failure("failure".to_string()),
        }));

        // Test DKG public shares Packet
        let rng = &mut OsRng;
        let comms = (0..nmb_items)
            .map(|i| {
                (
                    i,
                    PolyCommitment {
                        id: ID {
                            id: Scalar::random(rng),
                            kG: Point::from(Scalar::random(rng)),
                            kca: Scalar::random(rng),
                        },
                        poly: vec![
                            Point::from(Scalar::random(rng)),
                            Point::from(Scalar::random(rng)),
                        ],
                    },
                )
            })
            .collect();
        test_fixture_packet(Message::DkgPublicShares(DkgPublicShares {
            dkg_id,
            signer_id,
            comms,
        }));

        // Test DKG private shares Packet
        let mut shares = vec![];
        for i in 0..nmb_items {
            let mut shares_map = HashMap::new();
            for i in 0..nmb_items {
                let mut bytes = [0u8; 20];
                rng.fill(&mut bytes[..]);
                shares_map.insert(i, bytes.to_vec());
            }
            shares.push((i, shares_map));
        }
        test_fixture_packet(Message::DkgPrivateShares(DkgPrivateShares {
            dkg_id,
            signer_id,
            shares,
        }));

        // Test Nonce request Packet with merkle root
        let mut message = [0u8; 40];
        rng.fill(&mut message[..]);
        let mut merkle_root_bytes = [0u8; 32];
        rng.fill(&mut merkle_root_bytes[..]);
        let merkle_root = Some(merkle_root_bytes);

        test_fixture_packet(Message::NonceRequest(NonceRequest {
            dkg_id,
            sign_id,
            sign_iter_id,
            message: message.to_vec(),
            is_taproot: true,
            merkle_root,
        }));

        // Test Nonce request Packet with no merkle root
        test_fixture_packet(Message::NonceRequest(NonceRequest {
            dkg_id,
            sign_id,
            sign_iter_id,
            message: message.to_vec(),
            is_taproot: false,
            merkle_root: None,
        }));

        // Test Nonce response Packet
        let mut nonces = vec![];
        for _ in 0..nmb_items {
            nonces.push(PublicNonce {
                D: Point::from(Scalar::random(rng)),
                E: Point::from(Scalar::random(rng)),
            });
        }
        let nonce_response = NonceResponse {
            dkg_id,
            sign_id,
            sign_iter_id,
            signer_id,
            key_ids: key_ids.to_vec(),
            nonces,
            message: message.to_vec(),
        };
        test_fixture_packet(Message::NonceResponse(nonce_response.clone()));

        // Test Signature share request Packet with merkle root and nonce response
        test_fixture_packet(Message::SignatureShareRequest(SignatureShareRequest {
            dkg_id,
            sign_id,
            sign_iter_id,
            nonce_responses: vec![nonce_response],
            message: message.to_vec(),
            is_taproot: true,
            merkle_root,
        }));

        // Test Signature share request Packet with no merkle root and nonce response
        test_fixture_packet(Message::SignatureShareRequest(SignatureShareRequest {
            dkg_id,
            sign_id,
            sign_iter_id,
            nonce_responses: vec![],
            message: message.to_vec(),
            is_taproot: false,
            merkle_root: None,
        }));

        // Test Signature share response Packet
        let mut signature_shares = vec![];
        for i in 0..nmb_items {
            let mut key_ids = vec![];
            for i in 0..nmb_items {
                key_ids.push(i);
            }
            signature_shares.push(SignatureShare {
                id: i,
                z_i: Scalar::random(rng),
                key_ids,
            });
        }
        test_fixture_packet(Message::SignatureShareResponse(SignatureShareResponse {
            dkg_id,
            sign_id,
            sign_iter_id,
            signer_id,
            signature_shares,
        }));
    }

    #[test]
    fn serde_signer_message() {
        let rng = &mut OsRng;
        let signer_message = SignerMessage::Packet(Packet {
            msg: Message::DkgBegin(DkgBegin { dkg_id: 0 }),
            sig: vec![1u8; 20],
        });

        let serialized_signer_message = signer_message.serialize_to_vec();
        let deserialized_signer_message =
            read_next::<SignerMessage, _>(&mut &serialized_signer_message[..])
                .expect("Failed to deserialize SignerMessage");
        assert_eq!(signer_message, deserialized_signer_message);

        let signer_message = SignerMessage::BlockResponse(BlockResponse::Accepted((
            Sha512Trunc256Sum([2u8; 32]),
            ThresholdSignature(Signature {
                R: Point::from(Scalar::random(rng)),
                z: Scalar::random(rng),
            }),
        )));
        let serialized_signer_message = signer_message.serialize_to_vec();
        let deserialized_signer_message =
            read_next::<SignerMessage, _>(&mut &serialized_signer_message[..])
                .expect("Failed to deserialize SignerMessage");
        assert_eq!(signer_message, deserialized_signer_message);

        let sk = StacksPrivateKey::new();
        let tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: CHAIN_ID_TESTNET,
            auth: TransactionAuth::from_p2pkh(&sk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: "test-contract".into(),
                    code_body: StacksString::from_str("(/ 1 0)").unwrap(),
                },
                None,
            ),
        };
        let signer_message = SignerMessage::Transactions(vec![tx]);
        let serialized_signer_message = signer_message.serialize_to_vec();
        let deserialized_signer_message =
            read_next::<SignerMessage, _>(&mut &serialized_signer_message[..])
                .expect("Failed to deserialize SignerMessage");
        assert_eq!(signer_message, deserialized_signer_message);
    }
}
