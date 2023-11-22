// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use clarity::vm::costs::ExecutionCost;
use regex::{Captures, Regex};
use stacks_common::codec::{
    read_next, write_next, Error as CodecError, StacksMessageCodec, MAX_PAYLOAD_LEN,
};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksBlockId, StacksPublicKey,
};
use stacks_common::types::net::PeerHost;
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::hash::{hex_bytes, Hash160, Sha256Sum};
use stacks_common::util::retry::BoundReader;

use crate::burnchains::affirmation::AffirmationMap;
use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::NakamotoBlock;
use crate::chainstate::stacks::db::blocks::MINIMUM_TX_FEE_RATE_PER_BYTE;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::{
    StacksBlock, StacksBlockHeader, StacksTransaction, TransactionPayload,
};
use crate::core::mempool::MemPoolDB;
use crate::cost_estimates::FeeRateEstimate;
use crate::net::http::{
    parse_json, Error, HttpBadRequest, HttpContentType, HttpNotFound, HttpRequest,
    HttpRequestContents, HttpRequestPreamble, HttpResponse, HttpResponseContents,
    HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    request, HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler,
    StacksHttpRequest, StacksHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::relay::Relayer;
use crate::net::{
    Attachment, BlocksData, BlocksDatum, Error as NetError, StacksMessageType, StacksNodeState,
};

/// Represents a block proposed to the `v2/block_proposal` endpoint for validation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NakamotoBlockProposal {
    /// Proposed block
    pub block: NakamotoBlock,
    /// Identify the stacks/burnchain fork we are on
    pub parent_consensus_hash: ConsensusHash,
    /// These are all the microblocks that the proposed block
    /// will confirm.
    pub burn_tip: BurnchainHeaderHash,
    /// This refers to the burn block that was the current tip
    ///  at the time this proposal was constructed. In most cases,
    ///  if this proposal is accepted, it will be "mined" in the next
    ///  burn block.
    pub burn_tip_height: u32,
    /// Mainnet, Testnet, etc.
    pub chain_id: u32,
}

impl StacksMessageCodec for NakamotoBlockProposal {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.block)?;
        write_next(fd, &self.parent_consensus_hash)?;
        write_next(fd, &self.burn_tip)?;
        write_next(fd, &self.burn_tip_height)?;
        write_next(fd, &self.chain_id)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        Ok(Self {
            block: read_next(fd)?,
            parent_consensus_hash: read_next(fd)?,
            burn_tip: read_next(fd)?,
            burn_tip_height: read_next(fd)?,
            chain_id: read_next(fd)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NakamotoBlockProposalResponse {}

#[derive(Clone, Default)]
pub struct RPCBlockProposalRequestHandler {
    pub block_proposal: Option<NakamotoBlockProposal>,
}

impl RPCBlockProposalRequestHandler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode a bare transaction from the body
    fn parse_posttransaction_octets(mut body: &[u8]) -> Result<NakamotoBlockProposal, Error> {
        NakamotoBlockProposal::consensus_deserialize(&mut body).map_err(|e| match e {
            CodecError::DeserializeError(msg) => {
                Error::DecodeError(format!("Failed to deserialize posted transaction: {msg}"))
            }
            _ => e.into(),
        })
    }

    /// Decode a JSON-encoded transaction
    fn parse_posttransaction_json(body: &[u8]) -> Result<NakamotoBlockProposal, Error> {
        serde_json::from_slice(body).map_err(|_| Error::DecodeError("Failed to parse body".into()))
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCBlockProposalRequestHandler {
    fn verb(&self) -> &'static str {
        "POST"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v2/block_proposal$"#).unwrap()
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        captures: &Captures,
        query: Option<&str>,
        body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() == 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected non-zero-length body for PostBlock".to_string(),
            ));
        }

        if preamble.get_content_length() > MAX_PAYLOAD_LEN {
            return Err(Error::DecodeError(
                "Invalid Http request: BlockProposal body is too big".to_string(),
            ));
        }

        match preamble.content_type {
            None => {
                return Err(Error::DecodeError(
                    "Missing Content-Type for transaction".to_string(),
                ));
            }
            Some(HttpContentType::Bytes) => {
                // expect a bare transaction
                let block_proposal = Self::parse_posttransaction_octets(body)?;
                self.block_proposal = Some(block_proposal);
            }
            Some(HttpContentType::JSON) => {
                // expect a transaction and an attachment
                let block_proposal = Self::parse_posttransaction_json(body)?;
                self.block_proposal = Some(block_proposal);
            }
            _ => {
                return Err(Error::DecodeError(
                    "Wrong Content-Type for transaction; expected application/json or application/octet-stream".to_string(),
                ));
            }
        }

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCBlockProposalRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        todo!()
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        todo!()
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCBlockProposalRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        todo!()
    }
}

impl StacksHttpRequest {
    /// Make a new post-block request
    pub fn new_post_block_proposal(
        host: PeerHost,
        proposal: NakamotoBlockProposal,
    ) -> StacksHttpRequest {
        todo!()
    }
}

impl StacksHttpResponse {
    pub fn decode_stacks_block_proposal_accepted(
        self,
    ) -> Result<NakamotoBlockProposalResponse, NetError> {
        todo!()
    }
}
