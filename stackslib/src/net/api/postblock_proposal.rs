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
use crate::chainstate::nakamoto::proposal::{BlockValidateResponse, NakamotoBlockProposal};
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
        // Only accept requests from localhost
        let is_loopback = match preamble.host {
            // Should never be DNS
            PeerHost::DNS(..) => false,
            PeerHost::IP(addr, ..) => addr.is_loopback(),
        };

        if !is_loopback {
            return Err(Error::Http(403, "Forbidden".into()));
        }

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

        let block_proposal = match preamble.content_type {
            Some(HttpContentType::Bytes) => Self::parse_posttransaction_octets(body)?,
            Some(HttpContentType::JSON) => Self::parse_posttransaction_json(body)?,
            None => {
                return Err(Error::DecodeError(
                    "Missing Content-Type for transaction".to_string(),
                ))
            }
            _ => {
                return Err(Error::DecodeError(
                    "Wrong Content-Type for transaction; expected application/json or application/octet-stream".to_string(),
                ))
            }
        };

        self.block_proposal = Some(block_proposal);
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCBlockProposalRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.block_proposal = None
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let block_proposal = self
            .block_proposal
            .take()
            .ok_or(NetError::SendError("`block_proposal` not set".into()))?;

        let resp = node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
            block_proposal.validate(sortdb, chainstate)
        });

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
        let body = HttpResponseContents::try_from_json(&resp)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCBlockProposalRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let response: BlockValidateResponse = parse_json(preamble, body)?;
        HttpResponsePayload::try_from_json(response)
    }
}

impl StacksHttpRequest {
    /// Make a new post-block request
    #[cfg(test)]
    pub fn new_post_block_proposal(
        host: PeerHost,
        proposal: &NakamotoBlockProposal,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "POST".into(),
            "/v2/block_proposal".into(),
            HttpRequestContents::new().payload_stacks(proposal),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_stacks_block_proposal_accepted(self) -> Result<BlockValidateResponse, NetError> {
        todo!()
    }
}
