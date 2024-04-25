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

use std::io::{Read, Seek, SeekFrom, Write};
use std::{fs, io};

use regex::{Captures, Regex};
use serde::de::Error as de_Error;
use stacks_common::codec::{StacksMessageCodec, MAX_MESSAGE_LEN};
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId};
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::to_hex;
use {serde, serde_json};

use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState, NakamotoStagingBlocksConn};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::Error as ChainError;
use crate::net::api::getblock_v3::NakamotoBlockStream;
use crate::net::http::{
    parse_bytes, parse_json, Error, HttpBadRequest, HttpChunkGenerator, HttpContentType,
    HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse,
    HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError, HttpVersion,
};
use crate::net::httpcore::{
    HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp, StacksHttpRequest,
    StacksHttpResponse,
};
use crate::net::{Error as NetError, StacksNodeState, TipRequest, MAX_HEADERS};
use crate::util_lib::db::{DBConn, Error as DBError};

#[derive(Clone)]
pub struct RPCNakamotoTenureInfoRequestHandler {}

impl RPCNakamotoTenureInfoRequestHandler {
    pub fn new() -> Self {
        Self {}
    }
}

/// The view of this node's current tenure.
/// All of this information can be found from the PeerNetwork struct, so loading this up should
/// incur zero disk I/O.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct RPCGetTenureInfo {
    /// The highest known consensus hash (identifies the current tenure)
    pub consensus_hash: ConsensusHash,
    /// The tenure-start block ID of the current tenure
    pub tenure_start_block_id: StacksBlockId,
    /// The consensus hash of the parent tenure
    pub parent_consensus_hash: ConsensusHash,
    /// The block hash of the parent tenure's start block
    pub parent_tenure_start_block_id: StacksBlockId,
    /// The highest Stacks block ID in the current tenure
    pub tip_block_id: StacksBlockId,
    /// The height of this tip
    pub tip_height: u64,
    /// Which reward cycle we're in
    pub reward_cycle: u64,
}

/// Decode the HTTP request
impl HttpRequest for RPCNakamotoTenureInfoRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/tenures/info"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/tenures/info"
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        _captures: &Captures,
        query: Option<&str>,
        _body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() != 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected 0-length body".to_string(),
            ));
        }
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCNakamotoTenureInfoRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {}

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let info = node.with_node_state(|network, _sortdb, _chainstate, _mempool, _rpc_args| {
            RPCGetTenureInfo {
                consensus_hash: network.stacks_tip.0.clone(),
                tenure_start_block_id: network.tenure_start_block_id.clone(),
                parent_consensus_hash: network.parent_stacks_tip.0.clone(),
                parent_tenure_start_block_id: StacksBlockId::new(
                    &network.parent_stacks_tip.0,
                    &network.parent_stacks_tip.1,
                ),
                tip_block_id: StacksBlockId::new(&network.stacks_tip.0, &network.stacks_tip.1),
                tip_height: network.stacks_tip.2,
                reward_cycle: network
                    .burnchain
                    .block_height_to_reward_cycle(network.burnchain_tip.block_height)
                    .expect("FATAL: burnchain tip before system start"),
            }
        });

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&info)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCNakamotoTenureInfoRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let peer_info: RPCGetTenureInfo = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(peer_info)?)
    }
}

impl StacksHttpRequest {
    /// Make a new getinfo request to this endpoint
    pub fn new_get_nakamoto_tenure_info(host: PeerHost) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            "/v3/tenures/info".into(),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_nakamoto_tenure_info(self) -> Result<RPCGetTenureInfo, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let tenure_info: RPCGetTenureInfo = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(tenure_info)
    }
}
