// Copyright (C) 2024 Stacks Open Internet Foundation
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
use stacks_common::util::hash::{to_hex, Sha512Trunc256Sum};
use {serde, serde_json};

use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState, NakamotoStagingBlocksConn};
use crate::chainstate::stacks::db::{StacksBlockHeaderTypes, StacksChainState};
use crate::chainstate::stacks::Error as ChainError;
use crate::net::api::getblock_v3::NakamotoBlockStream;
use crate::net::http::{
    parse_bytes, parse_json, Error, HttpBadRequest, HttpChunkGenerator, HttpContentType,
    HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse,
    HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError, HttpVersion,
};
use crate::net::httpcore::{
    request, HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp, StacksHttpRequest,
    StacksHttpResponse,
};
use crate::net::{Error as NetError, StacksNodeState, TipRequest, MAX_HEADERS};
use crate::util_lib::db::{DBConn, Error as DBError};

#[derive(Clone)]
pub struct RPCNakamotoTenureTipRequestHandler {
    pub(crate) consensus_hash: Option<ConsensusHash>,
}

impl RPCNakamotoTenureTipRequestHandler {
    pub fn new() -> Self {
        Self {
            consensus_hash: None,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCNakamotoTenureTipRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/tenures/tip/(?P<consensus_hash>[0-9a-f]{40})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/tenures/tip/:consensus_hash"
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        captures: &Captures,
        query: Option<&str>,
        _body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() != 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected 0-length body".to_string(),
            ));
        }
        let consensus_hash = request::get_consensus_hash(captures, "consensus_hash")?;
        self.consensus_hash = Some(consensus_hash);
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCNakamotoTenureTipRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.consensus_hash = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let consensus_hash = self
            .consensus_hash
            .take()
            .ok_or(NetError::SendError("`consensus_hash` not set".into()))?;

        let tenure_tip_resp = node.with_node_state(|_network, _sortdb, chainstate, _mempool, _rpc_args| {
            let header_info = match NakamotoChainState::get_highest_known_block_header_in_tenure(chainstate.db(), &consensus_hash) {
                Ok(Some(header)) => header,
                Ok(None) => {
                    let msg = format!(
                        "No blocks in tenure {}",
                        &consensus_hash
                    );
                    debug!("{}", &msg);
                    return Err(StacksHttpResponse::new_error(
                        &preamble,
                        &HttpNotFound::new(msg),
                    ));
                }
                Err(e) => {
                    let msg = format!(
                        "Failed to query tenure blocks by consensus '{}': {:?}",
                        consensus_hash, &e
                    );
                    error!("{}", &msg);
                    return Err(StacksHttpResponse::new_error(
                        &preamble,
                        &HttpServerError::new(msg),
                    ));
                }
            };
            Ok(header_info.anchored_header)
        });

        let tenure_tip = match tenure_tip_resp {
            Ok(tenure_tip) => tenure_tip,
            Err(response) => {
                return response.try_into_contents().map_err(NetError::from);
            }
        };

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&tenure_tip)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCNakamotoTenureTipRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let tenure_tip: StacksBlockHeaderTypes = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(tenure_tip)?)
    }
}

impl StacksHttpRequest {
    /// Make a new getinfo request to this endpoint
    pub fn new_get_tenure_tip(host: PeerHost, consensus_hash: &ConsensusHash) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/tenures/tip/{}", consensus_hash),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_tenure_tip(self) -> Result<StacksBlockHeaderTypes, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let tenure_tip: StacksBlockHeaderTypes = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(tenure_tip)
    }
}
