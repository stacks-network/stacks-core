// Copyright (C) 2026 Stacks Open Internet Foundation
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

use regex::{Captures, Regex};
use stacks_common::types::chainstate::ConsensusHash;

use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::StacksBlockHeaderTypes;
use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{request, RPCRequestHandler, StacksHttpResponse};
use crate::net::{Error as NetError, StacksNodeState};

#[derive(Clone)]
pub struct NakamotoTenureTipMetadataRequestHandler {
    pub(crate) consensus_hash: Option<ConsensusHash>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct BlockHeaderWithMetadata {
    pub anchored_header: StacksBlockHeaderTypes,
    pub burn_view: Option<ConsensusHash>,
}

impl NakamotoTenureTipMetadataRequestHandler {
    pub fn new() -> Self {
        Self {
            consensus_hash: None,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for NakamotoTenureTipMetadataRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/tenures/tip_metadata/(?P<consensus_hash>[0-9a-f]{40})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/tenures/tip_metadata/:consensus_hash"
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

impl RPCRequestHandler for NakamotoTenureTipMetadataRequestHandler {
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

        let tenure_tip_resp =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                let header_info =
                    match NakamotoChainState::find_highest_known_block_header_in_tenure(
                        &chainstate,
                        sortdb,
                        &consensus_hash,
                    ) {
                        Ok(Some(header)) => header,
                        Ok(None) => {
                            let msg = format!("No blocks in tenure {}", &consensus_hash);
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
                Ok(header_info)
            });

        let tenure_tip = match tenure_tip_resp {
            Ok(tenure_tip) => tenure_tip,
            Err(response) => {
                return response.try_into_contents().map_err(NetError::from);
            }
        };

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&BlockHeaderWithMetadata {
            anchored_header: tenure_tip.anchored_header,
            burn_view: tenure_tip.burn_view,
        })?;

        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for NakamotoTenureTipMetadataRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let tenure_tip: BlockHeaderWithMetadata = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(tenure_tip)?)
    }
}
