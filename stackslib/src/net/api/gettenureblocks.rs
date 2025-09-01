// Copyright (C) 2025 Stacks Open Internet Foundation
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

use clarity::types::chainstate::StacksBlockId;
use regex::{Captures, Regex};
use serde_json;
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash};
use stacks_common::types::net::PeerHost;

use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::{StacksBlockHeaderTypes, StacksHeaderInfo};
use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{request, RPCRequestHandler, StacksHttpRequest, StacksHttpResponse};
use crate::net::{Error as NetError, StacksNodeState};

#[derive(Clone)]
pub struct RPCNakamotoTenureBlocksRequestHandler {
    pub(crate) consensus_hash: Option<ConsensusHash>,
}

impl RPCNakamotoTenureBlocksRequestHandler {
    pub fn new() -> Self {
        Self {
            consensus_hash: None,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct RPCTenureBlock {
    pub block_id: StacksBlockId,
    pub block_hash: BlockHeaderHash,
    pub parent_block_id: String,
    pub height: u64,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct RPCTenure {
    pub consensus_hash: ConsensusHash,
    pub burn_block_height: u64,
    pub burn_block_hash: String,
    pub stacks_blocks: Vec<RPCTenureBlock>,
}

/// Decode the HTTP request
impl HttpRequest for RPCNakamotoTenureBlocksRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/tenures/blocks/(?P<consensus_hash>[0-9a-f]{40})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/tenures/blocks/:consensus_hash"
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

impl RPCRequestHandler for RPCNakamotoTenureBlocksRequestHandler {
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

        let tenure_blocks_resp =
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

                let blocks = match NakamotoChainState::get_block_headers_in_tenure_at_burnview(
                    chainstate.db(),
                    &header_info.consensus_hash,
                    &header_info.burn_view.unwrap(),
                ) {
                    Ok(blocks) => blocks,
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

                let mut canonical_blocks: Vec<StacksHeaderInfo> = vec![];
                // now go back from the top to the bottom
                let mut current_block_opt = blocks.first();
                while let Some(current_block) = current_block_opt {
                    if let Some(nakamoto_block) = current_block.anchored_header.as_stacks_nakamoto()
                    {
                        let block = current_block.clone();
                        let block_parent_id = nakamoto_block.parent_block_id;
                        canonical_blocks.push(block);
                        current_block_opt = blocks
                            .iter()
                            .find(|block| block.index_block_hash() == block_parent_id);
                    } else {
                        break;
                    }
                }

                Ok((canonical_blocks, header_info))
            });

        let (tenure_blocks, header_info): (Vec<RPCTenureBlock>, StacksHeaderInfo) =
            match tenure_blocks_resp {
                Ok((tenure_blocks, header_info)) => (
                    tenure_blocks
                        .into_iter()
                        .map(|header| RPCTenureBlock {
                            block_id: header.index_block_hash(),
                            block_hash: header.anchored_header.block_hash(),
                            parent_block_id: match header.anchored_header {
                                StacksBlockHeaderTypes::Nakamoto(nakamoto) => {
                                    nakamoto.parent_block_id.to_hex()
                                }
                                StacksBlockHeaderTypes::Epoch2(epoch2) => {
                                    epoch2.parent_block.to_hex()
                                }
                            },

                            height: header.stacks_block_height,
                        })
                        .collect(),
                    header_info,
                ),
                Err(response) => {
                    return response.try_into_contents().map_err(NetError::from);
                }
            };

        let tenure = RPCTenure {
            consensus_hash: header_info.consensus_hash,
            burn_block_height: header_info.burn_header_height.into(),
            burn_block_hash: header_info.burn_header_hash.to_hex(),
            stacks_blocks: tenure_blocks,
        };

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&tenure)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCNakamotoTenureBlocksRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let tenure: RPCTenure = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(tenure)?)
    }
}

impl StacksHttpRequest {
    /// Make a new getinfo request to this endpoint
    pub fn new_get_tenure_blocks(
        host: PeerHost,
        consensus_hash: &ConsensusHash,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/tenures/blocks/{}", consensus_hash),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_tenure_blocks(self) -> Result<RPCTenure, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let tenure: RPCTenure = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(tenure)
    }
}
