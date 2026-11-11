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

//! Report the burnchain views a Stacks block hangs from, and whether a burnchain fork has
//! since orphaned either of them.
//!
//! A block is tied to the burnchain twice: by the sortition that elected its tenure, and by the
//! burn view its miner was building against. The two diverge whenever a tenure is extended
//! across a burn block, which is also the only time one tenure holds two blocks at the same
//! Stacks height. Telling those two blocks apart needs the burn view, which is derived during
//! block processing and stored, not carried in the block header.

use regex::{Captures, Regex};
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId};

use crate::chainstate::nakamoto::NakamotoChainState;
use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{request, RPCRequestHandler, StacksHttpRequest, StacksHttpResponse};
use crate::net::{Error as NetError, PeerHost, StacksNodeState};

#[derive(Clone, Default)]
pub struct GetBlockViewRequestHandler {
    pub(crate) block_id: Option<StacksBlockId>,
}

/// The burnchain views a block hangs from, each with its current fate.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct BlockViewInfo {
    /// The consensus hash of the tenure this block belongs to, i.e. the sortition that elected
    /// its miner. Unchanged when the tenure is extended.
    pub consensus_hash: ConsensusHash,
    /// Whether that sortition is still on the node's canonical burnchain fork. False means a
    /// burnchain fork orphaned the tenure, which voids every block it produced.
    pub consensus_hash_canonical: bool,
    /// The burn view the block was built against: set by a tenure-change or tenure-extend
    /// transaction, and inherited from the parent otherwise. `None` for an epoch 2.x block,
    /// which predates the concept.
    pub burn_view: Option<ConsensusHash>,
    /// Whether that burn view is still on the node's canonical burnchain fork. False means a
    /// burnchain fork orphaned the burn view, which this block cannot outlive even if its
    /// tenure survived. Always false when `burn_view` is `None`, which carries no claim.
    pub burn_view_canonical: bool,
}

impl GetBlockViewRequestHandler {
    pub fn new() -> Self {
        Self { block_id: None }
    }
}

/// Decode the HTTP request
impl HttpRequest for GetBlockViewRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/blocks/(?P<block_id>[0-9a-f]{64})/view$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/blocks/:block_id/view"
    }

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
        let block_id = request::get_block_hash(captures, "block_id")?;
        self.block_id = Some(block_id);
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for GetBlockViewRequestHandler {
    fn restart(&mut self) {
        self.block_id = None;
    }

    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let block_id = self
            .block_id
            .take()
            .ok_or(NetError::SendError("`block_id` not set".into()))?;

        let view_resp =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                let header_info =
                    match NakamotoChainState::get_block_header(chainstate.db(), &block_id) {
                        Ok(Some(header_info)) => header_info,
                        Ok(None) => {
                            let msg = format!("No such block {block_id}");
                            debug!("{msg}");
                            return Err(StacksHttpResponse::new_error(
                                &preamble,
                                &HttpNotFound::new(msg),
                            ));
                        }
                        Err(e) => {
                            let msg = format!("Failed to load block {block_id}: {e:?}");
                            error!("{msg}");
                            return Err(StacksHttpResponse::new_error(
                                &preamble,
                                &HttpServerError::new(msg),
                            ));
                        }
                    };

                // `processed_block` against a handle at the canonical tip is the same test the
                // node applies to a tenure's candidate blocks: it resolves the consensus hash
                // to its sortition and checks that the canonical fork reaches that very one,
                // rather than a competing sortition at the same burn height.
                //
                // A lookup failure is not an answer, and must not be reported as one. Callers
                // read `canonical: false` as proof that a burnchain fork orphaned the block,
                // which is grounds to release a signature already placed at that height and
                // sign a sibling instead. Answering a database error that way would spend that
                // proof on nothing. Fail the request so the caller's error path keeps whatever
                // it is holding.
                let handle = sortdb.index_handle_at_tip();
                let canonical = |consensus_hash: &ConsensusHash| {
                    handle.processed_block(consensus_hash).map_err(|e| {
                        let msg = format!(
                            "Failed to check whether consensus hash {consensus_hash} is canonical: {e:?}"
                        );
                        error!("{msg}");
                        StacksHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                    })
                };

                let consensus_hash = header_info.consensus_hash.clone();
                let consensus_hash_canonical = canonical(&consensus_hash)?;
                let burn_view_canonical = match header_info.burn_view.as_ref() {
                    Some(burn_view) => canonical(burn_view)?,
                    // No burn view is no claim either way.
                    None => false,
                };

                Ok(BlockViewInfo {
                    consensus_hash,
                    consensus_hash_canonical,
                    burn_view: header_info.burn_view.clone(),
                    burn_view_canonical,
                })
            });

        let view = match view_resp {
            Ok(view) => view,
            Err(response) => {
                return response.try_into_contents();
            }
        };

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&view)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for GetBlockViewRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let view: BlockViewInfo = parse_json(preamble, body)?;
        HttpResponsePayload::try_from_json(view)
    }
}

impl StacksHttpRequest {
    pub fn new_get_block_view(host: PeerHost, block_id: &StacksBlockId) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/blocks/{block_id}/view"),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_block_view(self) -> Result<BlockViewInfo, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let view: BlockViewInfo = serde_json::from_value(response_json).map_err(|e| {
            error!("Failed to decode JSON"; "err" => ?e);
            Error::DecodeError("Failed to decode JSON".to_string())
        })?;
        Ok(view)
    }
}
