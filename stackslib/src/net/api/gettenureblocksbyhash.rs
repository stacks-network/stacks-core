// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::net::PeerHost;

use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::net::api::gettenureblocks::{
    build_tenure_from_header_else_snapshot, encode_tenure_reply,
    get_prior_last_sortition_consensus_hash, RPCTenure,
};
use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{request, RPCRequestHandler, StacksHttpRequest, StacksHttpResponse};
use crate::net::{Error as NetError, StacksNodeState};

/// Retrieve the block snapshot for a given burnchain block hash
pub fn get_block_snapshot_by_burnchain_block_hash(
    sortdb: &SortitionDB,
    burn_header_hash: &BurnchainHeaderHash,
    preamble: &HttpRequestPreamble,
) -> Result<BlockSnapshot, StacksHttpResponse> {
    let handle = sortdb.index_handle_at_tip();
    let sort_id = match handle.get_sortition_id_for_bhh(burn_header_hash) {
        Ok(sort_id) => {
            let Some(sort_id) = sort_id else {
                let msg = format!("No sortition found for burn block hash '{burn_header_hash}'");
                debug!("{msg}");
                return Err(StacksHttpResponse::new_error(
                    preamble,
                    &HttpNotFound::new(msg),
                ))?;
            };
            sort_id
        }
        Err(e) => {
            let msg = format!(
                "Failed to get sortition snapshot for burn block hash '{burn_header_hash}': {e:?}"
            );
            error!("{msg}");
            Err(StacksHttpResponse::new_error(
                preamble,
                &HttpServerError::new(msg),
            ))?
        }
    };

    // load snapshot
    match SortitionDB::get_block_snapshot(handle.conn(), &sort_id) {
        Ok(snap) => {
            let Some(snap) = snap else {
                let msg =
                    format!("No sortition snapshot found for burn block hash '{burn_header_hash}'");
                debug!("{msg}");
                return Err(StacksHttpResponse::new_error(
                    preamble,
                    &HttpNotFound::new(msg),
                ));
            };
            Ok(snap)
        }
        Err(e) => {
            let msg = format!(
                "Failed to get sortition snapshot for burn block hash '{burn_header_hash}': {e:?}"
            );
            error!("{msg}");
            Err(StacksHttpResponse::new_error(
                preamble,
                &HttpServerError::new(msg),
            ))
        }
    }
}

#[derive(Clone)]
pub struct RPCNakamotoTenureBlocksByHashRequestHandler {
    pub(crate) burnchain_block_hash: Option<BurnchainHeaderHash>,
}

impl RPCNakamotoTenureBlocksByHashRequestHandler {
    pub fn new() -> Self {
        Self {
            burnchain_block_hash: None,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCNakamotoTenureBlocksByHashRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/tenures/blocks/hash/(?P<burnchain_block_hash>[0-9a-f]{64})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/tenures/blocks/hash/:burnchain_block_hash"
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
        let burnchain_block_hash =
            request::get_burnchain_header_hash(captures, "burnchain_block_hash")?;
        self.burnchain_block_hash = Some(burnchain_block_hash);
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCNakamotoTenureBlocksByHashRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.burnchain_block_hash = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let burnchain_block_hash = self
            .burnchain_block_hash
            .take()
            .ok_or(NetError::SendError("`burnchain_block_hash` not set".into()))?;

        let reply = node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
            let snapshot = get_block_snapshot_by_burnchain_block_hash(
                sortdb,
                &burnchain_block_hash,
                &preamble,
            )?;
            let last_sortition_ch =
                get_prior_last_sortition_consensus_hash(sortdb, &snapshot, &preamble)?;

            build_tenure_from_header_else_snapshot(
                chainstate,
                &snapshot,
                last_sortition_ch,
                &preamble,
                || {
                    NakamotoChainState::find_highest_known_block_header_in_tenure_by_block_hash(
                        chainstate,
                        sortdb,
                        &burnchain_block_hash,
                    )
                },
            )
        });

        encode_tenure_reply(&preamble, reply)
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCNakamotoTenureBlocksByHashRequestHandler {
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
    /// Make a new request to this endpoint
    pub fn new_get_tenure_blocks_by_hash(
        host: PeerHost,
        burnchain_block_hash: &BurnchainHeaderHash,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/tenures/blocks/hash/{burnchain_block_hash}"),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}
