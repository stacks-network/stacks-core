// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2025 Stacks Open Internet Foundation
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
use stacks_common::types::net::PeerHost;

use crate::net::http::{
    parse_json, Error, HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse,
    HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{RPCRequestHandler, StacksHttpRequest, StacksHttpResponse};
use crate::net::{Error as NetError, StacksNodeState};

/// The response for the GET /v3/health endpoint
/// This endpoint returns the difference in height between the node and its most advanced neighbor
/// and the heights of the node and its most advanced neighbor.
/// A user can use `difference_from_max_peer` to decide what is a good value
/// for them before considering the node out of sync.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCGetHealthResponse {
    /// provides the difference in height between the node and its most advanced neighbor
    pub difference_from_max_peer: u64,
    /// the max height of the node's most advanced neighbor
    pub max_stacks_height_of_neighbors: u64,
    /// the address of the node's most advanced neighbor
    pub max_stacks_neighbor_address: Option<String>,
    /// the height of this node
    pub node_stacks_tip_height: u64,
}

#[derive(Clone)]
/// Empty request handler for the GET /v3/health endpoint
pub struct RPCGetHealthRequestHandler {}

impl RPCGetHealthRequestHandler {
    pub fn new() -> Self {
        Self {}
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCGetHealthRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/health$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/health"
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
                "Invalid Http request: expected 0-length body for GetHealth".to_string(),
            ));
        }

        Ok(HttpRequestContents::new().query_string(query))
    }
}

fn create_error_response(
    preamble: &HttpRequestPreamble,
    error_message: &str,
) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
    StacksHttpResponse::new_error(preamble, &HttpServerError::new(error_message.to_string()))
        .try_into_contents()
        .map_err(NetError::from)
}

impl RPCRequestHandler for RPCGetHealthRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {}

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let ((max_stacks_neighbor_address, max_stacks_height_of_neighbors), node_stacks_tip_height) =
            node.with_node_state(|network, _sortdb, _chainstate, _mempool, _rpc_args| {
                (
                    network
                        .highest_stacks_neighbor
                        .map(|(addr, height)| (Some(addr.to_string()), height))
                        .unwrap_or((None, 0)),
                    network.stacks_tip.height,
                )
            });

        // There could be a edge case where our node is ahead of all peers.
        let difference_from_max_peer =
            max_stacks_height_of_neighbors.saturating_sub(node_stacks_tip_height);

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let data = RPCGetHealthResponse {
            difference_from_max_peer,
            max_stacks_height_of_neighbors,
            max_stacks_neighbor_address,
            node_stacks_tip_height,
        };
        let body = HttpResponseContents::try_from_json(&data)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCGetHealthRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let txinfo: RPCGetHealthResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(txinfo)?)
    }
}

impl StacksHttpRequest {
    pub fn new_gethealth(host: PeerHost) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            "/v3/health".into(),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_gethealth(self) -> Result<RPCGetHealthResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let txinfo: RPCGetHealthResponse = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(txinfo)
    }
}
