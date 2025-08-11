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

use std::fmt;
use std::str::FromStr;

use regex::{Captures, Regex};
use stacks_common::types::net::PeerHost;
use stacks_common::types::StacksEpochId;

use crate::net::db::PeerDB;
use crate::net::http::{
    parse_json, Error, HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse,
    HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{RPCRequestHandler, StacksHttpRequest, StacksHttpResponse};
use crate::net::{
    infer_initial_burnchain_block_download, Error as NetError, NeighborAddress, StacksNodeState,
};

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
    /// the height of this node
    pub node_stacks_tip_height: u64,
}

const NEIGHBORS_SCOPE_PARAM_NAME: &str = "neighbors";

#[derive(Clone, Debug, PartialEq)]
pub enum NeighborsScope {
    Initial,
    All,
}

impl FromStr for NeighborsScope {
    type Err = crate::net::http::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "initial" => Ok(NeighborsScope::Initial),
            "all" => Ok(NeighborsScope::All),
            _ => Err(crate::net::http::Error::Http(
                400,
                format!(
                    "Invalid `neighbors` query parameter: `{}`, allowed values are `initial` or `all`",
                    s
                ),
            )),
        }
    }
}

impl fmt::Display for NeighborsScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            NeighborsScope::Initial => "initial",
            NeighborsScope::All => "all",
        };
        write!(f, "{s}")
    }
}

#[derive(Clone)]
/// Empty request handler for the GET /v3/health endpoint
pub struct RPCGetHealthRequestHandler {
    neighbors_scope: Option<NeighborsScope>,
}

impl RPCGetHealthRequestHandler {
    pub fn new() -> Self {
        Self {
            neighbors_scope: None,
        }
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

        let req_contents = HttpRequestContents::new().query_string(query);
        if let Some(scope) = req_contents.get_query_arg(NEIGHBORS_SCOPE_PARAM_NAME) {
            self.neighbors_scope = Some(scope.parse()?);
        }

        Ok(req_contents)
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
    fn restart(&mut self) {
        self.neighbors_scope = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let neighbors_scope = self
            .neighbors_scope
            .take()
            .unwrap_or(NeighborsScope::Initial);
        let use_all_neighbors = neighbors_scope == NeighborsScope::All;

        node.with_node_state(|network, _sortdb, _chainstate, _mempool, _rpc_args| {
            let current_epoch = network.get_current_epoch();

            let neighbors_arg = if use_all_neighbors {
                None
            } else {
                let initial_neighbors = PeerDB::get_valid_initial_neighbors(
                    network.peerdb.conn(),
                    network.local_peer.network_id,
                    current_epoch.network_epoch,
                    network.peer_version,
                    network.chain_view.burn_block_height,
                )
                .map_err(NetError::from)?;

                if initial_neighbors.is_empty() {
                    return create_error_response(
                        &preamble,
                        "No viable bootstrap peers found, unable to determine health",
                    );
                }
                Some(initial_neighbors)
            };

            let peer_max_stacks_height_opt = {
                if current_epoch.epoch_id < StacksEpochId::Epoch30 {
                    // When the node enters Epoch 3.0, ibd is not accurate. In nakamoto it's always set to false.
                    // See the implementation of `RunLoop::start` in `stacks-node/src/run_loop/nakamoto.rs`,
                    // specifically the section and comment where `let ibd = false`, for details.
                    let ibd = infer_initial_burnchain_block_download(
                        &network.burnchain,
                        network.burnchain_tip.block_height,
                        network.chain_view.burn_block_height,
                    );

                    // get max block height amongst bootstrap nodes
                    match network.inv_state.as_ref() {
                        Some(inv_state) => {
                            inv_state.get_max_stacks_height_of_neighbors(neighbors_arg.as_deref(), ibd)
                        }
                        None => {
                            return create_error_response(
                                &preamble,
                                "Peer inventory state (Epoch 2.x) not found, unable to determine health.",
                            );
                        }
                    }
                } else {
                    let neighbors_arg: Option<Vec<NeighborAddress>> = neighbors_arg.as_ref().map(|v| v.iter().map(NeighborAddress::from_neighbor).collect());
                    match network.block_downloader_nakamoto.as_ref() {
                        Some(block_downloader_nakamoto) => {
                            block_downloader_nakamoto.get_max_stacks_height_of_neighbors(neighbors_arg.as_deref())
                        }
                        None => {
                            return create_error_response(
                                &preamble,
                                "Nakamoto block downloader not found (Epoch 3.0+), unable to determine health.",
                            );
                        }
                    }
                }
            };

            match peer_max_stacks_height_opt {
                Some(max_stacks_height_of_neighbors) => {
                    // There could be a edge case where our node is ahead of all peers.
                    let node_stacks_tip_height = network.stacks_tip.height;
                    let difference_from_max_peer =
                        max_stacks_height_of_neighbors.saturating_sub(node_stacks_tip_height);

                    let preamble = HttpResponsePreamble::ok_json(&preamble);
                    let data = RPCGetHealthResponse {
                        difference_from_max_peer,
                        max_stacks_height_of_neighbors,
                        node_stacks_tip_height,
                    };
                    let body = HttpResponseContents::try_from_json(&data)?;
                    Ok((preamble, body))
                }
                None => create_error_response(
                    &preamble,
                    "Couldn't obtain stats on any bootstrap peers, unable to determine health.",
                ),
            }
        })
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
    pub fn new_gethealth(host: PeerHost, neighbors_scope: NeighborsScope) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            "/v3/health".into(),
            HttpRequestContents::new().query_arg(
                NEIGHBORS_SCOPE_PARAM_NAME.into(),
                neighbors_scope.to_string(),
            ),
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
