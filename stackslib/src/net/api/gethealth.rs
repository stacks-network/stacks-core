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

use std::borrow::BorrowMut;
use std::io::{Read, Write};

use regex::{Captures, Regex};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, StacksBlockId, StacksPublicKey,
};
use stacks_common::types::net::PeerHost;
use stacks_common::types::{StacksEpochId, StacksPublicKeyBuffer};
use stacks_common::util::hash::{to_hex, Hash160, Sha256Sum};

use crate::burnchains::affirmation::AffirmationMap;
use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::StacksTransaction;
use crate::core::mempool::MemPoolDB;
use crate::net::db::PeerDB;
use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpNotImplemented, HttpRequest, HttpRequestContents,
    HttpRequestPreamble, HttpResponse, HttpResponseContents, HttpResponsePayload,
    HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    request, HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler,
    StacksHttpRequest, StacksHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{
    infer_initial_burnchain_block_download, Error as NetError, NeighborAddress, StacksNodeState,
    TipRequest,
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
        node.with_node_state(|network, _sortdb, _chainstate, _mempool, _rpc_args| {
            let current_epoch = network.get_current_epoch();

            let initial_neighbors = PeerDB::get_valid_initial_neighbors(
                network.peerdb.conn(),
                network.local_peer.network_id,
                current_epoch.network_epoch,
                network.peer_version,
                network.chain_view.burn_block_height,
            )
            .map_err(NetError::from)?;

            let node_stacks_tip_height = network.stacks_tip.height;
            let bitcoin_tip_height = network.chain_view.burn_block_height;
            let bitcoin_last_processed_height = network.burnchain_tip.block_height;
            // no bootstrap nodes found, unable to determine health.
            if initial_neighbors.len() == 0 {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpServerError::new(
                        "No viable bootstrap peers found, unable to determine health".into(),
                    ),
                )
                .try_into_contents()
                .map_err(NetError::from);
            }

            let peer_max_stacks_height_opt  = {
                if current_epoch.epoch_id < StacksEpochId::Epoch30 {
                    // When the node enters Epoch 3.0, ibd is not accurate. In nakamoto it's always set to false.
                    // See the implementation of `RunLoop::start` in `testnet/stacks-node/src/run_loop/nakamoto.rs`,
                    // specifically the section and comment where `let ibd = false`, for details.
                    let ibd = infer_initial_burnchain_block_download(
                        &network.burnchain,
                        bitcoin_last_processed_height,
                        bitcoin_tip_height,
                    );
                    // get max block height amongst bootstrap nodes
                    match network.inv_state.as_ref() {
                        Some(inv_state) => {
                            inv_state.get_max_stacks_height_of_neighbors(&initial_neighbors, ibd)
                        }
                        None => {
                            return create_error_response(
                                &preamble,
                                "Peer inventory state (Epoch 2.x) not found, unable to determine health.",
                            );
                        }
                    }
                } else {
                    let initial_neighbours_addresses: Vec<NeighborAddress> = initial_neighbors.iter().map(NeighborAddress::from_neighbor).collect();
                    match network.block_downloader_nakamoto.as_ref() {
                        Some(block_downloader_nakamoto) => block_downloader_nakamoto.get_max_stacks_height_of_neighbors(&initial_neighbours_addresses),
                        None => {
                            return create_error_response(
                                &preamble,
                                "Nakamoto block downloader not found (Epoch 3.0+), unable to determine health.",
                            );
                        }
                    }
                }
            };

            match peer_max_stacks_height_opt  {
                Some(max_stacks_height_of_neighbors) => {
                    // There could be a edge case where our node is ahead of all peers.
                    let difference_from_max_peer = max_stacks_height_of_neighbors.saturating_sub(node_stacks_tip_height);

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
    /// Make a new get-unconfirmed-tx request
    pub fn new_gethealth(host: PeerHost) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/health"),
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
