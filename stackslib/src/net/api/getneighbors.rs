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

use clarity::vm::types::QualifiedContractIdentifier;
use regex::{Captures, Regex};
use stacks_common::types::net::{PeerAddress, PeerHost};
use stacks_common::util::hash::Hash160;

use crate::net::db::PeerDB;
use crate::net::http::{
    parse_json, Error, HttpContentType, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpVersion,
};
use crate::net::httpcore::{
    HttpPreambleExtensions, RPCRequestHandler, StacksHttp, StacksHttpRequest, StacksHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, NeighborKey, StacksNodeState, MAX_NEIGHBORS_DATA_LEN};

#[derive(Clone)]
pub struct RPCNeighborsRequestHandler {}
impl RPCNeighborsRequestHandler {
    pub fn new() -> Self {
        Self {}
    }
}

/// Items in the NeighborsInfo -- combines NeighborKey and NeighborAddress
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCNeighbor {
    pub network_id: u32,
    pub peer_version: u32,
    #[serde(rename = "ip")]
    pub addrbytes: PeerAddress,
    pub port: u16,
    pub public_key_hash: Hash160,
    pub authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stackerdbs: Option<Vec<QualifiedContractIdentifier>>,
}

impl RPCNeighbor {
    pub fn from_neighbor_key_and_pubkh(
        nk: NeighborKey,
        pkh: Hash160,
        auth: bool,
        stackerdbs: Vec<QualifiedContractIdentifier>,
    ) -> RPCNeighbor {
        RPCNeighbor {
            network_id: nk.network_id,
            peer_version: nk.peer_version,
            addrbytes: nk.addrbytes,
            port: nk.port,
            public_key_hash: pkh,
            authenticated: auth,
            stackerdbs: Some(stackerdbs),
        }
    }
}

/// Struct given back from a call to `/v2/neighbors`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCNeighborsInfo {
    pub bootstrap: Vec<RPCNeighbor>,
    pub sample: Vec<RPCNeighbor>,
    pub inbound: Vec<RPCNeighbor>,
    pub outbound: Vec<RPCNeighbor>,
}

impl RPCNeighborsInfo {
    /// Load neighbor address information from the peer network
    pub fn from_p2p(network: &PeerNetwork) -> Result<RPCNeighborsInfo, NetError> {
        let network_epoch = network.get_current_epoch().network_epoch;
        let network_id = network.get_local_peer().network_id;
        let max_neighbor_age = network.get_connection_opts().max_neighbor_age;
        let burnchain_view = network.get_chain_view();
        let peerdb_conn = network.peerdb_conn();

        let bootstrap_nodes =
            PeerDB::get_bootstrap_peers(peerdb_conn, network_id).map_err(NetError::DBError)?;
        let bootstrap = bootstrap_nodes
            .into_iter()
            .map(|n| {
                let stackerdb_contract_ids =
                    PeerDB::static_get_peer_stacker_dbs(peerdb_conn, &n).unwrap_or(vec![]);
                RPCNeighbor::from_neighbor_key_and_pubkh(
                    n.addr.clone(),
                    Hash160::from_node_public_key(&n.public_key),
                    true,
                    stackerdb_contract_ids,
                )
            })
            .collect();

        let neighbor_sample = PeerDB::get_fresh_random_neighbors(
            peerdb_conn,
            network_id,
            network_epoch,
            max_neighbor_age,
            MAX_NEIGHBORS_DATA_LEN,
            burnchain_view.burn_block_height,
            false,
        )
        .map_err(NetError::DBError)?;

        let sample: Vec<RPCNeighbor> = neighbor_sample
            .into_iter()
            .map(|n| {
                let stackerdb_contract_ids =
                    PeerDB::static_get_peer_stacker_dbs(peerdb_conn, &n).unwrap_or(vec![]);
                RPCNeighbor::from_neighbor_key_and_pubkh(
                    n.addr.clone(),
                    Hash160::from_node_public_key(&n.public_key),
                    true,
                    stackerdb_contract_ids,
                )
            })
            .collect();

        let mut inbound = vec![];
        let mut outbound = vec![];
        for event_id in network.iter_peer_event_ids() {
            let convo = if let Some(convo) = network.get_p2p_convo(*event_id) {
                convo
            } else {
                continue;
            };

            let nk = convo.to_neighbor_key();
            let naddr = convo.to_neighbor_address();
            if convo.is_outbound() {
                outbound.push(RPCNeighbor::from_neighbor_key_and_pubkh(
                    nk,
                    naddr.public_key_hash,
                    convo.is_authenticated(),
                    convo.get_stackerdb_contract_ids().to_vec(),
                ));
            } else {
                inbound.push(RPCNeighbor::from_neighbor_key_and_pubkh(
                    nk,
                    naddr.public_key_hash,
                    convo.is_authenticated(),
                    convo.get_stackerdb_contract_ids().to_vec(),
                ));
            }
        }

        Ok(RPCNeighborsInfo {
            bootstrap,
            sample,
            inbound,
            outbound,
        })
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCNeighborsRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v2/neighbors$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/neighbors"
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
                "Invalid Http request: expected 0-length body for GetNeighbors".to_string(),
            ));
        }
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCNeighborsRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {}

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let neighbor_data =
            node.with_node_state(|network, _sortdb, _chainstate, _mempool, _rpc_args| {
                RPCNeighborsInfo::from_p2p(network)
            })?;

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
        let body = HttpResponseContents::try_from_json(&neighbor_data)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCNeighborsRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let neighbor_info: RPCNeighborsInfo = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(neighbor_info)?)
    }
}

impl StacksHttpRequest {
    /// Make a new getneighbors request to this endpoint
    pub fn new_getneighbors(host: PeerHost) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            "/v2/neighbors".into(),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    /// Make a new neighbors response
    #[cfg(test)]
    pub fn new_getneighbors(
        neighbors: RPCNeighborsInfo,
        with_content_length: bool,
    ) -> StacksHttpResponse {
        let value =
            serde_json::to_value(neighbors).expect("FATAL: failed to encode infallible data");
        let length = serde_json::to_string(&value)
            .expect("FATAL: failed to encode infallible data")
            .len();
        let preamble = HttpResponsePreamble::new(
            HttpVersion::Http11,
            200,
            "OK".to_string(),
            if with_content_length {
                Some(length as u32)
            } else {
                None
            },
            HttpContentType::JSON,
            true,
        );
        let body = HttpResponsePayload::JSON(value);
        StacksHttpResponse::new(preamble, body)
    }

    pub fn decode_rpc_neighbors(self) -> Result<RPCNeighborsInfo, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let rpc_neighbor_info = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(rpc_neighbor_info)
    }
}
