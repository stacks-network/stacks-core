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

use regex::{Captures, Regex};
use stacks_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, StacksBlockId, StacksPublicKey,
};
use stacks_common::types::net::PeerHost;
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::hash::{Hash160, Sha256Sum};

use crate::burnchains::affirmation::AffirmationMap;
use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::StacksChainState;
use crate::core::mempool::MemPoolDB;
use crate::net::http::{
    parse_json, Error, HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse,
    HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    HttpPreambleExtensions, RPCRequestHandler, StacksHttpRequest, StacksHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, StacksNodeState};

/// The request to GET /v3/diagnostics
#[derive(Clone)]
pub struct RPCDiagnosticsHandler {}
impl RPCDiagnosticsHandler {
    pub fn new() -> Self {
        Self {}
    }
}

/// Node diagnostics
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCDiagnosticsData {
}

impl RPCDiagnosticsData {
    pub fn from_network(
        network: &PeerNetwork,
        chainstate: &StacksChainState,
    ) -> RPCDiagnosticsData {

    }
}

/// Decode the HTTP request
impl HttpRequest for RPCDiagnosticsHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/diagnostics$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/diagnostics"
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
                "Invalid Http request: expected 0-length body for GetInfo".to_string(),
            ));
        }
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCDiagnosticsHandler {
    /// Reset internal state
    fn restart(&mut self) {}

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        
        let rpc_peer_info: Result<RPCDiagnosticsData, StacksHttpResponse> =
            node.with_node_state(|network, _sortdb, chainstate, _mempool, rpc_args| {
                let coinbase_height = network.stacks_tip.coinbase_height;

                Ok(RPCDiagnosticsData::from_network(
                    network,
                    chainstate,
                ))
            });

        let rpc_diagnostics_info = match rpc_diagnostics_info {
            Ok(rpc_diagnostics_info) => rpc_diagnostics_info,
            Err(response) => {
                return response.try_into_contents().map_err(NetError::from);
            }
        };

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
        let body = HttpResponseContents::try_from_json(&rpc_peer_info)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCDiagnosticsHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let peer_info: RPCPeerInfoData = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(peer_info)?)
    }
}

impl StacksHttpRequest {
    /// Make a new getdiagnostics request to this endpoint
    pub fn new_getdiagnostics(host: PeerHost) -> StacksHttpRequest {
        let mut req = StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            "/v3/diagnostics".into(),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data");
        req.preamble_mut()
            .set_canonical_stacks_tip_height(stacks_height);
        req
    }
}

impl StacksHttpResponse {
    pub fn decode_diagnostics_data(self) -> Result<RPCDiagnosticsData, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let diagnostics_info: RPCDiagnosticsData = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(diagnostics_info)
    }
}
