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
use clarity::util::secp256k1::Secp256k1PublicKey;
use regex::{Captures, Regex};
use serde_json::json;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::Sha256Sum;

use crate::burnchains::Burnchain;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::coordinator::OnChainRewardSetProvider;
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::boot::{
    PoxVersions, RewardSet, POX_1_NAME, POX_2_NAME, POX_3_NAME, POX_4_NAME,
};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::Error as ChainError;
use crate::core::mempool::MemPoolDB;
use crate::net::http::{
    parse_json, Error, HttpBadRequest, HttpNotFound, HttpRequest, HttpRequestContents,
    HttpRequestPreamble, HttpResponse, HttpResponseContents, HttpResponsePayload,
    HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp,
    StacksHttpRequest, StacksHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, StacksNodeState, TipRequest};
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::Error as DBError;

#[derive(Clone, Default)]
pub struct GetSignerRequestHandler {
    pub signer_pubkey: Option<Secp256k1PublicKey>,
    pub reward_cycle: Option<u64>,
}

impl GetSignerRequestHandler {
    pub fn new() -> Self {
        Self {
            signer_pubkey: None,
            reward_cycle: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSignerResponse {
    pub blocks_signed: u64,
}

/// Decode the HTTP request
impl HttpRequest for GetSignerRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(
            r#"^/v3/signer/(?P<signer_pubkey>0[23][0-9a-f]{64})/(?P<cycle_num>[0-9]{1,10})$"#,
        )
        .unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/signer/:signer_pubkey/:cycle_num"
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
                "Invalid Http request: expected 0-length body".into(),
            ));
        }

        let Some(cycle_num_str) = captures.name("cycle_num") else {
            return Err(Error::DecodeError(
                "Missing in request path: `cycle_num`".into(),
            ));
        };
        let Some(signer_pubkey_str) = captures.name("signer_pubkey") else {
            return Err(Error::DecodeError(
                "Missing in request path: `signer_pubkey`".into(),
            ));
        };

        let signer_pubkey = Secp256k1PublicKey::from_hex(signer_pubkey_str.into())
            .map_err(|e| Error::DecodeError(format!("Failed to signer public key: {e}")))?;

        let cycle_num = u64::from_str_radix(cycle_num_str.into(), 10)
            .map_err(|e| Error::DecodeError(format!("Failed to parse cycle number: {e}")))?;

        self.signer_pubkey = Some(signer_pubkey);
        self.reward_cycle = Some(cycle_num);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for GetSignerRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.signer_pubkey = None;
        self.reward_cycle = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let signer_pubkey = self
            .signer_pubkey
            .take()
            .ok_or(NetError::SendError("Missing `signer_pubkey`".into()))?;

        let reward_cycle = self
            .reward_cycle
            .take()
            .ok_or(NetError::SendError("Missing `reward_cycle`".into()))?;

        let result = node.with_node_state(|_network, _sortdb, chainstate, _mempool, _rpc_args| {
            NakamotoChainState::get_signer_block_count(
                &chainstate.index_conn(),
                &signer_pubkey,
                reward_cycle,
            )
        });

        let blocks_signed = match result {
            Ok(response) => response,
            Err(error) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new(error.to_string()),
                )
                .try_into_contents()
                .map_err(NetError::from);
            }
        };

        let response = GetSignerResponse { blocks_signed };

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
        let body = HttpResponseContents::try_from_json(&response)?;
        Ok((preamble, body))
    }
}

impl HttpResponse for GetSignerRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let response: GetSignerResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(response)?)
    }
}

impl StacksHttpRequest {
    /// Make a new getinfo request to this endpoint
    pub fn new_getsigner(
        host: PeerHost,
        signer_pubkey: &Secp256k1PublicKey,
        cycle_num: u64,
        tip_req: TipRequest,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/signer/{}/{cycle_num}", signer_pubkey.to_hex()),
            HttpRequestContents::new().for_tip(tip_req),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_signer(self) -> Result<GetSignerResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let response: GetSignerResponse = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(response)
    }
}
