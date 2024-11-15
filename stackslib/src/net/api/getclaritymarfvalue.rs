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

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::representations::CONTRACT_PRINCIPAL_REGEX_STRING;
use lazy_static::lazy_static;
use regex::{Captures, Regex};
use stacks_common::types::chainstate::TrieHash;
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::to_hex;

use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble,
};
use crate::net::httpcore::{
    request, HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler,
    StacksHttpRequest, StacksHttpResponse,
};
use crate::net::{Error as NetError, StacksNodeState, TipRequest};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClarityMarfResponse {
    pub data: String,
    #[serde(rename = "proof")]
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marf_proof: Option<String>,
}

#[derive(Clone)]
pub struct RPCGetClarityMarfRequestHandler {
    pub marf_key_hash: Option<TrieHash>,
}
impl RPCGetClarityMarfRequestHandler {
    pub fn new() -> Self {
        Self {
            marf_key_hash: None,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCGetClarityMarfRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v2/clarity/marf/(?P<marf_key_hash>[0-9a-f]{64})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/clarity/marf/:marf_key_hash"
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

        let marf_key = if let Some(key_str) = captures.name("marf_key_hash") {
            TrieHash::from_hex(key_str.as_str())
                .map_err(|e| Error::Http(400, format!("Invalid hash string: {e:?}")))?
        } else {
            return Err(Error::Http(404, "Missing `marf_key_hash`".to_string()));
        };

        self.marf_key_hash = Some(marf_key);

        let contents = HttpRequestContents::new().query_string(query);
        Ok(contents)
    }
}

/// Handle the HTTP request
impl RPCRequestHandler for RPCGetClarityMarfRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.marf_key_hash = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let marf_key_hash = self
            .marf_key_hash
            .take()
            .ok_or(NetError::SendError("`marf_key_hash` not set".to_string()))?;

        let tip = match node.load_stacks_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };

        let with_proof = contents.get_with_proof();

        let data_opt = node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
            chainstate.maybe_read_only_clarity_tx(
                &sortdb.index_handle_at_block(chainstate, &tip)?,
                &tip,
                |clarity_tx| {
                    clarity_tx.with_clarity_db_readonly(|clarity_db| {
                        let (value_hex, marf_proof): (String, _) = if with_proof {
                            clarity_db
                                .get_data_with_proof_by_hash(&marf_key_hash)
                                .ok()
                                .flatten()
                                .map(|(a, b)| (a, Some(format!("0x{}", to_hex(&b)))))?
                        } else {
                            clarity_db
                                .get_data_by_hash(&marf_key_hash)
                                .ok()
                                .flatten()
                                .map(|a| (a, None))?
                        };

                        let data = format!("0x{}", value_hex);
                        Some(ClarityMarfResponse { data, marf_proof })
                    })
                },
            )
        });

        let data_resp = match data_opt {
            Ok(Some(Some(data))) => data,
            Ok(Some(None)) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new("Marf key hash not found".to_string()),
                )
                .try_into_contents()
                .map_err(NetError::from);
            }
            Ok(None) | Err(_) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new("Chain tip not found".to_string()),
                )
                .try_into_contents()
                .map_err(NetError::from);
            }
        };

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
        let body = HttpResponseContents::try_from_json(&data_resp)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCGetClarityMarfRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let marf_value: ClarityMarfResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(marf_value)?)
    }
}

impl StacksHttpRequest {
    pub fn new_getclaritymarf(
        host: PeerHost,
        marf_key_hash: TrieHash,
        tip_req: TipRequest,
        with_proof: bool,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v2/clarity/marf/{}", &marf_key_hash),
            HttpRequestContents::new()
                .for_tip(tip_req)
                .query_arg("proof".into(), if with_proof { "1" } else { "0" }.into()),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_clarity_marf_response(self) -> Result<ClarityMarfResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let contents_json: serde_json::Value = contents.try_into()?;
        let resp: ClarityMarfResponse = serde_json::from_value(contents_json)
            .map_err(|_e| NetError::DeserializeError("Failed to load from JSON".to_string()))?;
        Ok(resp)
    }
}
