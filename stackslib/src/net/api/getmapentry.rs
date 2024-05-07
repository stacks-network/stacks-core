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

use clarity::vm::ast::parser::v1::CLARITY_NAME_REGEX;
use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::database::{ClarityDatabase, STXBalance, StoreType};
use clarity::vm::representations::{
    CONTRACT_NAME_REGEX_STRING, PRINCIPAL_DATA_REGEX_STRING, STANDARD_PRINCIPAL_REGEX_STRING,
};
use clarity::vm::types::{
    PrincipalData, QualifiedContractIdentifier, StandardPrincipalData,
    BOUND_VALUE_SERIALIZATION_HEX,
};
use clarity::vm::{ClarityName, ClarityVersion, ContractName, Value};
use regex::{Captures, Regex};
use stacks_common::types::chainstate::{StacksAddress, StacksBlockId};
use stacks_common::types::net::PeerHost;
use stacks_common::types::Address;
use stacks_common::util::hash::{to_hex, Sha256Sum};

use crate::burnchains::Burnchain;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::Error as ChainError;
use crate::core::mempool::MemPoolDB;
use crate::net::http::{
    parse_json, Error, HttpContentType, HttpNotFound, HttpRequest, HttpRequestContents,
    HttpRequestPayload, HttpRequestPreamble, HttpResponse, HttpResponseContents,
    HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    request, HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp,
    StacksHttpRequest, StacksHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, StacksNodeState, TipRequest};
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::Error as DBError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MapEntryResponse {
    pub data: String,
    #[serde(rename = "proof")]
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marf_proof: Option<String>,
}

#[derive(Clone)]
pub struct RPCGetMapEntryRequestHandler {
    pub contract_identifier: Option<QualifiedContractIdentifier>,
    pub map_name: Option<ClarityName>,
    pub key: Option<Value>,
}
impl RPCGetMapEntryRequestHandler {
    pub fn new() -> Self {
        Self {
            contract_identifier: None,
            map_name: None,
            key: None,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCGetMapEntryRequestHandler {
    fn verb(&self) -> &'static str {
        "POST"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(&format!(
            "^/v2/map_entry/(?P<address>{})/(?P<contract>{})/(?P<map>{})$",
            *STANDARD_PRINCIPAL_REGEX_STRING, *CONTRACT_NAME_REGEX_STRING, *CLARITY_NAME_REGEX
        ))
        .unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/map_entry/:principal/:contract_name/:map_name"
    }

    /// Try to decode this request.
    /// The body must be a hex string, encoded as a JSON string.
    /// So, something like `"123abc"`.  It encodes the map key as a serialized Clarity value.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        captures: &Captures,
        query: Option<&str>,
        body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        let content_len = preamble.get_content_length();
        if !(content_len > 0 && content_len < BOUND_VALUE_SERIALIZATION_HEX) {
            return Err(Error::DecodeError(format!(
                "Invalid Http request: invalid body length for GetMapEntry ({})",
                content_len
            )));
        }

        if preamble.content_type != Some(HttpContentType::JSON) {
            return Err(Error::DecodeError(
                "Invalid content-type: expected application/json".into(),
            ));
        }

        let contract_identifier = request::get_contract_address(captures, "address", "contract")?;
        let map_name = request::get_clarity_name(captures, "map")?;

        let mut body_ptr = body;
        let value_hex: String = serde_json::from_reader(&mut body_ptr)
            .map_err(|_e| Error::DecodeError("Failed to parse JSON body".into()))?;

        let value = Value::try_deserialize_hex_untyped(&value_hex)
            .map_err(|_e| Error::DecodeError("Failed to deserialize key value".into()))?;

        self.contract_identifier = Some(contract_identifier);
        self.map_name = Some(map_name);
        self.key = Some(value);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

/// Handle the HTTP request
impl RPCRequestHandler for RPCGetMapEntryRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.contract_identifier = None;
        self.map_name = None;
        self.key = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let contract_identifier = self
            .contract_identifier
            .take()
            .ok_or(NetError::SendError("`contract_identifier` not set".into()))?;
        let map_name = self
            .map_name
            .take()
            .ok_or(NetError::SendError("`map_name` not set".into()))?;
        let key = self
            .key
            .take()
            .ok_or(NetError::SendError("`key` not set".into()))?;

        let tip = match node.load_stacks_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };
        let with_proof = contents.get_with_proof();
        let key =
            ClarityDatabase::make_key_for_data_map_entry(&contract_identifier, &map_name, &key)
                .map_err(|e| NetError::SerializeError(format!("{:?}", &e)))?;
        let none_response = Value::none()
            .serialize_to_hex()
            .map_err(|e| NetError::SerializeError(format!("{:?}", &e)))?;

        let data_resp =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), &tip, |clarity_tx| {
                    clarity_tx.with_clarity_db_readonly(|clarity_db| {
                        let (value_hex, marf_proof): (String, _) = if with_proof {
                            clarity_db
                                .get_data_with_proof(&key)
                                .ok()
                                .flatten()
                                .map(|(a, b)| (a, Some(format!("0x{}", to_hex(&b)))))
                                .unwrap_or_else(|| {
                                    test_debug!("No value for '{}' in {}", &key, tip);
                                    (none_response, Some("".into()))
                                })
                        } else {
                            clarity_db
                                .get_data(&key)
                                .ok()
                                .flatten()
                                .map(|a| (a, None))
                                .unwrap_or_else(|| {
                                    test_debug!("No value for '{}' in {}", &key, tip);
                                    (none_response, None)
                                })
                        };

                        let data = format!("0x{}", value_hex);
                        MapEntryResponse { data, marf_proof }
                    })
                })
            });

        let data_resp = match data_resp {
            Ok(Some(data)) => data,
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
impl HttpResponse for RPCGetMapEntryRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let map_entry: MapEntryResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(map_entry)?)
    }
}

impl StacksHttpRequest {
    /// Make a new request for a data map
    pub fn new_getmapentry(
        host: PeerHost,
        contract_addr: StacksAddress,
        contract_name: ContractName,
        map_name: ClarityName,
        key: Value,
        tip_req: TipRequest,
        with_proof: bool,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "POST".into(),
            format!(
                "/v2/map_entry/{}/{}/{}",
                &contract_addr, &contract_name, &map_name
            ),
            HttpRequestContents::new()
                .for_tip(tip_req)
                .query_arg("proof".into(), if with_proof { "1" } else { "0" }.into())
                .payload_json(serde_json::Value::String(
                    key.serialize_to_hex()
                        .expect("FATAL: invalid key could not be serialized"),
                )),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_map_entry_response(self) -> Result<MapEntryResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let contents_json: serde_json::Value = contents.try_into()?;
        let resp: MapEntryResponse = serde_json::from_value(contents_json)
            .map_err(|_e| NetError::DeserializeError("Failed to load from JSON".to_string()))?;
        Ok(resp)
    }
}
