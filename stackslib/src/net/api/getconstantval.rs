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

use clarity::vm::ast::parser::v1::CLARITY_NAME_REGEX;
use clarity::vm::clarity::ClarityConnection;
use clarity::vm::representations::{CONTRACT_NAME_REGEX_STRING, STANDARD_PRINCIPAL_REGEX_STRING};
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::{ClarityName, ContractName};
use regex::{Captures, Regex};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::net::PeerHost;

use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble,
};
use crate::net::httpcore::{
    request, HttpRequestContentsExtensions as _, RPCRequestHandler, StacksHttpRequest,
    StacksHttpResponse,
};
use crate::net::{Error as NetError, StacksNodeState, TipRequest};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConstantValResponse {
    pub data: String,
}

#[derive(Clone)]
pub struct RPCGetConstantValRequestHandler {
    pub constname: Option<ClarityName>,
    pub contract_identifier: Option<QualifiedContractIdentifier>,
}

impl RPCGetConstantValRequestHandler {
    pub fn new() -> Self {
        Self {
            constname: None,
            contract_identifier: None,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCGetConstantValRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(&format!(
            "^/v2/constant_val/(?P<address>{})/(?P<contract>{})/(?P<constname>{})$",
            *STANDARD_PRINCIPAL_REGEX_STRING, *CONTRACT_NAME_REGEX_STRING, *CLARITY_NAME_REGEX
        ))
        .unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/constant_val/:principal/:contract_name/:const_name"
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

        let contract_identifier = request::get_contract_address(captures, "address", "contract")?;
        let constname = request::get_clarity_name(captures, "constname")?;

        self.contract_identifier = Some(contract_identifier);
        self.constname = Some(constname);

        let contents = HttpRequestContents::new().query_string(query);
        Ok(contents)
    }
}

/// Handle the HTTP request
impl RPCRequestHandler for RPCGetConstantValRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.contract_identifier = None;
        self.constname = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let contract_identifier = self.contract_identifier.take().ok_or(NetError::SendError(
            "`contract_identifier` not set".to_string(),
        ))?;
        let constant_name = self
            .constname
            .take()
            .ok_or(NetError::SendError("`constname` not set".to_string()))?;
        let tip = match node.load_stacks_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };

        let data_resp =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                chainstate.maybe_read_only_clarity_tx(
                    &sortdb.index_handle_at_block(chainstate, &tip)?,
                    &tip,
                    |clarity_tx| {
                        clarity_tx.with_clarity_db_readonly(|clarity_db| {
                            let contract = clarity_db.get_contract(&contract_identifier).ok()?;

                            let cst = contract
                                .contract_context
                                .lookup_variable(constant_name.as_str())?
                                .serialize_to_hex()
                                .ok()?;

                            let data = format!("0x{cst}");
                            Some(ConstantValResponse { data })
                        })
                    },
                )
            });

        let data_resp = match data_resp {
            Ok(Some(Some(data))) => data,
            Ok(Some(None)) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new("Constant not found".to_string()),
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

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&data_resp)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCGetConstantValRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let constant_val: ConstantValResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(constant_val)?)
    }
}

impl StacksHttpRequest {
    /// Make a new request for a constant val
    pub fn new_getconstantval(
        host: PeerHost,
        contract_addr: StacksAddress,
        contract_name: ContractName,
        constant_name: ClarityName,
        tip_req: TipRequest,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!(
                "/v2/constant_val/{}/{}/{}",
                &contract_addr, &contract_name, &constant_name
            ),
            HttpRequestContents::new().for_tip(tip_req),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_constant_val_response(self) -> Result<ConstantValResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let contents_json: serde_json::Value = contents.try_into()?;
        let resp: ConstantValResponse = serde_json::from_value(contents_json)
            .map_err(|_e| NetError::DeserializeError("Failed to load from JSON".to_string()))?;
        Ok(resp)
    }
}
