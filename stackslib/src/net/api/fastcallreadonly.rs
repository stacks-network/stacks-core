// Copyright (C) 2025 Stacks Open Internet Foundation
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

use std::time::Duration;

use clarity::vm::analysis::CheckErrors;
use clarity::vm::ast::parser::v1::CLARITY_NAME_REGEX;
use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::errors::Error::Unchecked;
use clarity::vm::representations::{CONTRACT_NAME_REGEX_STRING, STANDARD_PRINCIPAL_REGEX_STRING};
use clarity::vm::types::PrincipalData;
use clarity::vm::{ClarityName, ContractName, SymbolicExpression, Value};
use regex::{Captures, Regex};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::net::PeerHost;

use crate::net::api::callreadonly::{
    CallReadOnlyRequestBody, CallReadOnlyResponse, RPCCallReadOnlyRequestHandler,
};
use crate::net::http::{
    parse_json, Error, HttpContentType, HttpNotFound, HttpRequest, HttpRequestContents,
    HttpRequestPreamble, HttpRequestTimeout, HttpResponse, HttpResponseContents,
    HttpResponsePayload, HttpResponsePreamble,
};
use crate::net::httpcore::{
    request, HttpRequestContentsExtensions as _, RPCRequestHandler, StacksHttpRequest,
    StacksHttpResponse,
};
use crate::net::{Error as NetError, StacksNodeState, TipRequest};

#[derive(Clone)]
pub struct RPCFastCallReadOnlyRequestHandler {
    pub call_read_only_handler: RPCCallReadOnlyRequestHandler,
    read_only_max_execution_time: Duration,
    pub auth: Option<String>,
}

impl RPCFastCallReadOnlyRequestHandler {
    pub fn new(
        maximum_call_argument_size: u32,
        read_only_max_execution_time: Duration,
        auth: Option<String>,
    ) -> Self {
        Self {
            call_read_only_handler: RPCCallReadOnlyRequestHandler::new(
                maximum_call_argument_size,
                ExecutionCost {
                    write_length: 0,
                    write_count: 0,
                    read_length: 0,
                    read_count: 0,
                    runtime: 0,
                },
            ),
            read_only_max_execution_time,
            auth,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCFastCallReadOnlyRequestHandler {
    fn verb(&self) -> &'static str {
        "POST"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(&format!(
            "^/v3/contracts/fast-call-read/(?P<address>{})/(?P<contract>{})/(?P<function>{})$",
            *STANDARD_PRINCIPAL_REGEX_STRING, *CONTRACT_NAME_REGEX_STRING, *CLARITY_NAME_REGEX
        ))
        .unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/contracts/fast-call-read/:principal/:contract_name/:func_name"
    }

    /// Try to decode this request.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        captures: &Captures,
        query: Option<&str>,
        body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        // If no authorization is set, then the block proposal endpoint is not enabled
        let Some(password) = &self.auth else {
            return Err(Error::Http(400, "Bad Request.".into()));
        };
        let Some(auth_header) = preamble.headers.get("authorization") else {
            return Err(Error::Http(401, "Unauthorized".into()));
        };
        if auth_header != password {
            return Err(Error::Http(401, "Unauthorized".into()));
        }

        let content_len = preamble.get_content_length();
        if !(content_len > 0
            && content_len < self.call_read_only_handler.maximum_call_argument_size)
        {
            return Err(Error::DecodeError(format!(
                "Invalid Http request: invalid body length for FastCallReadOnly ({})",
                content_len
            )));
        }

        if preamble.content_type != Some(HttpContentType::JSON) {
            return Err(Error::DecodeError(
                "Invalid content-type: expected application/json".to_string(),
            ));
        }

        let contract_identifier = request::get_contract_address(captures, "address", "contract")?;
        let function = request::get_clarity_name(captures, "function")?;
        let body: CallReadOnlyRequestBody = serde_json::from_slice(body)
            .map_err(|_e| Error::DecodeError("Failed to parse JSON body".into()))?;

        let sender = PrincipalData::parse(&body.sender)
            .map_err(|_e| Error::DecodeError("Failed to parse sender principal".into()))?;

        let sponsor = if let Some(sponsor) = body.sponsor {
            Some(
                PrincipalData::parse(&sponsor)
                    .map_err(|_e| Error::DecodeError("Failed to parse sponsor principal".into()))?,
            )
        } else {
            None
        };

        // arguments must be valid Clarity values
        let arguments = body
            .arguments
            .into_iter()
            .map(|hex| Value::try_deserialize_hex_untyped(&hex).ok())
            .collect::<Option<Vec<Value>>>()
            .ok_or_else(|| Error::DecodeError("Failed to deserialize argument value".into()))?;

        self.call_read_only_handler.contract_identifier = Some(contract_identifier);
        self.call_read_only_handler.function = Some(function);
        self.call_read_only_handler.sender = Some(sender);
        self.call_read_only_handler.sponsor = sponsor;
        self.call_read_only_handler.arguments = Some(arguments);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

/// Handle the HTTP request
impl RPCRequestHandler for RPCFastCallReadOnlyRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.call_read_only_handler.contract_identifier = None;
        self.call_read_only_handler.function = None;
        self.call_read_only_handler.sender = None;
        self.call_read_only_handler.sponsor = None;
        self.call_read_only_handler.arguments = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let tip = match node.load_stacks_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };

        let contract_identifier = self
            .call_read_only_handler
            .contract_identifier
            .take()
            .ok_or(NetError::SendError("Missing `contract_identifier`".into()))?;
        let function = self
            .call_read_only_handler
            .function
            .take()
            .ok_or(NetError::SendError("Missing `function`".into()))?;
        let sender = self
            .call_read_only_handler
            .sender
            .take()
            .ok_or(NetError::SendError("Missing `sender`".into()))?;
        let sponsor = self.call_read_only_handler.sponsor.clone();
        let arguments = self
            .call_read_only_handler
            .arguments
            .take()
            .ok_or(NetError::SendError("Missing `arguments`".into()))?;

        // run the read-only call
        let data_resp =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                let args: Vec<_> = arguments
                    .iter()
                    .map(|x| SymbolicExpression::atom_value(x.clone()))
                    .collect();

                let mainnet = chainstate.mainnet;
                let chain_id = chainstate.chain_id;

                chainstate.maybe_read_only_clarity_tx(
                    &sortdb.index_handle_at_block(chainstate, &tip)?,
                    &tip,
                    |clarity_tx| {
                        clarity_tx.with_readonly_clarity_env(
                            mainnet,
                            chain_id,
                            sender,
                            sponsor,
                            LimitedCostTracker::new_free(),
                            |env| {
                                // cost tracking in read only calls is meamingful mainly from a security point of view
                                // for this reason we enforce max_execution_time when cost tracking is disabled/free

                                env.global_context
                                    .set_max_execution_time(self.read_only_max_execution_time);

                                // we want to execute any function as long as no actual writes are made as
                                // opposed to be limited to purely calling `define-read-only` functions,
                                // so use `read_only = false`.  This broadens the number of functions that
                                // can be called, and also circumvents limitations on `define-read-only`
                                // functions that can not use `contrac-call?`, even when calling other
                                // read-only functions
                                env.execute_contract(
                                    &contract_identifier,
                                    function.as_str(),
                                    &args,
                                    false,
                                )
                            },
                        )
                    },
                )
            });

        // decode the response
        let data_resp = match data_resp {
            Ok(Some(Ok(data))) => {
                let hex_result = data
                    .serialize_to_hex()
                    .map_err(|e| NetError::SerializeError(format!("{:?}", &e)))?;

                CallReadOnlyResponse {
                    okay: true,
                    result: Some(format!("0x{}", hex_result)),
                    cause: None,
                }
            }
            Ok(Some(Err(e))) => match e {
                Unchecked(CheckErrors::CostBalanceExceeded(actual_cost, _))
                    if actual_cost.write_count > 0 =>
                {
                    CallReadOnlyResponse {
                        okay: false,
                        result: None,
                        cause: Some("NotReadOnly".to_string()),
                    }
                }
                Unchecked(CheckErrors::ExecutionTimeExpired) => {
                    return StacksHttpResponse::new_error(
                        &preamble,
                        &HttpRequestTimeout::new("ExecutionTime expired".to_string()),
                    )
                    .try_into_contents()
                    .map_err(NetError::from)
                }
                _ => CallReadOnlyResponse {
                    okay: false,
                    result: None,
                    cause: Some(e.to_string()),
                },
            },
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
impl HttpResponse for RPCFastCallReadOnlyRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let map_entry: CallReadOnlyResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(map_entry)?)
    }
}

impl StacksHttpRequest {
    /// Make a new request to run a read-only function
    pub fn new_fastcallreadonlyfunction(
        host: PeerHost,
        contract_addr: StacksAddress,
        contract_name: ContractName,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        function_name: ClarityName,
        function_args: Vec<Value>,
        tip_req: TipRequest,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "POST".into(),
            format!(
                "/v3/contracts/fast-call-read/{}/{}/{}",
                &contract_addr, &contract_name, &function_name
            ),
            HttpRequestContents::new().for_tip(tip_req).payload_json(
                serde_json::to_value(CallReadOnlyRequestBody {
                    sender: sender.to_string(),
                    sponsor: sponsor.map(|s| s.to_string()),
                    arguments: function_args.into_iter().map(|v| v.to_string()).collect(),
                })
                .expect("FATAL: failed to encode infallible data"),
            ),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}
