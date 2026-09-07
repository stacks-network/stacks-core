// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use clarity::vm::analysis::RuntimeCheckErrorKind;
use clarity::vm::ast::parser::v1::CLARITY_NAME_REGEX;
use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::errors::ClarityEvalError;
use clarity::vm::errors::VmExecutionError::{self, RuntimeCheck};
use clarity::vm::representations::{CONTRACT_NAME_REGEX_STRING, STANDARD_PRINCIPAL_REGEX_STRING};
use clarity::vm::resource_limiter::{ResourceBudget, ResourceLimiter};
use clarity::vm::types::{BoundedErrorString, PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{ClarityName, ContractName, SymbolicExpression, Value};
use regex::{Captures, Regex};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::net::PeerHost;

pub use crate::net::api::read_only::parse::CallReadOnlyRequestBody;
use crate::net::api::read_only::parse::{
    parse_read_only_call_body, remaining_execution_mem_budget,
};
use crate::net::http::{
    parse_json, Error, HttpBadRequest, HttpContentType, HttpNotFound, HttpRequest,
    HttpRequestContents, HttpRequestPreamble, HttpResponse, HttpResponseContents,
    HttpResponsePayload, HttpResponsePreamble,
};
use crate::net::httpcore::{
    request, HttpRequestContentsExtensions as _, RPCRequestHandler, StacksHttpRequest,
    StacksHttpResponse,
};
use crate::net::{Error as NetError, StacksNodeState, TipRequest};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallReadOnlyResponse {
    pub okay: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<BoundedErrorString>,
}

#[derive(Clone)]
pub struct RPCCallReadOnlyRequestHandler {
    /// Maximum encoded HTTP body size accepted by the endpoint.
    pub maximum_call_argument_size: u32,
    read_only_call_limit: ExecutionCost,
    read_only_max_execution_time: Duration,
    pub read_only_call_max_mem_bytes: u64,

    /// Runtime fields
    pub contract_identifier: Option<QualifiedContractIdentifier>,
    pub function: Option<ClarityName>,
    pub sender: Option<PrincipalData>,
    pub sponsor: Option<PrincipalData>,
    pub arguments: Option<Vec<Value>>,
    /// Net bytes retained by parsing, deducted from the execution budget.
    pub parse_retained_mem_bytes: u64,
}

impl RPCCallReadOnlyRequestHandler {
    pub fn new(
        maximum_call_argument_size: u32,
        read_only_call_limit: ExecutionCost,
        read_only_max_execution_time: Duration,
        read_only_call_max_mem_bytes: u64,
    ) -> Self {
        Self {
            maximum_call_argument_size,
            read_only_call_limit,
            read_only_max_execution_time,
            read_only_call_max_mem_bytes,
            contract_identifier: None,
            function: None,
            sender: None,
            sponsor: None,
            arguments: None,
            parse_retained_mem_bytes: 0,
        }
    }

    /// Starts tracking at call time: build it before any execution-side
    /// allocation, e.g. converting the arguments.
    pub fn execution_resource_limiter(&self) -> ResourceLimiter {
        ResourceBudget::new()
            .with_max_duration(Some(self.read_only_max_execution_time))
            .with_max_memory_use(remaining_execution_mem_budget(
                self.read_only_call_max_mem_bytes,
                self.parse_retained_mem_bytes,
            ))
            .start_tracking()
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCCallReadOnlyRequestHandler {
    fn verb(&self) -> &'static str {
        "POST"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(&format!(
            "^/v2/contracts/call-read/(?P<address>{})/(?P<contract>{})/(?P<function>{})$",
            *STANDARD_PRINCIPAL_REGEX_STRING, *CONTRACT_NAME_REGEX_STRING, *CLARITY_NAME_REGEX
        ))
        .unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/contracts/call-read/:principal/:contract_name/:func_name"
    }

    /// Try to decode this request.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        captures: &Captures,
        query: Option<&str>,
        body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        let content_len = preamble.get_content_length();
        if !(content_len > 0 && content_len < self.maximum_call_argument_size) {
            return Err(Error::DecodeError(format!(
                "Invalid Http request: invalid body length for CallReadOnly ({})",
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
        let parsed = parse_read_only_call_body(body, self.read_only_call_max_mem_bytes)?;

        self.contract_identifier = Some(contract_identifier);
        self.function = Some(function);
        self.sender = Some(parsed.sender);
        self.sponsor = parsed.sponsor;
        self.arguments = Some(parsed.arguments);
        self.parse_retained_mem_bytes = parsed.retained_mem_bytes;

        Ok(HttpRequestContents::new().query_string(query))
    }
}

/// Handle the HTTP request
impl RPCRequestHandler for RPCCallReadOnlyRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.contract_identifier = None;
        self.function = None;
        self.sender = None;
        self.sponsor = None;
        self.arguments = None;
        self.parse_retained_mem_bytes = 0;
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
            .contract_identifier
            .take()
            .ok_or(NetError::SendError("Missing `contract_identifier`".into()))?;
        let function = self
            .function
            .take()
            .ok_or(NetError::SendError("Missing `function`".into()))?;
        let sender = self
            .sender
            .take()
            .ok_or(NetError::SendError("Missing `sender`".into()))?;
        let sponsor = self.sponsor.take();
        let arguments = self
            .arguments
            .take()
            .ok_or(NetError::SendError("Missing `arguments`".into()))?;

        // Started before the argument conversion so it counts against execution.
        let resource_limiter = self.execution_resource_limiter();

        // run the read-only call
        let data_resp =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                let args: Vec<_> = arguments
                    .into_iter()
                    .map(SymbolicExpression::atom_value)
                    .collect();

                let mainnet = chainstate.mainnet;
                let chain_id = chainstate.chain_id;
                let mut cost_limit = self.read_only_call_limit.clone();
                cost_limit.write_length = 0;
                cost_limit.write_count = 0;

                chainstate.maybe_read_only_clarity_tx(
                    &sortdb.index_handle_at_block(chainstate, &tip)?,
                    &tip,
                    |clarity_tx| {
                        let epoch = clarity_tx.get_epoch();
                        let cost_track = clarity_tx
                            .with_clarity_db_readonly(|clarity_db| {
                                LimitedCostTracker::new_mid_block(
                                    mainnet, chain_id, cost_limit, clarity_db, epoch,
                                )
                            })
                            .map_err(VmExecutionError::from)?;

                        clarity_tx.with_readonly_clarity_env(
                            mainnet,
                            chain_id,
                            sender,
                            sponsor,
                            cost_track,
                            |exec_state, invoke_ctx| {
                                exec_state
                                    .global_context
                                    .set_execution_resource_limiter(resource_limiter);

                                // we want to execute any function as long as no actual writes are made as
                                // opposed to be limited to purely calling `define-read-only` functions,
                                // so use `read_only = false`.  This broadens the number of functions that
                                // can be called, and also circumvents limitations on `define-read-only`
                                // functions that can not use `contrac-call?`, even when calling other
                                // read-only functions
                                exec_state
                                    .execute_contract(
                                        invoke_ctx,
                                        &contract_identifier,
                                        function.as_str(),
                                        &args,
                                        false,
                                    )
                                    .map_err(ClarityEvalError::from)
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
                ClarityEvalError::Vm(RuntimeCheck(RuntimeCheckErrorKind::CostBalanceExceeded(
                    actual_cost,
                    _,
                ))) if actual_cost.write_count > 0 => CallReadOnlyResponse {
                    okay: false,
                    result: None,
                    cause: Some("NotReadOnly".into()),
                },
                ClarityEvalError::Vm(RuntimeCheck(
                    RuntimeCheckErrorKind::ExecutionResourceBudgetExceeded(_),
                )) => {
                    return StacksHttpResponse::new_error(
                        &preamble,
                        &HttpBadRequest::new("Execution budget exceeded".to_string()),
                    )
                    .try_into_contents()
                    .map_err(NetError::from)
                }
                _ => CallReadOnlyResponse {
                    okay: false,
                    result: None,
                    cause: Some(BoundedErrorString::from_display(&e)),
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
impl HttpResponse for RPCCallReadOnlyRequestHandler {
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
    pub fn new_callreadonlyfunction(
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
                "/v2/contracts/call-read/{}/{}/{}",
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

impl StacksHttpResponse {
    pub fn decode_call_readonly_response(self) -> Result<CallReadOnlyResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let contents_json: serde_json::Value = contents.try_into()?;
        let resp: CallReadOnlyResponse = serde_json::from_value(contents_json)
            .map_err(|_e| NetError::DeserializeError("Failed to load from JSON".to_string()))?;
        Ok(resp)
    }
}
