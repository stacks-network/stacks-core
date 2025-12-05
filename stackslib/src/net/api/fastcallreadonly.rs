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

use clarity::vm::ast::parser::v1::CLARITY_NAME_REGEX;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::representations::{CONTRACT_NAME_REGEX_STRING, STANDARD_PRINCIPAL_REGEX_STRING};
use clarity::vm::types::PrincipalData;
use clarity::vm::{ClarityName, ContractName, Value};
use regex::{Captures, Regex};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::net::PeerHost;

use crate::net::api::callreadonly::{
    CallReadOnlyRequestBody, CallReadOnlyResponse, RPCCallReadOnlyRequestHandler,
};
use crate::net::http::{
    parse_json, Error, HttpContentType, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble,
};
use crate::net::httpcore::{
    request, HttpRequestContentsExtensions as _, RPCRequestHandler, StacksHttpRequest,
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
        //
        self.call_read_only_handler.execute_contract_function(
            preamble,
            contents,
            node,
            Some(LimitedCostTracker::new_free()),
            |env| {
                env.global_context
                    .set_max_execution_time(self.read_only_max_execution_time);
            },
        )
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
