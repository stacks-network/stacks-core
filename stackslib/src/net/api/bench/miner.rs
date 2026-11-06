// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! `GET` and `POST /bench/v1/miner`.

use regex::{Captures, Regex};
use stacks_common::types::net::PeerHost;

use super::check_auth;
use crate::bench_hooks::miner::{self as miner_hooks, MinerBenchCommand, MinerBenchStatus};
use crate::net::http::{
    parse_json, Error, HttpContentType, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble,
};
use crate::net::httpcore::{RPCRequestHandler, StacksHttpRequest, StacksHttpResponse};
use crate::net::{Error as NetError, StacksNodeState};

pub const BENCH_MINER_PATH: &str = "/bench/v1/miner";

/// Largest accepted command body. Commands are tiny JSON objects.
const MAX_COMMAND_BODY_LEN: u32 = 4096;

/// Handler for `GET /bench/v1/miner`: report the miner controls.
#[derive(Clone)]
pub struct RPCBenchMinerStatusRequestHandler {
    pub auth: Option<String>,
}

impl RPCBenchMinerStatusRequestHandler {
    pub fn new(auth: Option<String>) -> Self {
        Self { auth }
    }
}

/// Handler for `POST /bench/v1/miner`: apply a [`MinerBenchCommand`].
#[derive(Clone)]
pub struct RPCBenchMinerCommandRequestHandler {
    pub auth: Option<String>,
    pub command: Option<MinerBenchCommand>,
}

impl RPCBenchMinerCommandRequestHandler {
    pub fn new(auth: Option<String>) -> Self {
        Self {
            auth,
            command: None,
        }
    }
}

impl HttpRequest for RPCBenchMinerStatusRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(&format!("^{BENCH_MINER_PATH}$")).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        BENCH_MINER_PATH
    }

    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        _captures: &Captures,
        query: Option<&str>,
        _body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        check_auth(&self.auth, preamble)?;
        if preamble.get_content_length() != 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected 0-length body".to_string(),
            ));
        }
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl HttpRequest for RPCBenchMinerCommandRequestHandler {
    fn verb(&self) -> &'static str {
        "POST"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(&format!("^{BENCH_MINER_PATH}$")).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        BENCH_MINER_PATH
    }

    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        _captures: &Captures,
        query: Option<&str>,
        body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        check_auth(&self.auth, preamble)?;
        if preamble.get_content_length() == 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected a JSON command body".to_string(),
            ));
        }
        if preamble.get_content_length() > MAX_COMMAND_BODY_LEN {
            return Err(Error::DecodeError(
                "Invalid Http request: command body is too big".to_string(),
            ));
        }
        if !matches!(preamble.content_type, Some(HttpContentType::JSON)) {
            return Err(Error::DecodeError(
                "Invalid Http request: expected Content-Type application/json".to_string(),
            ));
        }
        let command = serde_json::from_slice(body)
            .map_err(|e| Error::DecodeError(format!("Invalid miner command: {e}")))?;
        self.command = Some(command);
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCBenchMinerStatusRequestHandler {
    fn restart(&mut self) {}

    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        _node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&miner_hooks::status())?;
        Ok((preamble, body))
    }
}

impl RPCRequestHandler for RPCBenchMinerCommandRequestHandler {
    fn restart(&mut self) {
        self.command = None;
    }

    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        _node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let command = self
            .command
            .take()
            .ok_or(NetError::SendError("Missing `command`".into()))?;
        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&miner_hooks::apply(command))?;
        Ok((preamble, body))
    }
}

impl HttpResponse for RPCBenchMinerStatusRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let status: MinerBenchStatus = parse_json(preamble, body)?;
        HttpResponsePayload::try_from_json(status)
    }
}

impl HttpResponse for RPCBenchMinerCommandRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let status: MinerBenchStatus = parse_json(preamble, body)?;
        HttpResponsePayload::try_from_json(status)
    }
}

impl StacksHttpRequest {
    /// Make a `GET /bench/v1/miner` request
    pub fn new_bench_miner_status(host: PeerHost) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            BENCH_MINER_PATH.into(),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }

    /// Make a `POST /bench/v1/miner` request
    pub fn new_bench_miner_command(
        host: PeerHost,
        command: MinerBenchCommand,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "POST".into(),
            BENCH_MINER_PATH.into(),
            HttpRequestContents::new().payload_json(
                serde_json::to_value(command).expect("FATAL: failed to encode MinerBenchCommand"),
            ),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_bench_miner_status(self) -> Result<MinerBenchStatus, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let status: MinerBenchStatus = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(status)
    }
}
