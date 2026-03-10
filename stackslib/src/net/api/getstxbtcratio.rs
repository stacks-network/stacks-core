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

use regex::{Captures, Regex};
use stacks_common::types::net::PeerHost;

use crate::chainstate::nakamoto::{NakamotoChainState, StxBtcCycleRatio};
use crate::net::http::{
    parse_json, Error, HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse,
    HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError,
    HttpUnauthorized,
};
use crate::net::httpcore::{
    HttpRequestContentsExtensions as _, RPCRequestHandler, StacksHttpRequest, StacksHttpResponse,
};
use crate::net::{Error as NetError, StacksNodeState, TipRequest};

#[derive(Clone)]
pub struct GetStxBtcRatioRequestHandler {
    pub reward_cycle: Option<u64>,
    pub auth: Option<String>,
}

impl GetStxBtcRatioRequestHandler {
    pub fn new(auth: Option<String>) -> Self {
        Self {
            reward_cycle: None,
            auth,
        }
    }
}

/// Response body for `GET /v3/stx_btc_ratio/:cycle_num`.
///
/// ## Units
/// `stx_btc_ratio` and `smoothed_stx_btc_ratio` are in **μSTX per satoshi**.
/// To convert to STX/BTC multiply by 100 (1 BTC = 10⁸ sat, 1 STX = 10⁶ μSTX).
///
/// ## None semantics
/// A ratio field is `None` when the cycle has no usable data (no tenures, or no BTC burned).
/// `Some(0)` means data exists but miners earned zero STX that cycle.
///
/// ## Smoothing window
/// `smoothed_stx_btc_ratio` is the weighted geometric mean across up to 5 cycles ending at
/// `reward_cycle`, with weights [5, 4, 3, 2, 1]. Cycles with no data are excluded.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetStxBtcRatioResponse {
    /// The reward cycle this response describes.
    pub reward_cycle: u64,
    /// Number of tenures that completed in this cycle.
    pub tenure_count: u64,
    /// Total STX (coinbase + fees) earned by miners in this cycle, in micro-STX.
    pub stx_earned_ustx: u128,
    /// Total BTC spent by all block-commit transactions in this cycle, in satoshis.
    /// Includes PoX outputs plus estimated Bitcoin tx fees for every competing commit.
    pub btc_spent_sats: u64,
    /// Raw μSTX/sat ratio for this cycle, or `None` if the cycle has no data.
    pub stx_btc_ratio: Option<u128>,
    /// 5-cycle weighted geometric mean in μSTX/sat, or `None` if this cycle has no data.
    pub smoothed_stx_btc_ratio: Option<u128>,
}

impl From<StxBtcCycleRatio> for GetStxBtcRatioResponse {
    fn from(value: StxBtcCycleRatio) -> Self {
        Self {
            reward_cycle: value.reward_cycle,
            tenure_count: value.tenure_count,
            stx_earned_ustx: value.stx_earned_ustx,
            btc_spent_sats: value.btc_spent_sats,
            stx_btc_ratio: value.stx_btc_ratio,
            smoothed_stx_btc_ratio: value.smoothed_stx_btc_ratio,
        }
    }
}

impl HttpRequest for GetStxBtcRatioRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/stx_btc_ratio/(?P<cycle_num>[0-9]{1,10})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/stx_btc_ratio/:cycle_num"
    }

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

        let cycle_num = u64::from_str_radix(cycle_num_str.into(), 10)
            .map_err(|e| Error::DecodeError(format!("Failed to parse cycle number: {e}")))?;

        self.reward_cycle = Some(cycle_num);
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for GetStxBtcRatioRequestHandler {
    fn restart(&mut self) {
        self.reward_cycle = None;
    }

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

        let reward_cycle = self
            .reward_cycle
            .take()
            .ok_or(NetError::SendError("Missing `reward_cycle`".into()))?;

        // Check if the cache covers all cycles needed for this request (the requested
        // cycle plus the 4 prior cycles used by the smoothing window). If any are
        // missing, the computation is expensive and requires auth.
        let cache_warm =
            node.with_node_state(|_network, _sortdb, chainstate, _mempool, _rpc_args| {
                let start_cycle = reward_cycle.saturating_sub(4);
                NakamotoChainState::is_cycle_cache_warm(
                    chainstate.db(),
                    start_cycle,
                    reward_cycle,
                    &tip,
                )
            });

        if !cache_warm {
            if let Some(password) = &self.auth {
                let auth_header = preamble.headers.get("authorization");
                if auth_header.map(|h| h != password).unwrap_or(true) {
                    return StacksHttpResponse::new_error(
                        &preamble,
                        &HttpUnauthorized::new(
                            "Cache is cold for this cycle; auth required".into(),
                        ),
                    )
                    .try_into_contents()
                    .map_err(NetError::from);
                }
            }
        }

        let response = node.with_node_state(|network, sortdb, chainstate, _mempool, _rpc_args| {
            let burnchain = network.get_burnchain();
            NakamotoChainState::get_stx_btc_ratio_for_cycle(
                &mut chainstate.index_conn(),
                sortdb,
                &tip,
                &burnchain.pox_constants,
                burnchain.first_block_height,
                reward_cycle,
            )
            .map(GetStxBtcRatioResponse::from)
        });

        let response = match response {
            Ok(response) => response,
            Err(error) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpServerError::new(error.to_string()),
                )
                .try_into_contents()
                .map_err(NetError::from);
            }
        };

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&response)?;
        Ok((preamble, body))
    }
}

impl HttpResponse for GetStxBtcRatioRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let response: GetStxBtcRatioResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(response)?)
    }
}

impl StacksHttpRequest {
    pub fn new_get_stx_btc_ratio(
        host: PeerHost,
        cycle_num: u64,
        tip_req: TipRequest,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/stx_btc_ratio/{cycle_num}"),
            HttpRequestContents::new().for_tip(tip_req),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_stx_btc_ratio(self) -> Result<GetStxBtcRatioResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let response: GetStxBtcRatioResponse = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(response)
    }
}
