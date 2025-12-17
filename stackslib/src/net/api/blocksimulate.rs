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

use clarity::util::hash::bytes_to_hex;
use regex::{Captures, Regex};
use stacks_common::codec::{Error as CodecError, StacksMessageCodec, MAX_PAYLOAD_LEN};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::hex_bytes;
use url::form_urlencoded;

use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::{Error as ChainError, StacksTransaction};
use crate::net::api::blockreplay::{remine_nakamoto_block, RPCReplayedBlock};
use crate::net::http::{
    parse_json, Error, HttpContentType, HttpNotFound, HttpRequest, HttpRequestContents,
    HttpRequestPreamble, HttpResponse, HttpResponseContents, HttpResponsePayload,
    HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{RPCRequestHandler, StacksHttpResponse};
use crate::net::{Error as NetError, StacksHttpRequest, StacksNodeState};

#[derive(Clone)]
pub struct RPCNakamotoBlockSimulateRequestHandler {
    pub block_id: Option<StacksBlockId>,
    pub auth: Option<String>,
    pub profiler: bool,
    pub disable_fees: bool,
    pub transactions: Vec<StacksTransaction>,
}

impl RPCNakamotoBlockSimulateRequestHandler {
    pub fn new(auth: Option<String>) -> Self {
        Self {
            block_id: None,
            auth,
            profiler: false,
            disable_fees: false,
            transactions: vec![],
        }
    }

    fn parse_json(body: &[u8]) -> Result<Vec<StacksTransaction>, Error> {
        let transactions_hex: Vec<String> = serde_json::from_slice(body)
            .map_err(|e| Error::DecodeError(format!("Failed to parse body: {e}")))?;

        let mut transactions = vec![];

        for tx_hex in transactions_hex {
            let tx_bytes =
                hex_bytes(&tx_hex).map_err(|_e| Error::DecodeError("Failed to parse tx".into()))?;
            let tx = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).map_err(|e| {
                if let CodecError::DeserializeError(msg) = e {
                    Error::DecodeError(format!("Failed to deserialize transaction: {}", msg))
                } else {
                    e.into()
                }
            })?;
            transactions.push(tx);
        }

        Ok(transactions)
    }

    pub fn block_simulate(
        &self,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
    ) -> Result<RPCReplayedBlock, ChainError> {
        let Some(block_id) = &self.block_id else {
            return Err(ChainError::InvalidStacksBlock("block_id is None".into()));
        };

        let rpc_simulated_block = remine_nakamoto_block(
            block_id,
            sortdb,
            chainstate,
            self.profiler,
            self.disable_fees,
            |_| self.transactions.clone(),
        )?;

        Ok(rpc_simulated_block)
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCNakamotoBlockSimulateRequestHandler {
    fn verb(&self) -> &'static str {
        "POST"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/blocks/simulate/(?P<block_id>[0-9a-f]{64})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/blocks/simulate/:block_id"
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        captures: &Captures,
        query: Option<&str>,
        body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        // If no authorization is set, then the block replay endpoint is not enabled
        let Some(password) = &self.auth else {
            return Err(Error::Http(400, "Bad Request.".into()));
        };
        let Some(auth_header) = preamble.headers.get("authorization") else {
            return Err(Error::Http(401, "Unauthorized".into()));
        };
        if auth_header != password {
            return Err(Error::Http(401, "Unauthorized".into()));
        }

        let block_id_str = captures
            .name("block_id")
            .ok_or_else(|| {
                Error::DecodeError("Failed to match path to block ID group".to_string())
            })?
            .as_str();

        let block_id = StacksBlockId::from_hex(block_id_str)
            .map_err(|_| Error::DecodeError("Invalid path: unparseable block id".to_string()))?;

        self.block_id = Some(block_id);

        if let Some(query_string) = query {
            for (key, value) in form_urlencoded::parse(query_string.as_bytes()) {
                if key == "profiler" {
                    if value == "1" {
                        self.profiler = true;
                    }
                } else if key == "disable_fees" {
                    if value == "1" {
                        self.disable_fees = true;
                    }
                }
            }
        }

        if preamble.get_content_length() == 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected non-zero-length body for block proposal endpoint"
                    .to_string(),
            ));
        }
        if preamble.get_content_length() > MAX_PAYLOAD_LEN {
            return Err(Error::DecodeError(
                "Invalid Http request: BlockProposal body is too big".to_string(),
            ));
        }

        self.transactions = match preamble.content_type {
            Some(HttpContentType::JSON) => Self::parse_json(body)?,
            Some(_) => {
                return Err(Error::DecodeError(
                    "Wrong Content-Type for block proposal; expected application/json".to_string(),
                ))
            }
            None => {
                return Err(Error::DecodeError(
                    "Missing Content-Type for block simulation".to_string(),
                ))
            }
        };

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCNakamotoBlockSimulateRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.block_id = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let Some(block_id) = &self.block_id else {
            return Err(NetError::SendError("Missing `block_id`".into()));
        };

        let simulated_block_res =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                self.block_simulate(sortdb, chainstate)
            });

        // start loading up the block
        let simulated_block = match simulated_block_res {
            Ok(simulated_block) => simulated_block,
            Err(ChainError::NoSuchBlockError) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new(format!("No such block {block_id}\n")),
                )
                .try_into_contents()
                .map_err(NetError::from)
            }
            Err(e) => {
                // nope -- error trying to check
                let msg = format!("Failed to simulate block {}: {:?}\n", &block_id, &e);
                warn!("{}", &msg);
                return StacksHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                    .try_into_contents()
                    .map_err(NetError::from);
            }
        };

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&simulated_block)?;
        Ok((preamble, body))
    }
}

impl StacksHttpRequest {
    /// Make a new block_replay request to this endpoint
    pub fn new_block_simulate(
        host: PeerHost,
        block_id: &StacksBlockId,
        transactions: &Vec<StacksTransaction>,
    ) -> StacksHttpRequest {
        let transactions_hex = transactions
            .iter()
            .map(|transaction| bytes_to_hex(&transaction.serialize_to_vec()))
            .collect();

        StacksHttpRequest::new_for_peer(
            host,
            "POST".into(),
            format!("/v3/blocks/simulate/{block_id}"),
            HttpRequestContents::new().payload_json(transactions_hex),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }

    pub fn new_block_simulate_with_profiler(
        host: PeerHost,
        block_id: &StacksBlockId,
        profiler: bool,
        transactions: &Vec<StacksTransaction>,
    ) -> StacksHttpRequest {
        let transactions_hex = transactions
            .iter()
            .map(|transaction| bytes_to_hex(&transaction.serialize_to_vec()))
            .collect();
        StacksHttpRequest::new_for_peer(
            host,
            "POST".into(),
            format!("/v3/blocks/simulate/{block_id}"),
            HttpRequestContents::new()
                .query_arg(
                    "profiler".into(),
                    if profiler { "1".into() } else { "0".into() },
                )
                .payload_json(transactions_hex),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }

    pub fn new_block_simulate_with_no_fees(
        host: PeerHost,
        block_id: &StacksBlockId,
        transactions: &Vec<StacksTransaction>,
    ) -> StacksHttpRequest {
        let transactions_hex = transactions
            .iter()
            .map(|transaction| bytes_to_hex(&transaction.serialize_to_vec()))
            .collect();
        StacksHttpRequest::new_for_peer(
            host,
            "POST".into(),
            format!("/v3/blocks/simulate/{block_id}"),
            HttpRequestContents::new()
                .query_arg("disable_fees".into(), "1".into())
                .payload_json(transactions_hex),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCNakamotoBlockSimulateRequestHandler {
    /// Decode this response from a byte stream.  This is called by the client to decode this
    /// message
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let rpc_replayed_block: RPCReplayedBlock = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(rpc_replayed_block)?)
    }
}

impl StacksHttpResponse {
    pub fn decode_simulated_block(self) -> Result<RPCReplayedBlock, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let replayed_block: RPCReplayedBlock = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(replayed_block)
    }
}
