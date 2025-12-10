// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2025 Stacks Open Internet Foundation
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
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::net::PeerHost;

use crate::burnchains::Txid;
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpNotImplemented, HttpRequest, HttpRequestContents,
    HttpRequestPreamble, HttpResponse, HttpResponseContents, HttpResponsePayload,
    HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{request, RPCRequestHandler, StacksHttpRequest, StacksHttpResponse};
use crate::net::{Error as NetError, StacksNodeState};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub index_block_hash: StacksBlockId,
    pub tx: String,
    pub result: String,
    pub block_height: Option<u64>,
    pub is_canonical: bool,
}

#[derive(Clone)]
pub struct RPCGetTransactionRequestHandler {
    pub txid: Option<Txid>,
}
impl RPCGetTransactionRequestHandler {
    pub fn new() -> Self {
        Self { txid: None }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCGetTransactionRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/transaction/(?P<txid>[0-9a-f]{64})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/transaction/:txid"
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
                "Invalid Http request: expected 0-length body for GetTransaction".to_string(),
            ));
        }

        let txid = request::get_txid(captures, "txid")?;
        self.txid = Some(txid);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCGetTransactionRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.txid = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        if !node.txindex {
            return StacksHttpResponse::new_error(
                &preamble,
                &HttpNotImplemented::new("Transaction indexing is not enabled".into()),
            )
            .try_into_contents()
            .map_err(NetError::from);
        }

        let txid = self
            .txid
            .take()
            .ok_or(NetError::SendError("`txid` no set".into()))?;

        let tip = match node.load_stacks_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };

        node.with_node_state(|_network, _sortdb, chainstate, _mempool, _rpc_args| {
            let index_block_hash_and_tx_hex_opt = match NakamotoChainState::get_tx_info_from_txid(
                chainstate.index_conn().conn(),
                &txid,
            ) {
                Ok(index_block_hash_and_tx_hex_opt) => index_block_hash_and_tx_hex_opt,
                Err(e) => {
                    // nope -- error trying to check
                    let msg = format!("Failed to load transaction: {e:?}\n");
                    warn!("{msg}");
                    return StacksHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                        .try_into_contents()
                        .map_err(NetError::from);
                }
            };

            match index_block_hash_and_tx_hex_opt {
                Some((index_block_hash, tx_hex, result)) => {
                    let block_height = chainstate
                        .index_conn()
                        .get_ancestor_block_height(&index_block_hash, &tip)?;
                    let is_canonical = chainstate
                        .index_conn()
                        .get_ancestor_block_height(&index_block_hash, &tip)
                        .map(|height_opt| height_opt.is_some())
                        .unwrap_or(false);
                    let preamble = HttpResponsePreamble::ok_json(&preamble);
                    let body = HttpResponseContents::try_from_json(&TransactionResponse {
                        index_block_hash: index_block_hash.clone(),
                        tx: tx_hex,
                        result,
                        block_height,
                        is_canonical,
                    })?;
                    return Ok((preamble, body));
                }
                None => {
                    // txid not found
                    return StacksHttpResponse::new_error(
                        &preamble,
                        &HttpNotFound::new(format!("No such transaction {txid:?}\n")),
                    )
                    .try_into_contents()
                    .map_err(NetError::from);
                }
            }
        })
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCGetTransactionRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let txinfo: TransactionResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(txinfo)?)
    }
}

impl StacksHttpRequest {
    /// Make a new get-unconfirmed-tx request
    pub fn new_gettransaction(host: PeerHost, txid: Txid) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/transaction/{}", &txid),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_gettransaction(self) -> Result<TransactionResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let txinfo: TransactionResponse = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(txinfo)
    }
}
