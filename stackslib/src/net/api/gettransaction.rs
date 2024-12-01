// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use std::borrow::BorrowMut;
use std::io::{Read, Write};

use regex::{Captures, Regex};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, StacksBlockId, StacksPublicKey,
};
use stacks_common::types::net::PeerHost;
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::hash::{to_hex, Hash160, Sha256Sum};

use crate::burnchains::affirmation::AffirmationMap;
use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::is_transaction_log_enabled;
use crate::chainstate::stacks::db::StacksChainState;
use crate::core::mempool::MemPoolDB;
use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpNotImplemented, HttpRequest, HttpRequestContents,
    HttpRequestPreamble, HttpResponse, HttpResponseContents, HttpResponsePayload,
    HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    request, HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler,
    StacksHttpRequest, StacksHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, StacksNodeState, TipRequest};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub index_block_hash: StacksBlockId,
    pub tx: String,
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
        Regex::new(r#"^/v3/transactions/(?P<txid>[0-9a-f]{64})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/transactions/:txid"
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
        if !is_transaction_log_enabled() {
            return StacksHttpResponse::new_error(
                &preamble,
                &HttpNotImplemented::new("Transaction log is not enabled".into()),
            )
            .try_into_contents()
            .map_err(NetError::from);
        }

        let tip = match node.load_stacks_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };

        let txid = self
            .txid
            .take()
            .ok_or(NetError::SendError("`txid` no set".into()))?;

        node.with_node_state(|_network, _sortdb, chainstate, _mempool, _rpc_args| {
            let index_block_hashes = match NakamotoChainState::get_index_block_hashes_from_txid(
                chainstate.index_conn().conn(),
                txid,
            ) {
                Ok(index_block_hashes) => index_block_hashes,
                Err(e) => {
                    // nope -- error trying to check
                    let msg = format!("Failed to load transaction: {:?}\n", &e);
                    warn!("{}", &msg);
                    return StacksHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                        .try_into_contents()
                        .map_err(NetError::from);
                }
            };

            // search for the first matching tx with valid index_block_hash
            for index_block_hash in index_block_hashes {
                match chainstate
                    .nakamoto_blocks_db()
                    .get_nakamoto_block(&index_block_hash)
                {
                    Ok(nakamoto_block) => match nakamoto_block {
                        Some(block) => {
                            for tx in block.0.txs {
                                if tx.txid() == txid {
                                    // if the tx matches, check if the block is an ancestor of the specified tip
                                    let found_block = match chainstate
                                        .index_conn()
                                        .get_ancestor_block_height(&index_block_hash, &tip)
                                    {
                                        Ok(found_block) => found_block,
                                        Err(e) => {
                                            // nope -- error trying to check
                                            let msg =
                                                format!("Failed to check block tip: {:?}\n", &e);
                                            warn!("{}", &msg);
                                            return StacksHttpResponse::new_error(
                                                &preamble,
                                                &HttpServerError::new(msg),
                                            )
                                            .try_into_contents()
                                            .map_err(NetError::from);
                                        }
                                    };

                                    if found_block.is_some() {
                                        let preamble = HttpResponsePreamble::ok_json(&preamble);
                                        let body = HttpResponseContents::try_from_json(
                                            &TransactionResponse {
                                                index_block_hash,
                                                tx: to_hex(&tx.serialize_to_vec()),
                                            },
                                        )?;
                                        return Ok((preamble, body));
                                    }
                                }
                            }
                        }
                        // nakamoto block not found
                        None => (),
                    },
                    Err(e) => {
                        // nope -- error trying to check
                        let msg = format!("Failed to load transaction: {:?}\n", &e);
                        warn!("{}", &msg);
                        return StacksHttpResponse::new_error(
                            &preamble,
                            &HttpServerError::new(msg),
                        )
                        .try_into_contents()
                        .map_err(NetError::from);
                    }
                };
            }

            // txid not found
            return StacksHttpResponse::new_error(
                &preamble,
                &HttpNotFound::new(format!("No such transaction {:?}\n", &txid)),
            )
            .try_into_contents()
            .map_err(NetError::from);
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
    pub fn new_gettransaction(host: PeerHost, txid: Txid, tip: TipRequest) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/transactions/{}", &txid),
            HttpRequestContents::new().for_tip(tip),
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
