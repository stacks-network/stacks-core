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

use std::io::{Read, Seek, SeekFrom, Write};
use std::{fs, io};

use regex::{Captures, Regex};
use rusqlite::Connection;
use serde::de::Error as de_Error;
use stacks_common::codec::{StacksMessageCodec, MAX_MESSAGE_LEN};
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};
use stacks_common::types::net::PeerHost;
use {serde, serde_json};

use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState, NakamotoStagingBlocksConn};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::Error as ChainError;
use crate::net::api::getblock_v3::{NakamotoBlockStream, RPCNakamotoBlockRequestHandler};
use crate::net::http::{
    parse_bytes, Error, HttpBadRequest, HttpChunkGenerator, HttpContentType, HttpNotFound,
    HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse, HttpResponseContents,
    HttpResponsePayload, HttpResponsePreamble, HttpServerError, HttpVersion,
};
use crate::net::httpcore::{
    HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp, StacksHttpRequest,
    StacksHttpResponse,
};
use crate::net::{Error as NetError, StacksNodeState, TipRequest, MAX_HEADERS};
use crate::util_lib::db::{DBConn, Error as DBError};

#[derive(Clone)]
pub struct RPCNakamotoBlockByHashRequestHandler {
    pub block_hash: Option<BlockHeaderHash>,
}

impl RPCNakamotoBlockByHashRequestHandler {
    pub fn new() -> Self {
        Self { block_hash: None }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCNakamotoBlockByHashRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/blockbyhash/(?P<block_hash>[0-9a-f]{64})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/blockbyhash/:block_hash"
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

        let block_hash_str = captures
            .name("block_hash")
            .ok_or_else(|| {
                Error::DecodeError("Failed to match path to block hash group".to_string())
            })?
            .as_str();

        let block_hash = BlockHeaderHash::from_hex(block_hash_str).map_err(|_| {
            Error::DecodeError("Invalid path: unparseable consensus hash".to_string())
        })?;
        self.block_hash = Some(block_hash);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCNakamotoBlockByHashRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.block_hash = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let block_hash = self
            .block_hash
            .take()
            .ok_or(NetError::SendError("Missing `block_hash`".into()))?;

        let index_block_hash_res =
            node.with_node_state(|_network, _sortdb, chainstate, _mempool, _rpc_args| {
                chainstate
                    .nakamoto_blocks_db()
                    .get_block_id_by_block_hash(&block_hash)
            });

        let block_id = match index_block_hash_res {
            Ok(index_block_hash_opt) => match index_block_hash_opt {
                Some(index_block_hash) => index_block_hash,
                None => {
                    // block hash not found
                    let msg = format!("No such block {:?}\n", &block_hash);
                    warn!("{}", &msg);
                    return StacksHttpResponse::new_error(&preamble, &HttpNotFound::new(msg))
                        .try_into_contents()
                        .map_err(NetError::from);
                }
            },
            Err(e) => {
                // error querying the db
                let msg = format!("Failed to load block {}: {:?}\n", &block_hash, &e);
                warn!("{}", &msg);
                return StacksHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                    .try_into_contents()
                    .map_err(NetError::from);
            }
        };

        // start loading up the block
        let stream = match RPCNakamotoBlockRequestHandler::get_stream_by_node(&block_id, node) {
            Ok(stream) => stream,
            Err(ChainError::NoSuchBlockError) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new(format!("No such block {:?}\n", &block_hash)),
                )
                .try_into_contents()
                .map_err(NetError::from)
            }
            Err(e) => {
                // nope -- error trying to check
                let msg = format!("Failed to load block {}: {:?}\n", &block_hash, &e);
                warn!("{}", &msg);
                return StacksHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                    .try_into_contents()
                    .map_err(NetError::from);
            }
        };

        let resp_preamble = HttpResponsePreamble::from_http_request_preamble(
            &preamble,
            200,
            "OK",
            None,
            HttpContentType::Bytes,
        );

        Ok((
            resp_preamble,
            HttpResponseContents::from_stream(Box::new(stream)),
        ))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCNakamotoBlockByHashRequestHandler {
    /// Decode this response from a byte stream.  This is called by the client to decode this
    /// message
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let bytes = parse_bytes(preamble, body, MAX_MESSAGE_LEN.into())?;
        Ok(HttpResponsePayload::Bytes(bytes))
    }
}

impl StacksHttpRequest {
    pub fn new_get_nakamoto_block_by_hash(
        host: PeerHost,
        block_hash: BlockHeaderHash,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/blockbyhash/{}", &block_hash),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}
