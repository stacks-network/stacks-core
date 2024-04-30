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
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId};
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::to_hex;
use {serde, serde_json};

use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState, NakamotoStagingBlocksConn};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::Error as ChainError;
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
pub struct RPCNakamotoBlockRequestHandler {
    pub block_id: Option<StacksBlockId>,
}

impl RPCNakamotoBlockRequestHandler {
    pub fn new() -> Self {
        Self { block_id: None }
    }
}

pub struct NakamotoBlockStream {
    /// index block hash of the block to download
    pub index_block_hash: StacksBlockId,
    /// consensus hash of this block (identifies its tenure; used by the tenure stream)
    pub consensus_hash: ConsensusHash,
    /// parent index block hash of the block to download (used by the tenure stream)
    pub parent_block_id: StacksBlockId,
    /// offset into the blob
    pub offset: u64,
    /// total number of bytes read.
    pub total_bytes: u64,
    /// Connection to the staging DB
    pub staging_db_conn: NakamotoStagingBlocksConn,
    /// rowid of the block
    pub rowid: i64,
}

impl NakamotoBlockStream {
    pub fn new(
        chainstate: &StacksChainState,
        block_id: StacksBlockId,
        consensus_hash: ConsensusHash,
        parent_block_id: StacksBlockId,
    ) -> Result<Self, ChainError> {
        let staging_db_path = chainstate.get_nakamoto_staging_blocks_path()?;
        let db_conn = StacksChainState::open_nakamoto_staging_blocks(&staging_db_path, false)?;
        let rowid = db_conn
            .conn()
            .get_nakamoto_block_rowid(&block_id)?
            .ok_or(ChainError::NoSuchBlockError)?;

        Ok(NakamotoBlockStream {
            index_block_hash: block_id,
            consensus_hash,
            parent_block_id,
            offset: 0,
            total_bytes: 0,
            staging_db_conn: db_conn,
            rowid,
        })
    }

    /// reset the stream to send another block.
    /// Does not change the DB connection or consensus hash.
    pub fn reset(
        &mut self,
        block_id: StacksBlockId,
        parent_block_id: StacksBlockId,
    ) -> Result<(), ChainError> {
        let rowid = self
            .staging_db_conn
            .conn()
            .get_nakamoto_block_rowid(&block_id)?
            .ok_or(ChainError::NoSuchBlockError)?;

        self.index_block_hash = block_id;
        self.parent_block_id = parent_block_id;
        self.offset = 0;
        self.total_bytes = 0;
        self.rowid = rowid;
        Ok(())
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCNakamotoBlockRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/blocks/(?P<block_id>[0-9a-f]{64})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/blocks/:block_id"
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

        let block_id_str = captures
            .name("block_id")
            .ok_or_else(|| {
                Error::DecodeError("Failed to match path to block ID group".to_string())
            })?
            .as_str();

        let block_id = StacksBlockId::from_hex(block_id_str).map_err(|_| {
            Error::DecodeError("Invalid path: unparseable consensus hash".to_string())
        })?;
        self.block_id = Some(block_id);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCNakamotoBlockRequestHandler {
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
        let block_id = self
            .block_id
            .take()
            .ok_or(NetError::SendError("Missing `block_id`".into()))?;

        let stream_res =
            node.with_node_state(|_network, _sortdb, chainstate, _mempool, _rpc_args| {
                let Some(header) =
                    NakamotoChainState::get_block_header_nakamoto(chainstate.db(), &block_id)?
                else {
                    return Err(ChainError::NoSuchBlockError);
                };
                let Some(nakamoto_header) = header.anchored_header.as_stacks_nakamoto() else {
                    return Err(ChainError::NoSuchBlockError);
                };
                NakamotoBlockStream::new(
                    chainstate,
                    block_id.clone(),
                    nakamoto_header.consensus_hash.clone(),
                    nakamoto_header.parent_block_id.clone(),
                )
            });

        // start loading up the block
        let stream = match stream_res {
            Ok(stream) => stream,
            Err(ChainError::NoSuchBlockError) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new(format!("No such block {:?}\n", &block_id)),
                )
                .try_into_contents()
                .map_err(NetError::from)
            }
            Err(e) => {
                // nope -- error trying to check
                let msg = format!("Failed to load block {}: {:?}\n", &block_id, &e);
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
impl HttpResponse for RPCNakamotoBlockRequestHandler {
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

/// Stream implementation for a Nakamoto block
impl HttpChunkGenerator for NakamotoBlockStream {
    #[cfg(test)]
    fn hint_chunk_size(&self) -> usize {
        // make this hurt
        32
    }

    #[cfg(not(test))]
    fn hint_chunk_size(&self) -> usize {
        4096
    }

    fn generate_next_chunk(&mut self) -> Result<Vec<u8>, String> {
        let mut blob_fd = self
            .staging_db_conn
            .open_nakamoto_block(self.rowid, false)
            .map_err(|e| {
                let msg = format!(
                    "Failed to open Nakamoto block {}: {:?}",
                    &self.index_block_hash, &e
                );
                warn!("{}", &msg);
                msg
            })?;

        blob_fd.seek(SeekFrom::Start(self.offset)).map_err(|e| {
            let msg = format!(
                "Failed to read Nakamoto block {}: {:?}",
                &self.index_block_hash, &e
            );
            warn!("{}", &msg);
            msg
        })?;

        let mut buf = vec![0u8; self.hint_chunk_size()];
        let num_read = blob_fd.read(&mut buf).map_err(|e| {
            let msg = format!(
                "Failed to read Nakamoto block {}: {:?}",
                &self.index_block_hash, &e
            );
            warn!("{}", &msg);
            msg
        })?;

        buf.truncate(num_read);

        self.offset += num_read as u64;
        self.total_bytes += num_read as u64;

        Ok(buf)
    }
}

impl StacksHttpRequest {
    pub fn new_get_nakamoto_block(host: PeerHost, block_id: StacksBlockId) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/blocks/{}", &block_id),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    /// Decode an HTTP response into a block.
    /// If it fails, return Self::Error(..)
    pub fn decode_nakamoto_block(self) -> Result<NakamotoBlock, NetError> {
        let contents = self.get_http_payload_ok()?;

        // contents will be raw bytes
        let block_bytes: Vec<u8> = contents.try_into()?;
        let block = NakamotoBlock::consensus_deserialize(&mut &block_bytes[..])?;

        Ok(block)
    }
}
