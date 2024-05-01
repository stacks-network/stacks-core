// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::{fs, io};

use regex::{Captures, Regex};
use serde::de::Error as de_Error;
use stacks_common::codec::{StacksMessageCodec, MAX_MESSAGE_LEN};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::to_hex;
use {serde, serde_json};

use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::{Error as ChainError, StacksBlock};
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
pub struct RPCBlocksRequestHandler {
    pub block_id: Option<StacksBlockId>,
}

impl RPCBlocksRequestHandler {
    pub fn new() -> Self {
        Self { block_id: None }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct StacksBlockStream {
    /// index block hash of the block to download
    pub index_block_hash: StacksBlockId,
    /// offset into whatever is being read (the blob, or the file in the chunk store)
    pub offset: u64,
    /// total number of bytes read.
    pub total_bytes: u64,

    /// connection to the underlying chainstate
    blocks_path: String,
}

impl StacksBlockStream {
    pub fn new(chainstate: &StacksChainState, block: &StacksBlockId) -> Result<Self, ChainError> {
        let _ = StacksChainState::load_staging_block_info(chainstate.db(), block)?
            .ok_or(ChainError::NoSuchBlockError)?;

        let blocks_path = chainstate.blocks_path.clone();

        Ok(StacksBlockStream {
            index_block_hash: block.clone(),
            offset: 0,
            total_bytes: 0,
            blocks_path,
        })
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCBlocksRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v2/blocks/(?P<block_id>[0-9a-f]{64})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/blocks/:block_id"
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
            .ok_or(Error::DecodeError(
                "Failed to match path to block ID group".to_string(),
            ))?
            .as_str();

        let block_id = StacksBlockId::from_hex(block_id_str)
            .map_err(|_| Error::DecodeError("Invalid path: unparseable block ID".to_string()))?;
        self.block_id = Some(block_id);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCBlocksRequestHandler {
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
                StacksBlockStream::new(chainstate, &block_id)
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
                let msg = format!("Failed to load block: {:?}\n", &e);
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
impl HttpResponse for RPCBlocksRequestHandler {
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

/// Stream implementation for HeaderStreamData
impl HttpChunkGenerator for StacksBlockStream {
    #[cfg(test)]
    fn hint_chunk_size(&self) -> usize {
        // make this hurt
        32
    }

    #[cfg(not(test))]
    fn hint_chunk_size(&self) -> usize {
        4096
    }

    #[cfg_attr(test, mutants::skip)]
    fn generate_next_chunk(&mut self) -> Result<Vec<u8>, String> {
        let block_path =
            StacksChainState::get_index_block_path(&self.blocks_path, &self.index_block_hash)
                .map_err(|e| {
                    let msg = format!(
                        "Failed to load block path for {}: {:?}",
                        &self.index_block_hash, &e
                    );
                    warn!("{}", &msg);
                    msg
                })?;

        // The reason we open a file on each call to stream data is because we don't want to
        // exhaust the supply of file descriptors.  Maybe a future version of this code will do
        // something like cache the set of open files so we don't have to keep re-opening them.
        let mut file_fd = fs::OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .truncate(false)
            .open(&block_path)
            .map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    let msg = format!("Blook file not found for {}", &self.index_block_hash);
                    warn!("{}", &msg);
                    msg
                } else {
                    let msg = format!("Failed to open block {}: {:?}", &self.index_block_hash, &e);
                    warn!("{}", &msg);
                    msg
                }
            })?;

        file_fd.seek(SeekFrom::Start(self.offset)).map_err(|e| {
            let msg = format!("Failed to read block {}: {:?}", &self.index_block_hash, &e);
            warn!("{}", &msg);
            msg
        })?;

        let mut buf = vec![0u8; self.hint_chunk_size()];
        let num_read = file_fd.read(&mut buf).map_err(|e| {
            let msg = format!("Failed to read block {}: {:?}", &self.index_block_hash, &e);
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
    pub fn new_getblock(host: PeerHost, index_block_hash: StacksBlockId) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v2/blocks/{}", &index_block_hash),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    #[cfg(test)]
    pub fn new_getblock(block: StacksBlock, with_content_length: bool) -> StacksHttpResponse {
        let value = block.serialize_to_vec();
        let length = value.len();
        let preamble = HttpResponsePreamble::new(
            HttpVersion::Http11,
            200,
            "OK".to_string(),
            if with_content_length {
                Some(length as u32)
            } else {
                None
            },
            HttpContentType::Bytes,
            true,
        );
        let body = HttpResponsePayload::Bytes(value);
        StacksHttpResponse::new(preamble, body)
    }

    /// Decode an HTTP response into a block.
    /// If it fails, return Self::Error(..)
    pub fn decode_block(self) -> Result<StacksBlock, NetError> {
        let contents = self.get_http_payload_ok()?;

        // contents will be raw bytes
        let block_bytes: Vec<u8> = contents.try_into()?;
        let block = StacksBlock::consensus_deserialize(&mut &block_bytes[..])?;

        Ok(block)
    }
}
