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

use clarity::types::chainstate::StacksBlockId;
use regex::{Captures, Regex};
use serde_json;
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash};
use stacks_common::types::net::PeerHost;

use crate::chainstate::burn::db::DBConn;
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::{StacksBlockHeaderTypes, StacksChainState};
use crate::chainstate::stacks::Error as ChainError;
use crate::net::http::{
    parse_json, Error, HttpChunkGenerator, HttpNotFound, HttpRequest, HttpRequestContents,
    HttpRequestPreamble, HttpResponse, HttpResponseContents, HttpResponsePayload,
    HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{request, RPCRequestHandler, StacksHttpRequest, StacksHttpResponse};
use crate::net::{Error as NetError, StacksNodeState};

#[derive(Clone)]
pub struct RPCNakamotoTenureBlocksRequestHandler {
    pub(crate) consensus_hash: Option<ConsensusHash>,
}

impl RPCNakamotoTenureBlocksRequestHandler {
    pub fn new() -> Self {
        Self {
            consensus_hash: None,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct RPCTenureBlock {
    pub block_id: StacksBlockId,
    pub header_type: String,
    pub block_hash: BlockHeaderHash,
    pub parent_block_id: StacksBlockId,
    pub height: u64,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct RPCTenure {
    pub consensus_hash: ConsensusHash,
    pub burn_block_height: u64,
    pub burn_block_hash: String,
    pub stacks_blocks: Vec<RPCTenureBlock>,
}

pub struct RPCTenureStream {
    /// connection to the headers DB
    pub headers_conn: DBConn,
    /// the tenure consensus hash
    pub consensus_hash: ConsensusHash,
    /// next block to process
    pub next_block_id: StacksBlockId,
    /// the first part of the json chunk to send (it is set to None after the chunk generation)
    pub tenure_first_chunk: Option<Vec<u8>>,
    /// do we need to send the last chunk?
    pub last_chunk: bool,
    /// is this the first block we are generating?
    pub first_block: bool,
}

impl RPCTenureStream {
    /// Prepare for tenure streaming.
    /// The tenure_first_chunk is created here and streamed at the first_next_block call
    /// The HttpChunkGenerator trait implementation will take care of completing
    /// the json stream (by clossing both the array and the object)
    pub fn new(
        chainstate: &StacksChainState,
        block_id: StacksBlockId,
        tenure: RPCTenure,
    ) -> Result<Self, ChainError> {
        let headers_conn = chainstate.reopen_db()?;
        let consensus_hash = tenure.consensus_hash;
        let burn_block_height = tenure.burn_block_height;
        let burn_block_hash = tenure.burn_block_hash;
        let tenure_first_chunk = format!("{{\"consensus_hash\": \"{consensus_hash}\", \"burn_block_height\": {burn_block_height}, \"burn_block_hash\": \"{burn_block_hash}\", \"stacks_blocks\": [");
        Ok(RPCTenureStream {
            headers_conn,
            consensus_hash,
            next_block_id: block_id,
            tenure_first_chunk: Some(tenure_first_chunk.into_bytes()),
            last_chunk: false,
            first_block: true,
        })
    }

    /// Stream the json block for the next block.
    /// Stops on non-existent block or on a block in a different tenure
    pub fn next_block(&mut self) -> Result<Vec<u8>, String> {
        let block_header_opt =
            NakamotoChainState::get_block_header(&self.headers_conn, &self.next_block_id)
                .map_err(|e| format!("Chain error: {e}"))?;

        // stop if the block does not exist
        let block_header = match block_header_opt {
            Some(block_header) => block_header,
            None => {
                return Ok(vec![]);
            }
        };

        // stop sending if the block is in a different tenure
        if block_header.consensus_hash != self.consensus_hash {
            return Ok(vec![]);
        }

        let parent_block_id = match &block_header.anchored_header {
            StacksBlockHeaderTypes::Nakamoto(nakamoto) => nakamoto.parent_block_id,
            StacksBlockHeaderTypes::Epoch2(epoch2) => {
                StacksBlockId::new(&self.consensus_hash, &epoch2.parent_block)
            }
        };

        let block = RPCTenureBlock {
            block_id: block_header.index_block_hash(),
            header_type: block_header.header_type_name().into(),
            block_hash: block_header.anchored_header.block_hash(),
            parent_block_id,
            height: block_header.stacks_block_height,
        };

        self.next_block_id = parent_block_id;

        let json = serde_json::to_string(&block)
            .map_err(|e| format!("Failed to serialize block: {e:?}"))?;
        Ok(json.into_bytes())
    }
}

/// Stream implementation for a Nakamoto block
impl HttpChunkGenerator for RPCTenureStream {
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
        // last chunk?
        if self.last_chunk {
            return Ok(vec![]);
        }

        // send the first chunk
        if let Some(first_chunk) = self.tenure_first_chunk.take() {
            self.tenure_first_chunk = None;
            return Ok(first_chunk);
        }

        // load up next block
        let mut send_more = self.next_block().map_err(|e| {
            let msg = format!("Failed to load next block in this tenure: {:?}", &e);
            warn!("{msg}");
            msg
        })?;

        // end of blocks?
        if send_more.is_empty() {
            self.last_chunk = true;
            return Ok(format!("]}}").into_bytes());
        }

        if !self.first_block {
            send_more.insert(0, b',');
        }

        self.first_block = false;

        Ok(send_more)
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCNakamotoTenureBlocksRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/tenures/blocks/(?P<consensus_hash>[0-9a-f]{40})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/tenures/blocks/:consensus_hash"
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
        let consensus_hash = request::get_consensus_hash(captures, "consensus_hash")?;
        self.consensus_hash = Some(consensus_hash);
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCNakamotoTenureBlocksRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.consensus_hash = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let consensus_hash = self
            .consensus_hash
            .take()
            .ok_or(NetError::SendError("`consensus_hash` not set".into()))?;

        let stream_res =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                let header_info =
                    match NakamotoChainState::find_highest_known_block_header_in_tenure(
                        &chainstate,
                        sortdb,
                        &consensus_hash,
                    ) {
                        Ok(Some(header)) => header,
                        Ok(None) => {
                            let msg = format!("No blocks in tenure {consensus_hash}");
                            debug!("{msg}");
                            return Err(StacksHttpResponse::new_error(
                                &preamble,
                                &HttpNotFound::new(msg),
                            ));
                        }
                        Err(e) => {
                            let msg = format!(
                        "Failed to query tenure blocks by consensus '{consensus_hash}': {e:?}"
                    );
                            error!("{msg}");
                            return Err(StacksHttpResponse::new_error(
                                &preamble,
                                &HttpServerError::new(msg),
                            ));
                        }
                    };

                let tenure = RPCTenure {
                    consensus_hash: header_info.consensus_hash,
                    burn_block_height: header_info.burn_header_height.into(),
                    burn_block_hash: header_info.burn_header_hash.to_hex(),
                    stacks_blocks: vec![],
                };

                match RPCTenureStream::new(chainstate, header_info.index_block_hash(), tenure) {
                    Ok(stream) => Ok(stream),
                    Err(e) => {
                        let msg = format!("Failed to create tenure stream: {e:?}");
                        error!("{msg}");
                        return Err(StacksHttpResponse::new_error(
                            &preamble,
                            &HttpServerError::new(msg),
                        ));
                    }
                }
            });

        let stream = match stream_res {
            Ok(stream) => stream,
            Err(e) => {
                let msg = format!("Failed to create tenure stream: {e:?}");
                error!("{msg}");
                return e.into();
            }
        };

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::from_stream(Box::new(stream));
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCNakamotoTenureBlocksRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let tenure: RPCTenure = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(tenure)?)
    }
}

impl StacksHttpRequest {
    /// Make a new getinfo request to this endpoint
    pub fn new_get_tenure_blocks(
        host: PeerHost,
        consensus_hash: &ConsensusHash,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/tenures/blocks/{consensus_hash}"),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_tenure_blocks(self) -> Result<RPCTenure, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let tenure: RPCTenure = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(tenure)
    }
}
