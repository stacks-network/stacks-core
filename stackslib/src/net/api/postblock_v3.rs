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
use stacks_common::codec::{Error as CodecError, StacksMessageCodec, MAX_PAYLOAD_LEN};
use stacks_common::types::net::PeerHost;

use super::postblock::StacksBlockAcceptedData;
use crate::chainstate::nakamoto::staging_blocks::NakamotoBlockObtainMethod;
use crate::chainstate::nakamoto::NakamotoBlock;
use crate::net::http::{
    parse_json, Error, HttpContentType, HttpError, HttpRequest, HttpRequestContents,
    HttpRequestPreamble, HttpResponse, HttpResponseContents, HttpResponsePayload,
    HttpResponsePreamble,
};
use crate::net::httpcore::{
    HttpPreambleExtensions, RPCRequestHandler, StacksHttpRequest, StacksHttpResponse,
};
use crate::net::relay::Relayer;
use crate::net::{Error as NetError, NakamotoBlocksData, StacksMessageType, StacksNodeState};

pub static PATH: &'static str = "/v3/blocks/upload/";

#[derive(Clone, Default)]
pub struct RPCPostBlockRequestHandler {
    pub block: Option<NakamotoBlock>,
}

impl RPCPostBlockRequestHandler {
    /// Decode a bare block from the body
    fn parse_postblock_octets(mut body: &[u8]) -> Result<NakamotoBlock, Error> {
        let block = NakamotoBlock::consensus_deserialize(&mut body).map_err(|e| {
            if let CodecError::DeserializeError(msg) = e {
                Error::DecodeError(format!("Failed to deserialize posted transaction: {}", msg))
            } else {
                e.into()
            }
        })?;
        Ok(block)
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCPostBlockRequestHandler {
    fn verb(&self) -> &'static str {
        "POST"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(&format!("^{PATH}$")).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        PATH
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        _captures: &Captures,
        query: Option<&str>,
        body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() == 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected non-zero-length body for PostBlock".to_string(),
            ));
        }

        if preamble.get_content_length() > MAX_PAYLOAD_LEN {
            return Err(Error::DecodeError(
                "Invalid Http request: PostBlock body is too big".to_string(),
            ));
        }

        if Some(HttpContentType::Bytes) != preamble.content_type || preamble.content_type.is_none()
        {
            return Err(Error::DecodeError(
                "Invalid Http request: PostBlock takes application/octet-stream".to_string(),
            ));
        }

        let block = Self::parse_postblock_octets(body)?;

        self.block = Some(block);
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCPostBlockRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.block = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        // get out the request body
        let block = self
            .block
            .take()
            .ok_or(NetError::SendError("`block` not set".into()))?;

        let response = node
            .with_node_state(|network, sortdb, chainstate, _mempool, _rpc_args| {
                let mut handle_conn = sortdb.index_handle_at_tip();
                let stacks_tip = network.stacks_tip.block_id();
                Relayer::process_new_nakamoto_block(
                    &network.burnchain,
                    &sortdb,
                    &mut handle_conn,
                    chainstate,
                    &stacks_tip,
                    &block,
                    None,
                    NakamotoBlockObtainMethod::Uploaded,
                )
            })
            .map_err(|e| {
                StacksHttpResponse::new_error(&preamble, &HttpError::new(400, e.to_string()))
            });

        let data_resp = match response {
            Ok(accepted) => StacksBlockAcceptedData {
                accepted,
                stacks_block_id: block.block_id(),
            },
            Err(e) => {
                return e.try_into_contents().map_err(NetError::from);
            }
        };

        // should set to relay...
        if data_resp.accepted {
            node.set_relay_message(StacksMessageType::NakamotoBlocks(NakamotoBlocksData {
                blocks: vec![block],
            }));
        }

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
        let body = HttpResponseContents::try_from_json(&data_resp)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCPostBlockRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let accepted: StacksBlockAcceptedData = parse_json(preamble, body)?;
        HttpResponsePayload::try_from_json(accepted)
    }
}

impl StacksHttpRequest {
    /// Make a new post-block request
    pub fn new_post_block_v3(host: PeerHost, block: &NakamotoBlock) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "POST".into(),
            PATH.into(),
            HttpRequestContents::new().payload_stacks(block),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}
