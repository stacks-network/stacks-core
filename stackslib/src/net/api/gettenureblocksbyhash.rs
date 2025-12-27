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

use crate::net::http::request::{PathCaptures, PathMatcher};
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::net::PeerHost;

use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::Error as ChainstateError;
use crate::net::api::gettenureblocks::{RPCTenure, RPCTenureStream};
use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{request, RPCRequestHandler, StacksHttpRequest, StacksHttpResponse};
use crate::net::{Error as NetError, StacksNodeState};

#[derive(Clone)]
pub struct RPCNakamotoTenureBlocksByHashRequestHandler {
    pub(crate) burnchain_block_hash: Option<BurnchainHeaderHash>,
}

impl RPCNakamotoTenureBlocksByHashRequestHandler {
    pub fn new() -> Self {
        Self {
            burnchain_block_hash: None,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCNakamotoTenureBlocksByHashRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_matcher(&self) -> PathMatcher {
        PathMatcher::new("/v3/tenures/blocks/hash/{burnchain_block_hash}")
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/tenures/blocks/hash/:burnchain_block_hash"
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        captures: &PathCaptures,
        query: Option<&str>,
        _body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() != 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected 0-length body".to_string(),
            ));
        }
        let burnchain_block_hash =
            request::get_burnchain_header_hash(captures, "burnchain_block_hash")?;
        self.burnchain_block_hash = Some(burnchain_block_hash);
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCNakamotoTenureBlocksByHashRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.burnchain_block_hash = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let burnchain_block_hash = self
            .burnchain_block_hash
            .take()
            .ok_or(NetError::SendError("`burnchain_block_hash` not set".into()))?;

        let stream_res =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                let header_info =
                    match NakamotoChainState::find_highest_known_block_header_in_tenure_by_block_hash(
                        &chainstate,
                        sortdb,
                        &burnchain_block_hash,
                    ) {
                        Ok(Some(header)) => header,
                        Ok(None) | Err(ChainstateError::NoSuchBlockError) => {
                            let msg = format!("No blocks in tenure with burnchain block hash {burnchain_block_hash}");
                            debug!("{msg}");
                            return Err(StacksHttpResponse::new_error(
                                &preamble,
                                &HttpNotFound::new(msg),
                            ));
                        }
                        Err(e) => {
                            let msg = format!(
                        "Failed to query tenure blocks by burnchain block hash '{burnchain_block_hash}': {e:?}"
                    );
                            error!("{msg}");
                            return Err(StacksHttpResponse::new_error(
                                &preamble,
                                &HttpServerError::new(msg),
                            ));
                        }
                    };

                let tenure = RPCTenure {
                    consensus_hash: header_info.consensus_hash.clone(),
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
impl HttpResponse for RPCNakamotoTenureBlocksByHashRequestHandler {
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
    /// Make a new request to this endpoint
    pub fn new_get_tenure_blocks_by_hash(
        host: PeerHost,
        burnchain_block_hash: &BurnchainHeaderHash,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/tenures/blocks/hash/{burnchain_block_hash}"),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}
