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

use regex::{Captures, Regex};
use stacks_common::types::net::PeerHost;

use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::Error as ChainstateError;
use crate::net::api::gettenureblocks::{
    create_rpc_tenure, create_tenure_stream_response, get_last_sortition_consensus_hash, RPCTenure,
};
use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{request, RPCRequestHandler, StacksHttpRequest, StacksHttpResponse};
use crate::net::{Error as NetError, StacksNodeState};

#[derive(Clone)]
pub struct RPCNakamotoTenureBlocksByHeightRequestHandler {
    pub(crate) burnchain_block_height: Option<u64>,
}

impl RPCNakamotoTenureBlocksByHeightRequestHandler {
    pub fn new() -> Self {
        Self {
            burnchain_block_height: None,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCNakamotoTenureBlocksByHeightRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/tenures/blocks/height/(?P<burnchain_block_height>\d+)$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/tenures/blocks/height/:burnchain_block_height"
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
        let burnchain_block_height = request::get_u64(captures, "burnchain_block_height")?;
        self.burnchain_block_height = Some(burnchain_block_height);
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCNakamotoTenureBlocksByHeightRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.burnchain_block_height = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let burnchain_block_height =
            self.burnchain_block_height
                .take()
                .ok_or(NetError::SendError(
                    "`burnchain_block_height` not set".into(),
                ))?;

        let stream_res =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                let header_info =
                    match NakamotoChainState::find_highest_known_block_header_in_tenure_by_block_height(
                        &chainstate,
                        sortdb,
                        burnchain_block_height,
                    ) {
                        Ok(Some(header)) => header,
                        Ok(None) | Err(ChainstateError::NoSuchBlockError) => {
                            let msg = format!("No blocks in tenure with burnchain block height {burnchain_block_height}");
                            debug!("{msg}");
                            return Err(StacksHttpResponse::new_error(
                                &preamble,
                                &HttpNotFound::new(msg),
                            ));
                        }
                        Err(e) => {
                            let msg = format!(
                        "Failed to query tenure blocks by burnchain block height {burnchain_block_height}: {e:?}"
                    );
                            error!("{msg}");
                            return Err(StacksHttpResponse::new_error(
                                &preamble,
                                &HttpServerError::new(msg),
                            ));
                        }
                    };
                let last_sortition_ch = get_last_sortition_consensus_hash(
                    &sortdb,
                    &header_info,
                    &preamble,
                )?;

                let tenure = create_rpc_tenure(&header_info, last_sortition_ch);

                create_tenure_stream_response(chainstate, header_info, tenure, &preamble)
            });

        let stream = match stream_res {
            Ok(stream) => stream,
            Err(e) => {
                error!("Failed to create tenure stream: {e:?}");
                return e.into();
            }
        };

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::from_stream(Box::new(stream));
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCNakamotoTenureBlocksByHeightRequestHandler {
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
    pub fn new_get_tenure_blocks_by_height(
        host: PeerHost,
        burnchain_block_height: u64,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/tenures/blocks/height/{burnchain_block_height}"),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}
