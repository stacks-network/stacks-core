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

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::representations::{
    CLARITY_NAME_REGEX, CONTRACT_NAME_REGEX_STRING, PRINCIPAL_DATA_REGEX_STRING,
    STANDARD_PRINCIPAL_REGEX_STRING,
};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};
use clarity::vm::{ClarityName, ContractName};
use libstackerdb::{SlotMetadata, STACKERDB_MAX_CHUNK_SIZE};
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
    HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    request, HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp,
    StacksHttpRequest, StacksHttpResponse,
};
use crate::net::{Error as NetError, StacksNodeState, TipRequest, MAX_HEADERS};
use crate::util_lib::db::{DBConn, Error as DBError};

#[derive(Clone)]
pub struct RPCGetStackerDBChunkRequestHandler {
    pub contract_identifier: Option<QualifiedContractIdentifier>,
    pub slot_id: Option<u32>,
    pub slot_version: Option<u32>,
}
impl RPCGetStackerDBChunkRequestHandler {
    pub fn new() -> Self {
        Self {
            contract_identifier: None,
            slot_id: None,
            slot_version: None,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCGetStackerDBChunkRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(&format!(
            r#"^/v2/stackerdb/(?P<address>{})/(?P<contract>{})/(?P<slot_id>[0-9]+)(/(?P<slot_version>[0-9]+)){{0,1}}$"#,
            *STANDARD_PRINCIPAL_REGEX_STRING, *CONTRACT_NAME_REGEX_STRING
        )).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/stackerdb/:principal/:contract_name/:slot_id/:slot_version"
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

        let contract_identifier = request::get_contract_address(captures, "address", "contract")?;
        let slot_id = request::get_u32(captures, "slot_id")?;
        let slot_version = if captures.name("slot_version").is_some() {
            Some(request::get_u32(captures, "slot_version")?)
        } else {
            None
        };

        self.contract_identifier = Some(contract_identifier);
        self.slot_id = Some(slot_id);
        self.slot_version = slot_version;

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCGetStackerDBChunkRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.contract_identifier = None;
        self.slot_id = None;
        self.slot_version = None;
    }

    /// Make the response.
    /// NOTE: it's not safe to stream chunks; they have to be sent all at once.
    /// This is because any streaming algorithm that does not lock the chunk row is at risk of
    /// racing a chunk-download or a chunk-push, which would atomically overwrite the data being
    /// streamed (and lead to corrupt data being sent).  As a result, StackerDB chunks are capped
    /// at 1MB, and StackerDB replication is always an opt-in protocol.  Node operators subscribe
    /// to StackerDB replicas at their own risk.
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let contract_identifier = self
            .contract_identifier
            .take()
            .ok_or(NetError::SendError("`contract_identifier` not set".into()))?;
        let slot_id = self
            .slot_id
            .take()
            .ok_or(NetError::SendError("`slot_id` not set".into()))?;
        let slot_version = self.slot_version.take();

        let chunk_resp =
            node.with_node_state(|network, _sortdb, _chainstate, _mempool, _rpc_args| {
                let chunk_res = if let Some(version) = slot_version.as_ref() {
                    network
                        .get_stackerdbs()
                        .get_chunk(&contract_identifier, slot_id, *version)
                        .map(|chunk_data| chunk_data.map(|chunk_data| chunk_data.data))
                } else {
                    network
                        .get_stackerdbs()
                        .get_latest_chunk(&contract_identifier, slot_id)
                };

                match chunk_res {
                    Ok(Some(chunk)) => {
                        debug!(
                            "Loaded {}-byte chunk for {} slot {} version {:?}",
                            chunk.len(),
                            &contract_identifier,
                            slot_id,
                            &slot_version
                        );
                        Ok(chunk)
                    }
                    Ok(None) | Err(NetError::NoSuchStackerDB(..)) => {
                        // not found
                        Err(StacksHttpResponse::new_error(
                            &preamble,
                            &HttpNotFound::new("StackerDB contract or chunk not found".to_string()),
                        ))
                    }
                    Err(e) => {
                        // some other error
                        error!("Failed to load StackerDB chunk";
                               "smart_contract_id" => contract_identifier.to_string(),
                               "slot_id" => slot_id,
                               "slot_version" => slot_version,
                               "error" => format!("{:?}", &e)
                        );
                        Err(StacksHttpResponse::new_error(
                            &preamble,
                            &HttpServerError::new("Failed to load StackerDB chunk".to_string()),
                        ))
                    }
                }
            });

        let chunk_resp = match chunk_resp {
            Ok(chunk) => chunk,
            Err(response) => {
                return response.try_into_contents().map_err(NetError::from);
            }
        };

        let mut preamble = HttpResponsePreamble::from_http_request_preamble(
            &preamble,
            200,
            "OK",
            None,
            HttpContentType::Bytes,
        );

        preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
        let body = HttpResponseContents::from_ram(chunk_resp);
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCGetStackerDBChunkRequestHandler {
    /// Decode this response from a byte stream.  This is called by the client to decode this
    /// message
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let data: Vec<u8> = parse_bytes(preamble, body, STACKERDB_MAX_CHUNK_SIZE.into())?;
        Ok(HttpResponsePayload::Bytes(data))
    }
}

impl StacksHttpRequest {
    /// Make a request for a stackerDB's chunk
    pub fn new_get_stackerdb_chunk(
        host: PeerHost,
        stackerdb_contract_id: QualifiedContractIdentifier,
        slot_id: u32,
        slot_version: Option<u32>,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            if let Some(version) = slot_version {
                format!(
                    "/v2/stackerdb/{}/{}/{}/{}",
                    &stackerdb_contract_id.issuer, &stackerdb_contract_id.name, slot_id, version
                )
            } else {
                format!(
                    "/v2/stackerdb/{}/{}/{}",
                    &stackerdb_contract_id.issuer, &stackerdb_contract_id.name, slot_id
                )
            },
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    /// Decode an HTTP response into a chunk
    /// If it fails, return Self::Error(..)
    pub fn decode_stackerdb_chunk(self) -> Result<Vec<u8>, NetError> {
        let contents = self.get_http_payload_ok()?;
        let chunk_bytes: Vec<u8> = contents.try_into()?;
        Ok(chunk_bytes)
    }
}
