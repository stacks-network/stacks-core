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
    CONTRACT_NAME_REGEX_STRING, PRINCIPAL_DATA_REGEX_STRING, STANDARD_PRINCIPAL_REGEX_STRING,
};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};
use clarity::vm::{ClarityName, ContractName};
use libstackerdb::SlotMetadata;
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
    parse_json, Error, HttpBadRequest, HttpChunkGenerator, HttpContentType, HttpNotFound,
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
pub struct RPCGetStackerDBMetadataRequestHandler {
    pub contract_identifier: Option<QualifiedContractIdentifier>,
}
impl RPCGetStackerDBMetadataRequestHandler {
    pub fn new() -> Self {
        Self {
            contract_identifier: None,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCGetStackerDBMetadataRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(&format!(
            r#"^/v2/stackerdb/(?P<address>{})/(?P<contract>{})$"#,
            *STANDARD_PRINCIPAL_REGEX_STRING, *CONTRACT_NAME_REGEX_STRING
        ))
        .unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/stackerdb/:principal/:contract_name"
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
        self.contract_identifier = Some(contract_identifier);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCGetStackerDBMetadataRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.contract_identifier = None;
    }

    /// Make the response
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

        let metadata_resp =
            node.with_node_state(|network, _sortdb, _chainstate, _mempool, _rpc_args| {
                network
                    .get_stackerdbs()
                    .get_db_slot_metadata(&contract_identifier)
                    .map_err(|_e| {
                        StacksHttpResponse::new_error(
                            &preamble,
                            &HttpNotFound::new("StackerDB contract not found".to_string()),
                        )
                    })
            });

        let metadata_resp = match metadata_resp {
            Ok(metadata) => metadata,
            Err(response) => {
                return response.try_into_contents().map_err(NetError::from);
            }
        };

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
        let body = HttpResponseContents::try_from_json(&metadata_resp)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCGetStackerDBMetadataRequestHandler {
    /// Decode this response from a byte stream.  This is called by the client to decode this
    /// message
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let metadata: Vec<SlotMetadata> = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(metadata)?)
    }
}

impl StacksHttpRequest {
    pub fn new_get_stackerdb_metadata(
        host: PeerHost,
        stackerdb_contract_id: QualifiedContractIdentifier,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!(
                "/v2/stackerdb/{}/{}",
                &stackerdb_contract_id.issuer, &stackerdb_contract_id.name
            ),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    /// Decode an HTTP response into a block.
    /// If it fails, return Self::Error(..)
    pub fn decode_stackerdb_metadata(self) -> Result<Vec<SlotMetadata>, NetError> {
        let contents = self.get_http_payload_ok()?;
        let contents_json: serde_json::Value = contents.try_into()?;
        let resp: Vec<SlotMetadata> = serde_json::from_value(contents_json)
            .map_err(|_e| NetError::DeserializeError("Failed to load from JSON".to_string()))?;
        Ok(resp)
    }
}
