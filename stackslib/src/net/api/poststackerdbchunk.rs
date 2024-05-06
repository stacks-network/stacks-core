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
use libstackerdb::{
    SlotMetadata, StackerDBChunkAckData, StackerDBChunkData, STACKERDB_MAX_CHUNK_SIZE,
};
use regex::{Captures, Regex};
use serde::de::Error as de_Error;
use serde_json::json;
use stacks_common::codec::{StacksMessageCodec, MAX_MESSAGE_LEN};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::to_hex;
use stacks_common::util::secp256k1::MessageSignature;
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
use crate::net::{
    Error as NetError, StackerDBPushChunkData, StacksMessageType, StacksNodeState, TipRequest,
};
use crate::util_lib::db::{DBConn, Error as DBError};

#[derive(Clone)]
pub struct RPCPostStackerDBChunkRequestHandler {
    pub contract_identifier: Option<QualifiedContractIdentifier>,
    pub chunk: Option<StackerDBChunkData>,
}
impl RPCPostStackerDBChunkRequestHandler {
    pub fn new() -> Self {
        Self {
            contract_identifier: None,
            chunk: None,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCPostStackerDBChunkRequestHandler {
    fn verb(&self) -> &'static str {
        "POST"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(&format!(
            r#"^/v2/stackerdb/(?P<address>{})/(?P<contract>{})/chunks$"#,
            *STANDARD_PRINCIPAL_REGEX_STRING, *CONTRACT_NAME_REGEX_STRING
        ))
        .unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/block_proposal/:principal/:contract_name/chunks"
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        captures: &Captures,
        query: Option<&str>,
        body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() == 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected non-empty body".to_string(),
            ));
        }

        if preamble.get_content_length() > MAX_MESSAGE_LEN {
            return Err(Error::DecodeError(
                "Invalid Http request: PostStackerDBChunk body is too big".to_string(),
            ));
        }

        let contract_identifier = request::get_contract_address(captures, "address", "contract")?;
        let chunk: StackerDBChunkData = serde_json::from_slice(body).map_err(Error::JsonError)?;

        self.contract_identifier = Some(contract_identifier);
        self.chunk = Some(chunk);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum StackerDBErrorCodes {
    DataAlreadyExists,
    NoSuchSlot,
    BadSigner,
}

impl StackerDBErrorCodes {
    pub fn code(&self) -> u32 {
        match self {
            Self::DataAlreadyExists => 0,
            Self::NoSuchSlot => 1,
            Self::BadSigner => 2,
        }
    }

    #[cfg_attr(test, mutants::skip)]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::DataAlreadyExists => "Data for this slot and version already exist",
            Self::NoSuchSlot => "No such StackerDB slot",
            Self::BadSigner => "Signature does not match slot signer",
        }
    }

    pub fn into_json(self) -> serde_json::Value {
        json!({
            "code": self.code(),
            "message": format!("{:?}", &self),
            "reason": self.reason()
        })
    }

    #[cfg_attr(test, mutants::skip)]
    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::DataAlreadyExists),
            1 => Some(Self::NoSuchSlot),
            2 => Some(Self::BadSigner),
            _ => None,
        }
    }
}

impl RPCRequestHandler for RPCPostStackerDBChunkRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.contract_identifier = None;
        self.chunk = None;
    }

    /// Make the response.
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
        let stackerdb_chunk = self
            .chunk
            .take()
            .ok_or(NetError::SendError("`chunk` not set".into()))?;

        let ack_resp =
            node.with_node_state(|network, _sortdb, _chainstate, _mempool, _rpc_args| {
                let tx = if let Ok(tx) = network.stackerdbs_tx_begin(&contract_identifier) {
                    tx
                } else {
                    return Err(StacksHttpResponse::new_error(
                        &preamble,
                        &HttpNotFound::new("StackerDB not found".to_string()),
                    ));
                };
                if let Err(_e) = tx.get_stackerdb_id(&contract_identifier) {
                    // shouldn't be necessary (this is checked against the peer network's configured DBs),
                    // but you never know.
                    return Err(StacksHttpResponse::new_error(
                        &preamble,
                        &HttpNotFound::new("StackerDB not found".to_string()),
                    ));
                }
                if let Err(e) = tx.try_replace_chunk(
                    &contract_identifier,
                    &stackerdb_chunk.get_slot_metadata(),
                    &stackerdb_chunk.data,
                ) {
                    test_debug!(
                        "Failed to replace chunk {}.{} in {}: {:?}",
                        stackerdb_chunk.slot_id,
                        stackerdb_chunk.slot_version,
                        &contract_identifier,
                        &e
                    );
                    let slot_metadata_opt =
                        match tx.get_slot_metadata(&contract_identifier, stackerdb_chunk.slot_id) {
                            Ok(slot_opt) => slot_opt,
                            Err(e) => {
                                // some other error
                                error!("Failed to load replaced StackerDB chunk metadata";
                                       "smart_contract_id" => contract_identifier.to_string(),
                                       "error" => format!("{:?}", &e)
                                );
                                return Err(StacksHttpResponse::new_error(
                                    &preamble,
                                    &HttpServerError::new(format!(
                                        "Failed to load StackerDB chunk for {}: {:?}",
                                        &contract_identifier, &e
                                    )),
                                ));
                            }
                        };

                    let err_code = if slot_metadata_opt.is_some() {
                        if let NetError::BadSlotSigner(..) = e {
                            StackerDBErrorCodes::BadSigner
                        } else {
                            StackerDBErrorCodes::DataAlreadyExists
                        }
                    } else {
                        StackerDBErrorCodes::NoSuchSlot
                    };
                    let reason = serde_json::to_string(&err_code.clone().into_json())
                        .unwrap_or("(unable to encode JSON)".to_string());

                    let ack = StackerDBChunkAckData {
                        accepted: false,
                        reason: Some(reason),
                        metadata: slot_metadata_opt,
                        code: Some(err_code.code()),
                    };
                    return Ok(ack);
                }

                let slot_metadata = if let Ok(Some(md)) =
                    tx.get_slot_metadata(&contract_identifier, stackerdb_chunk.slot_id)
                {
                    md
                } else {
                    return Err(StacksHttpResponse::new_error(
                        &preamble,
                        &HttpServerError::new(
                            "Failed to load slot metadata after storing chunk".to_string(),
                        ),
                    ));
                };

                if let Err(e) = tx.commit() {
                    return Err(StacksHttpResponse::new_error(
                        &preamble,
                        &HttpServerError::new(format!("Failed to commit StackerDB tx: {:?}", &e)),
                    ));
                }

                debug!(
                    "Wrote {}-byte chunk to {} slot {} version {}",
                    &stackerdb_chunk.data.len(),
                    &contract_identifier,
                    stackerdb_chunk.slot_id,
                    stackerdb_chunk.slot_version
                );

                // success!
                let ack = StackerDBChunkAckData {
                    accepted: true,
                    reason: None,
                    metadata: Some(slot_metadata),
                    code: None,
                };

                return Ok(ack);
            });

        let ack_resp = match ack_resp {
            Ok(ack) => ack,
            Err(response) => {
                return response.try_into_contents().map_err(NetError::from);
            }
        };

        if ack_resp.accepted {
            let push_chunk_data = StackerDBPushChunkData {
                contract_id: contract_identifier,
                rc_consensus_hash: node.with_node_state(|network, _, _, _, _| {
                    network.get_chain_view().rc_consensus_hash.clone()
                }),
                chunk_data: stackerdb_chunk,
            };
            node.set_relay_message(StacksMessageType::StackerDBPushChunk(push_chunk_data));
        }

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
        let body = HttpResponseContents::try_from_json(&ack_resp)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCPostStackerDBChunkRequestHandler {
    /// Decode this response from a byte stream.  This is called by the client to decode this
    /// message
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let ack: StackerDBChunkAckData = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(ack)?)
    }
}

impl StacksHttpRequest {
    pub fn new_post_stackerdb_chunk(
        host: PeerHost,
        stackerdb_contract_id: QualifiedContractIdentifier,
        slot_id: u32,
        slot_version: u32,
        sig: MessageSignature,
        data: Vec<u8>,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "POST".into(),
            format!(
                "/v2/stackerdb/{}/{}/chunks",
                &stackerdb_contract_id.issuer, &stackerdb_contract_id.name
            ),
            HttpRequestContents::new().payload_json(
                serde_json::to_value(StackerDBChunkData {
                    slot_id,
                    slot_version,
                    sig,
                    data,
                })
                .expect("FATAL: failed to construct JSON from infallible structure"),
            ),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    /// Decode an HTTP response into a chunk
    /// If it fails, return Self::Error(..)
    pub fn decode_stackerdb_chunk_ack(self) -> Result<StackerDBChunkAckData, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let data: StackerDBChunkAckData = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(data)
    }
}
