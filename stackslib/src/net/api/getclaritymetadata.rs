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

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::database::clarity_db::ContractDataVarName;
use clarity::vm::database::StoreType;
use crate::net::http::request::{PathCaptures, PathMatcher};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::net::PeerHost;

use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble,
};
use crate::net::httpcore::{
    request, HttpRequestContentsExtensions as _, RPCRequestHandler, StacksHttpRequest,
    StacksHttpResponse,
};
use crate::net::{Error as NetError, StacksNodeState, TipRequest};


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClarityMetadataResponse {
    pub data: String,
}

#[derive(Clone)]
pub struct RPCGetClarityMetadataRequestHandler {
    pub clarity_metadata_key: Option<String>,
    pub contract_identifier: Option<QualifiedContractIdentifier>,
}
impl RPCGetClarityMetadataRequestHandler {
    pub fn new() -> Self {
        Self {
            clarity_metadata_key: None,
            contract_identifier: None,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCGetClarityMetadataRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_matcher(&self) -> PathMatcher {
        PathMatcher::new("/v2/clarity/metadata/{address}/{contract}/{clarity_metadata_key}")
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/clarity/metadata/:principal/:contract_name/:clarity_metadata_key"
    }

    fn try_parse_request(
        &mut self,
        _preamble: &HttpRequestPreamble,
        captures: &PathCaptures,
        query: Option<&str>,
        _body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        let contract_identifier = request::get_contract_address(captures, "address", "contract")?;

        let metadata_key = match captures.name("clarity_metadata_key") {
            Some(key_str) => key_str.to_string(),
            None => {
                return Err(Error::DecodeError(
                    "Missing `clarity_metadata_key`".to_string(),
                ));
            }
        };

        if metadata_key != "analysis" {
            // Validate that the metadata key is well-formed. It must be of data type:
            //   DataMapMeta (5) | VariableMeta (6) | FungibleTokenMeta (7) | NonFungibleTokenMeta (8)
            //   or Contract (9) followed by a valid contract metadata name
            if !metadata_key.starts_with("vm-metadata::") {
                return Err(Error::DecodeError("Invalid metadata key prefix".to_string()));
            }
            let parts: Vec<&str> = metadata_key.split("::").collect();
            if parts.len() != 3 {
                return Err(Error::DecodeError("Invalid metadata key format".to_string()));
            }
            let data_type_str = parts[1];
            let var_name = parts[2];

            let data_type = StoreType::try_from(data_type_str).map_err(|_| {
                Error::DecodeError("Invalid metadata type".to_string())
            })?;

            match data_type {
                StoreType::DataMapMeta
                | StoreType::VariableMeta
                | StoreType::FungibleTokenMeta
                | StoreType::NonFungibleTokenMeta => {}
                StoreType::Contract => {
                    if ContractDataVarName::try_from(var_name).is_err() {
                        return Err(Error::DecodeError(
                            "Invalid metadata var name".to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(Error::DecodeError("Invalid metadata type".to_string()));
                }
            }
        }

        self.contract_identifier = Some(contract_identifier);
        self.clarity_metadata_key = Some(metadata_key);

        let contents = HttpRequestContents::new().query_string(query);
        Ok(contents)
    }
}

/// Handle the HTTP request
impl RPCRequestHandler for RPCGetClarityMetadataRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.contract_identifier = None;
        self.clarity_metadata_key = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let contract_identifier = self.contract_identifier.take().ok_or(NetError::SendError(
            "`contract_identifier` not set".to_string(),
        ))?;
        let clarity_metadata_key = self.clarity_metadata_key.take().ok_or(NetError::SendError(
            "`clarity_metadata_key` not set".to_string(),
        ))?;

        let tip = match node.load_stacks_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };

        let data_opt = node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
            chainstate.maybe_read_only_clarity_tx(
                &sortdb.index_handle_at_block(chainstate, &tip)?,
                &tip,
                |clarity_tx| {
                    clarity_tx.with_clarity_db_readonly(|clarity_db| {
                        let data = clarity_db
                            .store
                            .get_metadata(&contract_identifier, &clarity_metadata_key)
                            .ok()
                            .flatten()?;

                        Some(ClarityMetadataResponse { data })
                    })
                },
            )
        });

        let data_resp = match data_opt {
            Ok(Some(Some(data))) => data,
            Ok(Some(None)) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new("Metadata not found".to_string()),
                )
                .try_into_contents()
                .map_err(NetError::from);
            }
            Ok(None) | Err(_) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new("Chain tip not found".to_string()),
                )
                .try_into_contents()
                .map_err(NetError::from);
            }
        };

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&data_resp)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCGetClarityMetadataRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let metadata: ClarityMetadataResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(metadata)?)
    }
}

impl StacksHttpRequest {
    pub fn new_getclaritymetadata(
        host: PeerHost,
        contract_addr: StacksAddress,
        contract_name: ContractName,
        clarity_metadata_key: String,
        tip_req: TipRequest,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!(
                "/v2/clarity/metadata/{}/{}/{}",
                &contract_addr, &contract_name, &clarity_metadata_key
            ),
            HttpRequestContents::new().for_tip(tip_req),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_clarity_metadata_response(self) -> Result<ClarityMetadataResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let contents_json: serde_json::Value = contents.try_into()?;
        let resp: ClarityMetadataResponse = serde_json::from_value(contents_json)
            .map_err(|_e| NetError::DeserializeError("Failed to load from JSON".to_string()))?;
        Ok(resp)
    }
}
