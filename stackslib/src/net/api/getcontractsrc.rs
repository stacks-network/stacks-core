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

use std::io::{Read, Write};

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::database::clarity_store::{make_contract_hash_key, ContractCommitment};
use clarity::vm::database::{ClarityDatabase, STXBalance, StoreType};
use clarity::vm::representations::{
    CONTRACT_NAME_REGEX_STRING, PRINCIPAL_DATA_REGEX_STRING, STANDARD_PRINCIPAL_REGEX_STRING,
};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};
use clarity::vm::{ClarityName, ClarityVersion, ContractName};
use regex::{Captures, Regex};
use stacks_common::types::chainstate::{StacksAddress, StacksBlockId};
use stacks_common::types::net::PeerHost;
use stacks_common::types::Address;
use stacks_common::util::hash::{to_hex, Sha256Sum};

use crate::burnchains::Burnchain;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::Error as ChainError;
use crate::core::mempool::MemPoolDB;
use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    request, HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp,
    StacksHttpRequest, StacksHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, StacksNodeState, TipRequest};
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::Error as DBError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractSrcResponse {
    pub source: String,
    pub publish_height: u32,
    #[serde(rename = "proof")]
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marf_proof: Option<String>,
}

#[derive(Clone)]
pub struct RPCGetContractSrcRequestHandler {
    pub contract_identifier: Option<QualifiedContractIdentifier>,
}

impl RPCGetContractSrcRequestHandler {
    pub fn new() -> Self {
        Self {
            contract_identifier: None,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCGetContractSrcRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(&format!(
            "^/v2/contracts/source/(?P<address>{})/(?P<contract>{})$",
            *STANDARD_PRINCIPAL_REGEX_STRING, *CONTRACT_NAME_REGEX_STRING
        ))
        .unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/contracts/source/:principal/:contract_name"
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

        let contents = HttpRequestContents::new().query_string(query);
        Ok(contents)
    }
}

/// Handle the HTTP request
impl RPCRequestHandler for RPCGetContractSrcRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.contract_identifier = None;
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
        let tip = match node.load_stacks_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };
        let with_proof = contents.get_with_proof();

        let data_resp =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                chainstate.maybe_read_only_clarity_tx(
                    &sortdb.index_handle_at_block(chainstate, &tip)?,
                    &tip,
                    |clarity_tx| {
                        clarity_tx.with_clarity_db_readonly(|db| {
                            let source = db.get_contract_src(&contract_identifier)?;
                            let contract_commit_key = make_contract_hash_key(&contract_identifier);
                            let (contract_commit, proof) = if with_proof {
                                db.get_data_with_proof::<ContractCommitment>(&contract_commit_key)
                                    .ok()
                                    .flatten()
                                    .map(|(a, b)| (a, Some(format!("0x{}", to_hex(&b)))))?
                            } else {
                                db.get_data::<ContractCommitment>(&contract_commit_key)
                                    .ok()
                                    .flatten()
                                    .map(|a| (a, None))?
                            };

                            let publish_height = contract_commit.block_height;
                            Some(ContractSrcResponse {
                                source,
                                publish_height,
                                marf_proof: proof,
                            })
                        })
                    },
                )
            });

        let data_resp = match data_resp {
            Ok(Some(Some(data))) => data,
            Ok(Some(None)) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new("No contract source data found".to_string()),
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

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
        let body = HttpResponseContents::try_from_json(&data_resp)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCGetContractSrcRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let contract_src: ContractSrcResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(contract_src)?)
    }
}

impl StacksHttpRequest {
    /// Make a new request for a contract's source code
    pub fn new_getcontractsrc(
        host: PeerHost,
        contract_addr: StacksAddress,
        contract_name: ContractName,
        tip_req: TipRequest,
        with_proof: bool,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v2/contracts/source/{}/{}", &contract_addr, &contract_name),
            HttpRequestContents::new()
                .for_tip(tip_req)
                .query_arg("proof".into(), if with_proof { "1" } else { "0" }.into()),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_contract_src_response(self) -> Result<ContractSrcResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let contents_json: serde_json::Value = contents.try_into()?;
        let resp: ContractSrcResponse = serde_json::from_value(contents_json)
            .map_err(|_e| NetError::DeserializeError("Failed to load from JSON".to_string()))?;
        Ok(resp)
    }
}
