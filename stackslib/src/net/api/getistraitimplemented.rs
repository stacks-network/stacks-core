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

use clarity::vm::ast::parser::v1::CLARITY_NAME_REGEX;
use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::database::{ClarityDatabase, STXBalance, StoreType};
use clarity::vm::representations::{
    CONTRACT_NAME_REGEX_STRING, PRINCIPAL_DATA_REGEX_STRING, STANDARD_PRINCIPAL_REGEX_STRING,
};
use clarity::vm::types::{
    PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, TraitIdentifier,
};
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
pub struct GetIsTraitImplementedResponse {
    pub is_implemented: bool,
}

#[derive(Clone)]
pub struct RPCGetIsTraitImplementedRequestHandler {
    pub contract_identifier: Option<QualifiedContractIdentifier>,
    pub trait_contract_identifier: Option<QualifiedContractIdentifier>,
    pub trait_name: Option<ClarityName>,
}
impl RPCGetIsTraitImplementedRequestHandler {
    pub fn new() -> Self {
        Self {
            contract_identifier: None,
            trait_contract_identifier: None,
            trait_name: None,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCGetIsTraitImplementedRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(&format!(
            "^/v2/traits/(?P<address>{})/(?P<contract>{})/(?P<traitContractAddr>{})/(?P<traitContractName>{})/(?P<traitName>{})$",
            *STANDARD_PRINCIPAL_REGEX_STRING, *CONTRACT_NAME_REGEX_STRING, *STANDARD_PRINCIPAL_REGEX_STRING, *CONTRACT_NAME_REGEX_STRING, *CLARITY_NAME_REGEX
        ))
        .unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/traits/:principal/:contract_name"
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
        let trait_contract_identifier =
            request::get_contract_address(captures, "traitContractAddr", "traitContractName")?;
        let trait_name = request::get_clarity_name(captures, "traitName")?;

        self.contract_identifier = Some(contract_identifier);
        self.trait_contract_identifier = Some(trait_contract_identifier);
        self.trait_name = Some(trait_name);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

/// Handle the HTTP request
impl RPCRequestHandler for RPCGetIsTraitImplementedRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.contract_identifier = None;
        self.trait_contract_identifier = None;
        self.trait_name = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let contract_identifier = self
            .contract_identifier
            .take()
            .ok_or(NetError::SendError("`contract_identifier` not set".into()))?;
        let trait_contract_id =
            self.trait_contract_identifier
                .take()
                .ok_or(NetError::SendError(
                    "`trait_contract_identifier` not set".into(),
                ))?;
        let trait_name = self
            .trait_name
            .take()
            .ok_or(NetError::SendError("`trait_name` not set".into()))?;

        let tip = match node.load_stacks_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };
        let trait_id =
            TraitIdentifier::new(trait_contract_id.issuer, trait_contract_id.name, trait_name);

        let data_resp =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), &tip, |clarity_tx| {
                    clarity_tx.with_clarity_db_readonly(|db| {
                        let analysis = db
                            .load_contract_analysis(&contract_identifier)
                            .ok()
                            .flatten()?;
                        if analysis.implemented_traits.contains(&trait_id) {
                            Some(GetIsTraitImplementedResponse {
                                is_implemented: true,
                            })
                        } else {
                            let trait_defining_contract = db
                                .load_contract_analysis(&trait_id.contract_identifier)
                                .ok()
                                .flatten()?;
                            let trait_definition =
                                trait_defining_contract.get_defined_trait(&trait_id.name)?;
                            let is_implemented = analysis
                                .check_trait_compliance(
                                    &db.get_clarity_epoch_version().ok()?,
                                    &trait_id,
                                    trait_definition,
                                )
                                .is_ok();
                            Some(GetIsTraitImplementedResponse { is_implemented })
                        }
                    })
                })
            });

        let data_resp = match data_resp {
            Ok(Some(Some(data))) => data,
            Ok(Some(None)) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new(
                        "No contract analysis found or trait definition not found".to_string(),
                    ),
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
impl HttpResponse for RPCGetIsTraitImplementedRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let is_implemented: GetIsTraitImplementedResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(is_implemented)?)
    }
}

impl StacksHttpResponse {
    pub fn decode_is_trait_implemented_response(
        self,
    ) -> Result<GetIsTraitImplementedResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let contents_json: serde_json::Value = contents.try_into()?;
        let resp: GetIsTraitImplementedResponse = serde_json::from_value(contents_json)
            .map_err(|_e| NetError::DeserializeError("Failed to load from JSON".to_string()))?;
        Ok(resp)
    }
}

impl StacksHttpRequest {
    /// Make a new is-trait-implemented request
    pub fn new_get_is_trait_implemented(
        host: PeerHost,
        contract_addr: StacksAddress,
        contract_name: ContractName,
        trait_contract_addr: StacksAddress,
        trait_contract_name: ContractName,
        trait_name: ClarityName,
        tip_req: TipRequest,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!(
                "/v2/traits/{}/{}/{}/{}/{}",
                &contract_addr,
                &contract_name,
                &trait_contract_addr,
                &trait_contract_name,
                &trait_name
            ),
            HttpRequestContents::new().for_tip(tip_req),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}
