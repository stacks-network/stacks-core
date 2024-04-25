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
use clarity::vm::database::{ClarityDatabase, STXBalance};
use clarity::vm::representations::PRINCIPAL_DATA_REGEX_STRING;
use clarity::vm::types::{PrincipalData, StandardPrincipalData};
use clarity::vm::ClarityVersion;
use regex::{Captures, Regex};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::{to_hex, Sha256Sum};

use crate::burnchains::Burnchain;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::stacks::boot::{POX_1_NAME, POX_2_NAME, POX_3_NAME};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::Error as ChainError;
use crate::core::mempool::MemPoolDB;
use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp,
    StacksHttpRequest, StacksHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, StacksNodeState, TipRequest};
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::Error as DBError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountEntryResponse {
    pub balance: String,
    pub locked: String,
    pub unlock_height: u64,
    pub nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub balance_proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub nonce_proof: Option<String>,
}

#[derive(Clone)]
pub struct RPCGetAccountRequestHandler {
    pub account: Option<PrincipalData>,
}
impl RPCGetAccountRequestHandler {
    pub fn new() -> Self {
        Self { account: None }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCGetAccountRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(&format!(
            "^/v2/accounts/(?P<principal>{})$",
            *PRINCIPAL_DATA_REGEX_STRING
        ))
        .unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/accounts/:principal"
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

        let account = if let Some(value) = captures.name("principal") {
            PrincipalData::parse(value.into())
                .map_err(|_e| Error::DecodeError("Failed to parse `principal` field".to_string()))?
        } else {
            return Err(Error::DecodeError(
                "Missing in request path: `principal`".into(),
            ));
        };

        self.account = Some(account);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

/// Handle the HTTP request
impl RPCRequestHandler for RPCGetAccountRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.account = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let tip = match node.load_stacks_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };
        let account = self
            .account
            .take()
            .ok_or(NetError::SendError("Missing `account`".into()))?;
        let with_proof = contents.get_with_proof();

        let account_opt_res =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), &tip, |clarity_tx| {
                    clarity_tx.with_clarity_db_readonly(|clarity_db| {
                        let key = ClarityDatabase::make_key_for_account_balance(&account);
                        let burn_block_height =
                            clarity_db.get_current_burnchain_block_height().ok()? as u64;
                        let v1_unlock_height = clarity_db.get_v1_unlock_height();
                        let v2_unlock_height = clarity_db.get_v2_unlock_height().ok()?;
                        let v3_unlock_height = clarity_db.get_v3_unlock_height().ok()?;
                        let (balance, balance_proof) = if with_proof {
                            clarity_db
                                .get_data_with_proof::<STXBalance>(&key)
                                .ok()
                                .flatten()
                                .map(|(a, b)| (a, Some(format!("0x{}", to_hex(&b)))))
                                .unwrap_or_else(|| (STXBalance::zero(), Some("".into())))
                        } else {
                            clarity_db
                                .get_data::<STXBalance>(&key)
                                .ok()
                                .flatten()
                                .map(|a| (a, None))
                                .unwrap_or_else(|| (STXBalance::zero(), None))
                        };

                        let key = ClarityDatabase::make_key_for_account_nonce(&account);
                        let (nonce, nonce_proof) = if with_proof {
                            clarity_db
                                .get_data_with_proof(&key)
                                .ok()
                                .flatten()
                                .map(|(a, b)| (a, Some(format!("0x{}", to_hex(&b)))))
                                .unwrap_or_else(|| (0, Some("".into())))
                        } else {
                            clarity_db
                                .get_data(&key)
                                .ok()
                                .flatten()
                                .map(|a| (a, None))
                                .unwrap_or_else(|| (0, None))
                        };

                        let unlocked = balance
                            .get_available_balance_at_burn_block(
                                burn_block_height,
                                v1_unlock_height,
                                v2_unlock_height,
                                v3_unlock_height,
                            )
                            .ok()?;

                        let (locked, unlock_height) = balance.get_locked_balance_at_burn_block(
                            burn_block_height,
                            v1_unlock_height,
                            v2_unlock_height,
                            v3_unlock_height,
                        );

                        let balance = format!("0x{}", to_hex(&unlocked.to_be_bytes()));
                        let locked = format!("0x{}", to_hex(&locked.to_be_bytes()));

                        Some(AccountEntryResponse {
                            balance,
                            locked,
                            unlock_height,
                            nonce,
                            balance_proof,
                            nonce_proof,
                        })
                    })
                })
            });

        let account = if let Ok(Some(account)) = account_opt_res {
            account
        } else {
            return StacksHttpResponse::new_error(
                &preamble,
                &HttpNotFound::new(format!("Chain tip '{}' not found", &tip)),
            )
            .try_into_contents()
            .map_err(NetError::from);
        };

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
        let body = HttpResponseContents::try_from_json(&account)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCGetAccountRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let account: AccountEntryResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(account)?)
    }
}

impl StacksHttpRequest {
    /// Make a new request for an account
    pub fn new_getaccount(
        host: PeerHost,
        principal: PrincipalData,
        tip_req: TipRequest,
        with_proof: bool,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v2/accounts/{}", &principal),
            HttpRequestContents::new()
                .for_tip(tip_req)
                .query_arg("proof".into(), if with_proof { "1" } else { "0" }.into()),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_account_entry_response(self) -> Result<AccountEntryResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let contents_json: serde_json::Value = contents.try_into()?;
        let resp: AccountEntryResponse = serde_json::from_value(contents_json)
            .map_err(|_e| NetError::DeserializeError("Failed to load from JSON".to_string()))?;
        Ok(resp)
    }
}
