// Copyright (C) 2026 Stacks Open Internet Foundation
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

use std::time::Duration;

use clarity::util::hash::bytes_to_hex;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::Value;
use regex::{Captures, Regex};
use stacks_common::codec::{Error as CodecError, StacksMessageCodec, MAX_PAYLOAD_LEN};
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId};
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::hex_bytes;
use stacks_common::util::serde_serializers::prefix_hex_codec;

use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::miner::{MinerTenureInfoCause, NakamotoBlockBuilder};
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::miner::{BlockBuilder, BlockLimitFunction, TransactionResult};
use crate::chainstate::stacks::{Error as ChainError, StacksTransaction};
use crate::config::DEFAULT_MAX_TENURE_BYTES;
use crate::net::http::{
    parse_json, Error, HttpBadRequest, HttpContentType, HttpNotFound, HttpRequest,
    HttpRequestContents, HttpRequestPreamble, HttpResponse, HttpResponseContents,
    HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{RPCRequestHandler, StacksHttpResponse};
use crate::net::{Error as NetError, StacksHttpRequest, StacksNodeState};

#[derive(Clone, Serialize, Deserialize)]
pub struct RPCTransactionSimulateBody {
    pub transaction_hex: String,
}

#[derive(Clone)]
pub struct RPCTransactionSimulateRequestHandler {
    pub auth: Option<String>,
    /// Wall-clock cap applied to both the analysis and execution phases of
    /// the simulated transaction, so that a pathological transaction cannot
    /// stall the node
    pub max_execution_time: Duration,
    pub transaction: Option<StacksTransaction>,
}

impl RPCTransactionSimulateRequestHandler {
    pub fn new(auth: Option<String>, max_execution_time: Duration) -> Self {
        Self {
            auth,
            max_execution_time,
            transaction: None,
        }
    }

    fn parse_json(body: &[u8]) -> Result<StacksTransaction, Error> {
        let tx_simulate_body: RPCTransactionSimulateBody = serde_json::from_slice(body)
            .map_err(|e| Error::DecodeError(format!("Failed to parse body: {e}")))?;

        let tx_bytes = hex_bytes(&tx_simulate_body.transaction_hex)
            .map_err(|_e| Error::DecodeError("Failed to parse tx".into()))?;
        let tx = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).map_err(|e| {
            if let CodecError::DeserializeError(msg) = e {
                Error::DecodeError(format!("Failed to deserialize transaction: {}", msg))
            } else {
                e.into()
            }
        })?;

        Ok(tx)
    }

    /// Simulate the transaction in an ephemeral block built on top of the
    /// canonical chain tip, extending the tip's tenure.  The execution budget
    /// is reset to the full tenure limit, so the result is independent of how
    /// much of the current tenure's budget has already been consumed.  All
    /// state changes are discarded.
    pub fn transaction_simulate(
        &self,
        tip_block_id: &StacksBlockId,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
    ) -> Result<RPCSimulatedTransaction, ChainError> {
        let Some(tx) = &self.transaction else {
            return Err(ChainError::InvalidStacksTransaction(
                "transaction is None".into(),
                false,
            ));
        };

        let tip_header = NakamotoChainState::get_block_header(chainstate.db(), tip_block_id)?
            .ok_or(ChainError::NoSuchBlockError)?;

        let Some(tip_nakamoto_header) = tip_header.anchored_header.as_stacks_nakamoto() else {
            return Err(ChainError::InvalidStacksBlock(
                "Chain tip is not a Nakamoto block".into(),
            ));
        };
        let consensus_hash = tip_header.consensus_hash.clone();
        let total_burn = tip_nakamoto_header.burn_spent;
        let bitvec_len = tip_nakamoto_header.pox_treatment.len();

        let burn_dbconn = sortdb
            .index_handle_at_block(chainstate, tip_block_id)
            .map_err(|_| ChainError::NoSuchBlockError)?;

        // build an ephemeral block on top of the canonical tip, continuing the
        // tip's tenure
        let mut builder = NakamotoBlockBuilder::new(
            &tip_header,
            &consensus_hash,
            total_burn,
            None,
            None,
            bitvec_len,
            None,
            None,
            None,
            u64::from(DEFAULT_MAX_TENURE_BYTES),
        )?;

        let mut miner_tenure_info = builder.load_ephemeral_tenure_info(
            chainstate,
            &burn_dbconn,
            MinerTenureInfoCause::NoTenureChange,
        )?;
        let mut tenure_tx = builder.tenure_begin(&burn_dbconn, &mut miner_tenure_info)?;

        // `tenure_begin` seeds the cost tracker with the cost already consumed
        // by the current tenure; reset it so the transaction gets the full
        // tenure execution budget
        tenure_tx.reset_cost(ExecutionCost::ZERO);
        let execution_limit = tenure_tx.block_limit();

        let block_height = builder.header.chain_length;

        let mut total_receipts = 0;
        let tx_result = builder.try_mine_tx_with_len(
            &mut tenure_tx,
            tx,
            tx.tx_len(),
            &BlockLimitFunction::NO_LIMIT_HIT,
            Some(self.max_execution_time),
            Some(self.max_execution_time),
            &mut total_receipts,
        );

        let receipt = match tx_result {
            TransactionResult::Success(tx_result) => tx_result.receipt,
            TransactionResult::ProcessingError(e) => {
                tenure_tx.rollback_block();
                return Err(ChainError::InvalidStacksTransaction(
                    format!("Error processing transaction: {}", e.error),
                    false,
                ));
            }
            TransactionResult::Skipped(e) => {
                tenure_tx.rollback_block();
                return Err(ChainError::InvalidStacksTransaction(
                    format!("Skipped transaction: {}", e.error),
                    false,
                ));
            }
            TransactionResult::Problematic(e) => {
                tenure_tx.rollback_block();
                return Err(ChainError::InvalidStacksTransaction(
                    format!("Problematic transaction: {}", e.error),
                    false,
                ));
            }
        };

        tenure_tx.rollback_block();

        RPCSimulatedTransaction::from_receipt(
            &receipt,
            tip_block_id.clone(),
            consensus_hash,
            block_height,
            execution_limit,
        )
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct RPCSimulatedTransaction {
    /// transaction id
    pub txid: Txid,
    /// the chain tip the transaction was simulated on top of
    pub tip_block_id: StacksBlockId,
    /// consensus hash of the tenure the simulated block would extend
    pub consensus_hash: ConsensusHash,
    /// height of the ephemeral block the transaction was simulated in
    pub block_height: u64,
    /// result of the transaction execution (hex string)
    #[serde(with = "prefix_hex_codec")]
    pub result_hex: Value,
    /// amount of burned stx
    pub stx_burned: u128,
    /// execution cost consumed by the transaction
    pub execution_cost: ExecutionCost,
    /// the execution limit the simulation ran under (the full tenure budget)
    pub execution_limit: Option<ExecutionCost>,
    /// generated events
    pub events: Vec<serde_json::Value>,
    /// whether the tx was aborted by a post-condition
    pub post_condition_aborted: bool,
    /// optional vm error
    pub vm_error: Option<String>,
}

impl RPCSimulatedTransaction {
    pub fn from_receipt(
        receipt: &StacksTransactionReceipt,
        tip_block_id: StacksBlockId,
        consensus_hash: ConsensusHash,
        block_height: u64,
        execution_limit: Option<ExecutionCost>,
    ) -> Result<Self, ChainError> {
        let txid = receipt.transaction.txid();

        let events = if receipt.post_condition_aborted {
            vec![]
        } else {
            receipt
                .events
                .iter()
                .enumerate()
                .map(|(event_index, event)| {
                    event.json_serialize(event_index, &txid, true).map_err(|e| {
                        ChainError::InvalidStacksBlock(format!(
                            "Failed to serialize transaction event: {e}"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        Ok(Self {
            txid,
            tip_block_id,
            consensus_hash,
            block_height,
            result_hex: receipt.result.clone(),
            stx_burned: receipt.stx_burned,
            execution_cost: receipt.execution_cost.clone(),
            execution_limit,
            events,
            post_condition_aborted: receipt.post_condition_aborted,
            vm_error: receipt.vm_error.clone(),
        })
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCTransactionSimulateRequestHandler {
    fn verb(&self) -> &'static str {
        "POST"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/transactions/simulate$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/transactions/simulate"
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
        // If no authorization is set, then the transaction simulation endpoint is not enabled
        let Some(password) = &self.auth else {
            return Err(Error::Http(400, "Bad Request.".into()));
        };
        let Some(auth_header) = preamble.headers.get("authorization") else {
            return Err(Error::Http(401, "Unauthorized".into()));
        };
        if auth_header != password {
            return Err(Error::Http(401, "Unauthorized".into()));
        }

        if preamble.get_content_length() == 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected non-zero-length body for transaction simulation endpoint"
                    .to_string(),
            ));
        }
        if preamble.get_content_length() > MAX_PAYLOAD_LEN {
            return Err(Error::DecodeError(
                "Invalid Http request: transaction simulation body is too big".to_string(),
            ));
        }

        self.transaction = match preamble.content_type {
            Some(HttpContentType::JSON) => Some(Self::parse_json(body)?),
            Some(_) => {
                return Err(Error::DecodeError(
                    "Wrong Content-Type for transaction simulation; expected application/json"
                        .to_string(),
                ))
            }
            None => {
                return Err(Error::DecodeError(
                    "Missing Content-Type for transaction simulation".to_string(),
                ))
            }
        };

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCTransactionSimulateRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.transaction = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let simulated_tx_res =
            node.with_node_state(|network, sortdb, chainstate, _mempool, _rpc_args| {
                let tip_block_id = network.stacks_tip.block_id();
                self.transaction_simulate(&tip_block_id, sortdb, chainstate)
            });

        let simulated_tx = match simulated_tx_res {
            Ok(simulated_tx) => simulated_tx,
            Err(ChainError::NoSuchBlockError) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new("No such chain tip\n".into()),
                )
                .try_into_contents()
                .map_err(NetError::from)
            }
            Err(ChainError::InvalidStacksTransaction(reason, _)) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpBadRequest::new(format!("Failed to simulate transaction: {reason}\n")),
                )
                .try_into_contents()
                .map_err(NetError::from)
            }
            Err(e) => {
                // nope -- error trying to simulate
                let msg = format!("Failed to simulate transaction: {e:?}\n");
                warn!("{}", &msg);
                return StacksHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                    .try_into_contents()
                    .map_err(NetError::from);
            }
        };

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&simulated_tx)?;
        Ok((preamble, body))
    }
}

impl StacksHttpRequest {
    /// Make a new transaction simulation request to this endpoint
    pub fn new_transaction_simulate(
        host: PeerHost,
        transaction: &StacksTransaction,
    ) -> StacksHttpRequest {
        let tx_simulate_body = RPCTransactionSimulateBody {
            transaction_hex: bytes_to_hex(&transaction.serialize_to_vec()),
        };

        StacksHttpRequest::new_for_peer(
            host,
            "POST".into(),
            "/v3/transactions/simulate".into(),
            HttpRequestContents::new().payload_json(
                serde_json::to_value(tx_simulate_body)
                    .expect("FATAL: failed to encode RPCTransactionSimulateBody"),
            ),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCTransactionSimulateRequestHandler {
    /// Decode this response from a byte stream.  This is called by the client to decode this
    /// message
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let simulated_tx: RPCSimulatedTransaction = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(simulated_tx)?)
    }
}

impl StacksHttpResponse {
    pub fn decode_simulated_transaction(self) -> Result<RPCSimulatedTransaction, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let simulated_tx: RPCSimulatedTransaction = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(simulated_tx)
    }
}
