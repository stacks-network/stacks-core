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

// Copied from stackslib/src/net/api/blockreplay.rs lines 16-41
use clarity::vm::costs::ExecutionCost;
use clarity::vm::Value;
use regex::{Captures, Regex};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::net::PeerHost;
use stacks_common::util::get_epoch_time_secs;
use url::form_urlencoded;

use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::miner::{MinerTenureInfoCause, NakamotoBlockBuilder};
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::miner::{
    BlockBuilder, BlockLimitFunction, TransactionError, TransactionProblematic, TransactionResult,
    TransactionSkipped,
};
use crate::chainstate::stacks::{Error as ChainError, StacksTransaction};
use crate::config::DEFAULT_MAX_TENURE_BYTES;
use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{RPCRequestHandler, StacksHttpResponse};
use crate::net::{Error as NetError, StacksHttpRequest, StacksNodeState};

// Copied from stackslib/src/net/api/blockreplay.rs lines 43-144
// BlockReplayProfiler - used for CPU performance profiling (Linux x86_64 only)
#[cfg(all(feature = "profiler", target_os = "linux", target_arch = "x86_64"))]
struct BlockReplayProfiler {
    perf_event_cpu_instructions: Option<perf_event::Counter>,
    perf_event_cpu_cycles: Option<perf_event::Counter>,
    perf_event_cpu_ref_cycles: Option<perf_event::Counter>,
}

#[cfg(not(all(feature = "profiler", target_os = "linux", target_arch = "x86_64")))]
struct BlockReplayProfiler();

#[derive(Default)]
struct BlockReplayProfilerResult {
    cpu_instructions: Option<u64>,
    cpu_cycles: Option<u64>,
    cpu_ref_cycles: Option<u64>,
}

#[cfg(all(feature = "profiler", target_os = "linux", target_arch = "x86_64"))]
impl BlockReplayProfiler {
    fn new() -> Self {
        let mut perf_event_cpu_instructions: Option<perf_event::Counter> = None;
        let mut perf_event_cpu_cycles: Option<perf_event::Counter> = None;
        let mut perf_event_cpu_ref_cycles: Option<perf_event::Counter> = None;

        if let Ok(mut perf_event_cpu_instructions_result) =
            perf_event::Builder::new(perf_event::events::Hardware::INSTRUCTIONS).build()
        {
            if perf_event_cpu_instructions_result.enable().is_ok() {
                perf_event_cpu_instructions = Some(perf_event_cpu_instructions_result);
            }
        }

        if let Ok(mut perf_event_cpu_cycles_result) =
            perf_event::Builder::new(perf_event::events::Hardware::CPU_CYCLES).build()
        {
            if perf_event_cpu_cycles_result.enable().is_ok() {
                perf_event_cpu_cycles = Some(perf_event_cpu_cycles_result);
            }
        }

        if let Ok(mut perf_event_cpu_ref_cycles_result) =
            perf_event::Builder::new(perf_event::events::Hardware::REF_CPU_CYCLES).build()
        {
            if perf_event_cpu_ref_cycles_result.enable().is_ok() {
                perf_event_cpu_ref_cycles = Some(perf_event_cpu_ref_cycles_result);
            }
        }

        Self {
            perf_event_cpu_instructions,
            perf_event_cpu_cycles,
            perf_event_cpu_ref_cycles,
        }
    }

    fn collect(self) -> BlockReplayProfilerResult {
        let mut cpu_instructions: Option<u64> = None;
        let mut cpu_cycles: Option<u64> = None;
        let mut cpu_ref_cycles: Option<u64> = None;

        if let Some(mut perf_event_cpu_instructions) = self.perf_event_cpu_instructions {
            if perf_event_cpu_instructions.disable().is_ok() {
                if let Ok(value) = perf_event_cpu_instructions.read() {
                    cpu_instructions = Some(value);
                }
            }
        }

        if let Some(mut perf_event_cpu_cycles) = self.perf_event_cpu_cycles {
            if perf_event_cpu_cycles.disable().is_ok() {
                if let Ok(value) = perf_event_cpu_cycles.read() {
                    cpu_cycles = Some(value);
                }
            }
        }

        if let Some(mut perf_event_cpu_ref_cycles) = self.perf_event_cpu_ref_cycles {
            if perf_event_cpu_ref_cycles.disable().is_ok() {
                if let Ok(value) = perf_event_cpu_ref_cycles.read() {
                    cpu_ref_cycles = Some(value);
                }
            }
        }

        BlockReplayProfilerResult {
            cpu_instructions,
            cpu_cycles,
            cpu_ref_cycles,
        }
    }
}

#[cfg(not(all(feature = "profiler", target_os = "linux", target_arch = "x86_64")))]
impl BlockReplayProfiler {
    fn new() -> Self {
        warn!("BlockReplay Profiler is not available in this build.");
        Self {}
    }
    fn collect(self) -> BlockReplayProfilerResult {
        BlockReplayProfilerResult::default()
    }
}

// Based on stackslib/src/net/api/blockreplay.rs:146-160
// CHANGED: Different fields for transaction simulation
#[derive(Clone)]
pub struct RPCTransactionSimulateRequestHandler {
    pub tx: Option<StacksTransaction>,      // CHANGED: transaction instead of block_id
    pub block_id: Option<StacksBlockId>,    // NEW: optional parent block (defaults to tip)
    pub auth: Option<String>,               // SAME: auth token
    pub profiler: bool,                     // SAME: profiler flag
    pub ignore_limits: bool,                // NEW: whether to ignore block limits
}

impl RPCTransactionSimulateRequestHandler {
    pub fn new(auth: Option<String>) -> Self {
        Self {
            tx: None,
            block_id: None,
            auth,
            profiler: false,
            ignore_limits: false,
        }
    }

    // Based on stackslib/src/net/api/blockreplay.rs:162-325 (block_replay)
    // HEAVILY ADAPTED for single transaction simulation
    pub fn simulate_transaction(
        &self,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
    ) -> Result<RPCSimulatedTransaction, ChainError> {
        // Validate we have a transaction
        // CHANGED: Check for tx instead of block_id
        let Some(tx) = &self.tx else {
            return Err(ChainError::InvalidStacksTransaction(
                "No transaction provided".into(),
                false,
            ));
        };

        // CHANGED: Determine parent block - default to canonical tip
        let parent_block_id = if let Some(block_id) = &self.block_id {
            // User specified a parent block
            block_id.clone()
        } else {
            // Default to current canonical tip
            // DIFFERENT from replay: we simulate against current state, not historical
            let tip_header = NakamotoChainState::get_canonical_block_header(chainstate.db(), sortdb)?
                .ok_or_else(|| ChainError::NoSuchBlockError)?;
            tip_header.index_block_hash()
        };

        // Get parent block header
        // From blockreplay.rs:223-233
        let parent_stacks_header_opt =
            match NakamotoChainState::get_block_header(chainstate.db(), &parent_block_id) {
                Ok(parent_stacks_header_opt) => parent_stacks_header_opt,
                Err(e) => return Err(e),
            };

        let Some(parent_stacks_header) = parent_stacks_header_opt else {
            return Err(ChainError::InvalidStacksBlock(
                "Invalid Parent Block".into(),
            ));
        };

        // CHANGED: Get CURRENT burn chain tip and consensus hash
        // Different from replay which uses historical consensus_hash from block.header
        let burn_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .map_err(|_| ChainError::NoSuchBlockError)?;
        let consensus_hash = burn_tip.consensus_hash;

        let burn_dbconn = match sortdb.index_handle_at_block(chainstate, &parent_block_id) {
            Ok(burn_dbconn) => burn_dbconn,
            Err(_) => return Err(ChainError::NoSuchBlockError),
        };

        // CHANGED: No tenure change or coinbase for simulation
        // From blockreplay.rs:208-221, but always None for simulation
        let tenure_change = None; // Simulations don't change tenure
        let coinbase = None; // Simulations don't mint coinbase
        let tenure_cause = MinerTenureInfoCause::NoTenureChange;

        // CHANGED: Use current timestamp, not historical
        // From blockreplay.rs:235-249, but with current time
        let mut builder = match NakamotoBlockBuilder::new(
            &parent_stacks_header,
            &consensus_hash,             // CHANGED: current consensus hash
            0,                            // CHANGED: no burn (not mining a real block)
            tenure_change,                // None
            coinbase,                     // None
            0,                            // CHANGED: no pox_treatment
            None,                         // No VRF proof
            None,                         // No miner key
            Some(get_epoch_time_secs()),  // CHANGED: current timestamp
            u64::from(DEFAULT_MAX_TENURE_BYTES),
        ) {
            Ok(builder) => builder,
            Err(e) => return Err(e),
        };

        // From blockreplay.rs:251-255 - SAME
        let mut miner_tenure_info =
            match builder.load_ephemeral_tenure_info(chainstate, &burn_dbconn, tenure_cause) {
                Ok(miner_tenure_info) => miner_tenure_info,
                Err(e) => return Err(e),
            };

        // From blockreplay.rs:257-261 - SAME
        let _burn_chain_height = miner_tenure_info.burn_tip_height;
        let mut tenure_tx = match builder.tenure_begin(&burn_dbconn, &mut miner_tenure_info) {
            Ok(tenure_tx) => tenure_tx,
            Err(e) => return Err(e),
        };

        // CHANGED: Execute single transaction, not loop
        // From blockreplay.rs:263-305, but simplified for single tx
        let tx_len = tx.tx_len();
        let mut total_receipts = 0u64;

        let mut profiler: Option<BlockReplayProfiler> = None;
        let mut profiler_result = BlockReplayProfilerResult::default();

        if self.profiler {
            profiler = Some(BlockReplayProfiler::new());
        }

        // CHANGED: Optionally respect block limits
        // From blockreplay.rs:276-283, but with configurable limit_behavior
        let limit_behavior = if self.ignore_limits {
            BlockLimitFunction::NO_LIMIT_HIT
        } else {
            // Respect limits to see if tx would fit in a real block
            BlockLimitFunction::CONTRACT_LIMIT_HIT
        };

        let tx_result = builder.try_mine_tx_with_len(
            &mut tenure_tx,
            tx,
            tx_len,
            &limit_behavior, // CHANGED: configurable
            None,
            &mut total_receipts,
        );

        if let Some(profiler) = profiler {
            profiler_result = profiler.collect();
        }

        // CHANGED: Don't abort on error - return it to user
        // From blockreplay.rs:289-305, but different error handling
        let (receipt_opt, error_opt, valid) = match tx_result {
            TransactionResult::Success(tx_result) => (Some(tx_result.receipt), None, true),
            TransactionResult::Skipped(TransactionSkipped { error, .. }) => {
                (None, Some(format!("Transaction skipped: {}", error)), false)
            }
            TransactionResult::ProcessingError(TransactionError { error, .. }) => (
                None,
                Some(format!("Processing error: {:?}", error)),
                false,
            ),
            TransactionResult::Problematic(TransactionProblematic { error, .. }) => (
                None,
                Some(format!("Problematic transaction: {:?}", error)),
                false,
            ),
        };

        // From blockreplay.rs:309 - SAME: Always rollback
        tenure_tx.rollback_block();

        // CHANGED: No block finalization needed
        // Skip blockreplay.rs:307-323 (mine_nakamoto_block, merkle validation)
        // We're not creating a block, just simulating execution

        // CHANGED: Build simulation response
        // Different from RPCReplayedBlock structure
        let response = RPCSimulatedTransaction {
            txid: tx.txid(),
            valid,
            error: error_opt,
            result: receipt_opt.as_ref().map(|r| r.result.clone()),
            result_hex: receipt_opt.as_ref().map(|r| r.result.clone()),
            stx_burned: receipt_opt.as_ref().map(|r| r.stx_burned).unwrap_or(0),
            execution_cost: receipt_opt
                .as_ref()
                .map(|r| r.execution_cost.clone())
                .unwrap_or(ExecutionCost::ZERO),
            events: receipt_opt
                .as_ref()
                .map(|r| {
                    r.events
                        .iter()
                        .enumerate()
                        .map(|(idx, event)| {
                            event
                                .json_serialize(idx, &tx.txid(), !r.post_condition_aborted)
                                .unwrap()
                        })
                        .collect()
                })
                .unwrap_or_default(),
            post_condition_aborted: receipt_opt
                .as_ref()
                .map(|r| r.post_condition_aborted)
                .unwrap_or(false),
            vm_error: receipt_opt.as_ref().and_then(|r| r.vm_error.clone()),
            cpu_instructions: profiler_result.cpu_instructions,
            cpu_cycles: profiler_result.cpu_cycles,
            cpu_ref_cycles: profiler_result.cpu_ref_cycles,
        };

        Ok(response)
    }
}

// Based on stackslib/src/net/api/blockreplay.rs:328-408 (RPCReplayedBlockTransaction)
// CHANGED: Single transaction response, not array in block
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct RPCSimulatedTransaction {
    /// transaction id
    pub txid: Txid,

    // NEW FIELDS for simulation
    /// Whether the transaction is valid and would be accepted
    pub valid: bool,
    /// Error message if transaction failed validation/execution
    pub error: Option<String>,

    // SAME FIELDS as RPCReplayedBlockTransaction
    /// result of transaction execution (clarity value)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// result of the transaction execution (hex string)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_hex: Option<Value>,
    /// amount of burned stx
    pub stx_burned: u128,
    /// execution cost infos
    pub execution_cost: ExecutionCost,
    /// generated events
    pub events: Vec<serde_json::Value>,
    /// Whether the tx was aborted by a post-condition
    pub post_condition_aborted: bool,
    /// optional vm error
    pub vm_error: Option<String>,

    // SAME: profiling data
    pub cpu_instructions: Option<u64>,
    pub cpu_cycles: Option<u64>,
    pub cpu_ref_cycles: Option<u64>,
}

// Based on stackslib/src/net/api/blockreplay.rs:468-532
// CHANGED: POST method, different path, body parsing
impl HttpRequest for RPCTransactionSimulateRequestHandler {
    fn verb(&self) -> &'static str {
        "POST" // CHANGED: POST instead of GET
    }

    fn path_regex(&self) -> Regex {
        // CHANGED: New endpoint path
        Regex::new(r#"^/v3/transactions/simulate$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/transactions/simulate"
    }

    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        _captures: &Captures,
        query: Option<&str>,
        body: &[u8], // CHANGED: Now we read the body!
    ) -> Result<HttpRequestContents, Error> {
        // From blockreplay.rs:491-500 - SAME auth check
        let Some(password) = &self.auth else {
            return Err(Error::Http(400, "Bad Request.".into()));
        };
        let Some(auth_header) = preamble.headers.get("authorization") else {
            return Err(Error::Http(401, "Unauthorized".into()));
        };
        if auth_header != password {
            return Err(Error::Http(401, "Unauthorized".into()));
        }

        // CHANGED: Parse transaction from body
        // Different from blockreplay which has no body
        if body.is_empty() {
            return Err(Error::DecodeError(
                "Missing transaction in request body".to_string(),
            ));
        }

        // Parse transaction hex from body
        let tx = StacksTransaction::consensus_deserialize(&mut &body[..]).map_err(|e| {
            Error::DecodeError(format!("Failed to deserialize transaction: {:?}", e))
        })?;

        self.tx = Some(tx);

        // CHANGED: Parse query parameters
        // From blockreplay.rs:519-529, but with additional params
        if let Some(query_string) = query {
            for (key, value) in form_urlencoded::parse(query_string.as_bytes()) {
                match key.as_ref() {
                    "profiler" => {
                        if value == "1" {
                            self.profiler = true;
                        }
                    }
                    "ignore_limits" => {
                        if value == "1" {
                            self.ignore_limits = true;
                        }
                    }
                    "block_id" => {
                        // NEW: Optional parent block
                        let block_id = StacksBlockId::from_hex(&value).map_err(|_| {
                            Error::DecodeError("Invalid block_id parameter".to_string())
                        })?;
                        self.block_id = Some(block_id);
                    }
                    _ => {}
                }
            }
        }

        Ok(HttpRequestContents::new().query_string(query))
    }
}

// Based on stackslib/src/net/api/blockreplay.rs:534-581
// Minor changes for simulation
impl RPCRequestHandler for RPCTransactionSimulateRequestHandler {
    fn restart(&mut self) {
        self.tx = None;
        self.block_id = None;
        self.profiler = false;
        self.ignore_limits = false;
    }

    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        // CHANGED: Check for tx instead of block_id
        let Some(_tx) = &self.tx else {
            return Err(NetError::SendError("Missing transaction".into()));
        };

        // CHANGED: Call simulate_transaction instead of block_replay
        let simulated_tx_res =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                self.simulate_transaction(sortdb, chainstate)
            });

        // From blockreplay.rs:557-575, but simpler error handling
        let simulated_tx = match simulated_tx_res {
            Ok(simulated_tx) => simulated_tx,
            Err(ChainError::NoSuchBlockError) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new("Parent block not found\n".to_string()),
                )
                .try_into_contents()
                .map_err(NetError::from)
            }
            Err(e) => {
                let msg = format!("Failed to simulate transaction: {:?}\n", &e);
                warn!("{}", &msg);
                return StacksHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                    .try_into_contents()
                    .map_err(NetError::from);
            }
        };

        // From blockreplay.rs:577-580 - SAME response format
        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&simulated_tx)?;
        Ok((preamble, body))
    }
}

// Based on stackslib/src/net/api/blockreplay.rs:583-611
// CHANGED: POST request with transaction body
impl StacksHttpRequest {
    pub fn new_transaction_simulate(
        host: PeerHost,
        tx: &StacksTransaction,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "POST".into(),
            "/v3/transactions/simulate".to_string(),
            HttpRequestContents::new().payload_stacks(tx),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }

    pub fn new_transaction_simulate_with_options(
        host: PeerHost,
        tx: &StacksTransaction,
        block_id: Option<&StacksBlockId>,
        profiler: bool,
        ignore_limits: bool,
    ) -> StacksHttpRequest {
        let mut contents = HttpRequestContents::new().payload_stacks(tx);

        if profiler {
            contents = contents.query_arg("profiler".into(), "1".into());
        }
        if ignore_limits {
            contents = contents.query_arg("ignore_limits".into(), "1".into());
        }
        if let Some(block_id) = block_id {
            contents = contents.query_arg("block_id".into(), block_id.to_hex());
        }

        StacksHttpRequest::new_for_peer(
            host,
            "POST".into(),
            "/v3/transactions/simulate".to_string(),
            contents,
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

// Based on stackslib/src/net/api/blockreplay.rs:613-635
// CHANGED: Different response structure
impl HttpResponse for RPCTransactionSimulateRequestHandler {
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
