// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use std::sync::Mutex;

use std::sync::LazyLock;

pub static STACKS_TIP_HEIGHT_GAUGE: LazyLock<IntGauge> = LazyLock::new(|| register_int_gauge!(opts!(
    "stacks_signer_stacks_node_height",
    "The current height of the Stacks node"
))
.unwrap());
pub static BLOCK_VALIDATION_RESPONSES: LazyLock<IntCounterVec> = LazyLock::new(|| register_int_counter_vec!(
    "stacks_signer_block_validation_responses",
    "The number of block validation responses. `response_type` is either 'accepted' or 'rejected'",
    &["response_type"]
)
.unwrap());
pub static BLOCK_RESPONSES_SENT: LazyLock<IntCounterVec> = LazyLock::new(|| register_int_counter_vec!(
    "stacks_signer_block_responses_sent",
    "The number of block responses sent. `response_type` is either 'accepted' or 'rejected'",
    &["response_type"]
)
.unwrap());
pub static BLOCK_PROPOSALS_RECEIVED: LazyLock<IntCounter> = LazyLock::new(|| register_int_counter!(opts!(
    "stacks_signer_block_proposals_received",
    "The number of block proposals received by the signer"
))
.unwrap());
pub static BLOCK_PRE_COMMITS_SENT: LazyLock<IntCounter> = LazyLock::new(|| register_int_counter!(opts!(
    "stacks_signer_block_pre_commits_sent",
    "The number of block pre-commits sent by the signer"
))
.unwrap());
pub static CURRENT_REWARD_CYCLE: LazyLock<IntGauge> = LazyLock::new(|| register_int_gauge!(opts!(
    "stacks_signer_current_reward_cycle",
    "The current reward cycle"
)).unwrap());
pub static SIGNER_STX_BALANCE: LazyLock<IntGauge> = LazyLock::new(|| register_int_gauge!(opts!(
    "stacks_signer_stx_balance",
    "The current STX balance of the signer"
)).unwrap());
pub static SIGNER_NONCE: LazyLock<IntGauge> = LazyLock::new(|| register_int_gauge!(opts!(
    "stacks_signer_nonce",
    "The current nonce of the signer"
)).unwrap());

pub static SIGNER_RPC_CALL_LATENCIES_HISTOGRAM: LazyLock<HistogramVec> = LazyLock::new(|| register_histogram_vec!(histogram_opts!(
    "stacks_signer_node_rpc_call_latencies_histogram",
    "Time (seconds) measuring round-trip RPC call latency to the Stacks node"
    // Will use DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0] by default
), &["path"]).unwrap());

pub static SIGNER_BLOCK_VALIDATION_LATENCIES_HISTOGRAM: LazyLock<HistogramVec> = LazyLock::new(|| register_histogram_vec!(histogram_opts!(
    "stacks_signer_block_validation_latencies_histogram",
    "Time (seconds) measuring block validation time reported by the Stacks node",
    vec![0.005, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0]
), &[]).unwrap());

pub static SIGNER_BLOCK_RESPONSE_LATENCIES_HISTOGRAM: LazyLock<HistogramVec> = LazyLock::new(|| register_histogram_vec!(histogram_opts!(
    "stacks_signer_block_response_latencies_histogram",
    "Time (seconds) measuring end-to-end time to respond to a block",
    vec![0.005, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0]
), &[]).unwrap());

pub static SIGNER_AGREEMENT_STATE_CHANGE_REASONS: LazyLock<IntCounterVec> = LazyLock::new(|| register_int_counter_vec!(
    "stacks_signer_agreement_state_change_reasons",
    "The number of state machine changes in signer agreement protocol. `reason` can be one of: 'burn_block_arrival', 'stacks_block_arrival', 'inactive_miner', 'protocol_upgrade', 'miner_view_update', 'miner_parent_tenure_update'",
    &["reason"]
).unwrap());

pub static SIGNER_AGREEMENT_STATE_CONFLICTS: LazyLock<IntCounterVec> = LazyLock::new(|| register_int_counter_vec!(
    "stacks_signer_agreement_state_conflicts",
    "The number of state machine conflicts in signer agreement protocol. `conflict` can be one of: 'burn_block_delay', 'stacks_block_delay', 'miner_view'",
    &["conflict"]
).unwrap());

pub static SIGNER_AGREEMENT_CAPITULATION_LATENCIES_HISTOGRAM: LazyLock<HistogramVec> = LazyLock::new(|| register_histogram_vec!(histogram_opts!(
    "stacks_signer_agreement_capitulation_latencies_histogram",
    "Measuring the time (in seconds) for the signer to agree (capitulate) with the signer set",
    vec![0.0, 1.0, 3.0, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0]
), &[]).unwrap());

pub static SIGNER_LOCAL_STATE_MACHINE: LazyLock<Mutex<Option<LocalStateMachine>>> = LazyLock::new(|| Mutex::new(None));

pub fn gather_metrics_string() -> String {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let metrics_families = gather();
    encoder.encode(&metrics_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
