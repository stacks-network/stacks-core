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

use std::sync::LazyLock;

use prometheus::{
    gather, histogram_opts, opts, register_histogram_vec, register_int_counter,
    register_int_counter_vec, register_int_gauge, Encoder, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, TextEncoder,
};

pub static STACKS_TIP_HEIGHT_GAUGE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_signer_stacks_node_height",
        "The current height of the Stacks node"
    ))
    .expect("Failed to create STACKS_TIP_HEIGHT_GAUGE")
});

pub static BLOCK_VALIDATION_RESPONSES: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "stacks_signer_block_validation_responses",
        "The number of block validation responses. `response_type` is either 'accepted' or 'rejected'",
        &["response_type"]
    ).expect("Failed to create BLOCK_VALIDATION_RESPONSES")
});

pub static BLOCK_RESPONSES_SENT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "stacks_signer_block_responses_sent",
        "The number of block responses sent. `response_type` is either 'accepted' or 'rejected'",
        &["response_type"]
    )
    .expect("Failed to create BLOCK_RESPONSES_SENT")
});

pub static SIGNER_INBOUND_MESSAGES: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_signer_inbound_messages",
        "The number of inbound messages received by the signer"
    ))
    .expect("Failed to create SIGNER_INBOUND_MESSAGES")
});

pub static COORDINATOR_INBOUND_MESSAGES: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_signer_coordinator_inbound_messages",
        "The number of inbound messages received as a coordinator"
    ))
    .expect("Failed to create COORDINATOR_INBOUND_MESSAGES")
});

pub static INBOUND_PACKETS_RECEIVED: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_signer_inbound_packets_received",
        "The number of inbound packets received by the signer"
    ))
    .expect("Failed to create INBOUND_PACKETS_RECEIVED")
});

pub static COMMANDS_PROCESSED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "stacks_signer_commands_processed",
        "The number of commands processed by the signer",
        &["command_type"]
    )
    .expect("Failed to create COMMANDS_PROCESSED")
});

pub static DGK_VOTES_SUBMITTED: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_signer_dgk_votes_submitted",
        "The number of DGK votes submitted by the signer"
    ))
    .expect("Failed to create DGK_VOTES_SUBMITTED")
});

pub static OPERATION_RESULTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "stacks_signer_operation_results_dkg",
        "The number of DKG operation results",
        &["operation_type"]
    )
    .expect("Failed to create OPERATION_RESULTS")
});

pub static BLOCK_PROPOSALS_RECEIVED: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_signer_block_proposals_received",
        "The number of block proposals received by the signer"
    ))
    .expect("Failed to create BLOCK_PROPOSALS_RECEIVED")
});

pub static CURRENT_REWARD_CYCLE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_signer_current_reward_cycle",
        "The current reward cycle"
    ))
    .expect("Failed to create CURRENT_REWARD_CYCLE")
});

pub static SIGNER_STX_BALANCE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_signer_stx_balance",
        "The current STX balance of the signer"
    ))
    .expect("Failed to create SIGNER_STX_BALANCE")
});

pub static SIGNER_NONCE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_signer_nonce",
        "The current nonce of the signer"
    ))
    .expect("Failed to create SIGNER_NONCE")
});

pub static SIGNER_RPC_CALL_LATENCIES_HISTOGRAM: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        histogram_opts!(
            "stacks_signer_node_rpc_call_latencies_histogram",
            "Time (seconds) measuring round-trip RPC call latency to the Stacks node" // Will use DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0] by default
        ),
        &["path"]
    )
    .expect("Failed to create SIGNER_RPC_CALL_LATENCIES_HISTOGRAM")
});

pub fn gather_metrics_string() -> String {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let metrics_families = gather();
    encoder.encode(&metrics_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
