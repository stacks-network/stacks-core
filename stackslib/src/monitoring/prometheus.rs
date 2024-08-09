// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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
    histogram_opts, labels, opts, register_gauge, register_histogram, register_histogram_vec,
    register_int_counter, register_int_counter_vec, register_int_gauge, Gauge, Histogram,
    HistogramTimer, HistogramVec, IntCounter, IntCounterVec, IntGauge,
};

pub static RPC_CALL_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_node_rpc_requests_total",
        "Total number of RPC requests made.",
        labels! {"handler" => "all",}
    ))
    .expect("Failed to register RPC_CALL_COUNTER")
});

pub static RPC_CALL_LATENCIES_HISTOGRAM: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        histogram_opts!(
            "stacks_node_rpc_call_latencies_histogram",
            "Time (seconds) measuring RPC calls latency" // Will use DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0] by default
        ),
        &["path"]
    )
    .expect("Failed to register RPC_CALL_LATENCIES_HISTOGRAM")
});

pub static STX_BLOCKS_RECEIVED_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_node_stx_blocks_received_total",
        "Total number of Stacks blocks received"
    ))
    .expect("Failed to register STX_BLOCKS_RECEIVED_COUNTER")
});

pub static STX_MICRO_BLOCKS_RECEIVED_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_node_stx_micro_blocks_received_total",
        "Total number of Stacks micro blocks received"
    ))
    .expect("Failed to register STX_MICRO_BLOCKS_RECEIVED_COUNTER")
});

pub static STX_BLOCKS_SERVED_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_node_stx_blocks_served_total",
        "Total number of Stacks blocks served"
    ))
    .expect("Failed to register STX_BLOCKS_SERVED_COUNTER")
});

pub static STX_MICRO_BLOCKS_SERVED_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_node_stx_micro_blocks_served_total",
        "Total number of Stacks micro blocks served"
    ))
    .expect("Failed to register STX_MICRO_BLOCKS_SERVED_COUNTER")
});

pub static STX_CONFIRMED_MICRO_BLOCKS_SERVED_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_node_stx_confirmed_micro_blocks_served_total",
        "Total number of Stacks blocks served"
    ))
    .expect("Failed to register STX_CONFIRMED_MICRO_BLOCKS_SERVED_COUNTER")
});

pub static TXS_RECEIVED_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_node_transactions_received_total",
        "Total number of transactions received and relayed"
    ))
    .expect("Failed to register TXS_RECEIVED_COUNTER")
});

pub static BTC_BLOCKS_RECEIVED_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_node_btc_blocks_received_total",
        "Total number of blocks processed from the burnchain"
    ))
    .expect("Failed to register BTC_BLOCKS_RECEIVED_COUNTER")
});

pub static BTC_OPS_SENT_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_node_btc_ops_sent_total",
        "Total number of ops (key registrations, block commits, user burn supports) submitted to the burnchain"
    )).expect("Failed to register BTC_OPS_SENT_COUNTER")
});

pub static STX_BLOCKS_PROCESSED_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_node_stx_blocks_processed_total",
        "Total number of stacks blocks processed"
    ))
    .expect("Failed to register STX_BLOCKS_PROCESSED_COUNTER")
});

pub static STX_BLOCKS_MINED_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_node_stx_blocks_mined_total",
        "Total number of stacks blocks mined by node"
    ))
    .expect("Failed to register STX_BLOCKS_MINED_COUNTER")
});

pub static WARNING_EMITTED_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_node_warning_emitted_total",
        "Total number of warning logs emitted by node"
    ))
    .expect("Failed to register WARNING_EMITTED_COUNTER")
});

pub static ERRORS_EMITTED_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_node_errors_emitted_total",
        "Total number of error logs emitted by node"
    ))
    .expect("Failed to register ERRORS_EMITTED_COUNTER")
});

pub static LAST_BLOCK_READ_COUNT: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(opts!(
        "stacks_node_last_block_read_count",
        "`execution_cost_read_count` for the last block observed."
    ))
    .expect("Failed to register LAST_BLOCK_READ_COUNT")
});

pub static LAST_BLOCK_WRITE_COUNT: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(opts!(
        "stacks_node_last_block_write_count",
        "`execution_cost_write_count` for the last block observed."
    ))
    .expect("Failed to register LAST_BLOCK_WRITE_COUNT")
});

pub static LAST_BLOCK_READ_LENGTH: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(opts!(
        "stacks_node_last_block_read_length",
        "`execution_cost_read_length` for the last block observed."
    ))
    .expect("Failed to register LAST_BLOCK_READ_LENGTH")
});

pub static LAST_BLOCK_WRITE_LENGTH: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(opts!(
        "stacks_node_last_block_write_length",
        "`execution_cost_write_length` for the last block observed."
    ))
    .expect("Failed to register LAST_BLOCK_WRITE_LENGTH")
});

pub static LAST_BLOCK_RUNTIME: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(opts!(
        "stacks_node_last_block_runtime",
        "`execution_cost_runtime` for the last block observed."
    ))
    .expect("Failed to register LAST_BLOCK_RUNTIME")
});

pub static LAST_BLOCK_TRANSACTION_COUNT: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_last_block_transaction_count",
        "Number of transactions in the last block."
    ))
    .expect("Failed to register LAST_BLOCK_TRANSACTION_COUNT")
});

pub static LAST_MINED_BLOCK_READ_COUNT: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(opts!(
        "stacks_node_last_mined_block_read_count",
        "`execution_cost_read_count` for the last mined block produced."
    ))
    .expect("Failed to register LAST_MINED_BLOCK_READ_COUNT")
});

pub static LAST_MINED_BLOCK_WRITE_COUNT: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(opts!(
        "stacks_node_last_mined_block_write_count",
        "`execution_cost_write_count` for the last mined block produced."
    ))
    .expect("Failed to register LAST_MINED_BLOCK_WRITE_COUNT")
});

pub static LAST_MINED_BLOCK_READ_LENGTH: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(opts!(
        "stacks_node_last_mined_block_read_length",
        "`execution_cost_read_length` for the last mined block produced."
    ))
    .expect("Failed to register LAST_MINED_BLOCK_READ_LENGTH")
});

pub static LAST_MINED_BLOCK_WRITE_LENGTH: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(opts!(
        "stacks_node_last_mined_block_write_length",
        "`execution_cost_write_length` for the last mined block produced."
    ))
    .expect("Failed to register LAST_MINED_BLOCK_WRITE_LENGTH")
});

pub static LAST_MINED_BLOCK_RUNTIME: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(opts!(
        "stacks_node_last_mined_block_runtime",
        "`execution_cost_runtime` for the last mined block produced."
    ))
    .expect("Failed to register LAST_MINED_BLOCK_RUNTIME")
});

pub static LAST_MINED_BLOCK_TRANSACTION_COUNT: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_last_mined_block_transaction_count",
        "Number of transactions in the last mined block."
    ))
    .expect("Failed to register LAST_MINED_BLOCK_TRANSACTION_COUNT")
});

pub static ACTIVE_MINERS_COUNT_GAUGE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_active_miners_total",
        "Total number of active miners"
    ))
    .expect("Failed to register ACTIVE_MINERS_COUNT_GAUGE")
});

pub static STACKS_TIP_HEIGHT_GAUGE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_stacks_tip_height",
        "Stacks chain tip height"
    ))
    .expect("Failed to register STACKS_TIP_HEIGHT_GAUGE")
});

pub static BURNCHAIN_HEIGHT_GAUGE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_burn_block_height",
        "Burnchain tip height"
    ))
    .expect("Failed to register BURNCHAIN_HEIGHT_GAUGE")
});

pub static INBOUND_NEIGHBORS_GAUGE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_neighbors_inbound",
        "Total count of current known inbound neighbors"
    ))
    .expect("Failed to register INBOUND_NEIGHBORS_GAUGE")
});

pub static OUTBOUND_NEIGHBORS_GAUGE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_neighbors_outbound",
        "Total count of current known outbound neighbors"
    ))
    .expect("Failed to register OUTBOUND_NEIGHBORS_GAUGE")
});

pub static INBOUND_BANDWIDTH_GAUGE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_bandwidth_inbound",
        "Total inbound bandwidth total in bytes"
    ))
    .expect("Failed to register INBOUND_BANDWIDTH_GAUGE")
});

pub static OUTBOUND_BANDWIDTH_GAUGE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_bandwidth_outbound",
        "Total outbound bandwidth total in bytes"
    ))
    .expect("Failed to register OUTBOUND_BANDWIDTH_GAUGE")
});

pub static INBOUND_RPC_BANDWIDTH_GAUGE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_rpc_bandwidth_inbound",
        "Total RPC inbound bandwidth in bytes"
    ))
    .expect("Failed to register INBOUND_RPC_BANDWIDTH_GAUGE")
});

pub static OUTBOUND_RPC_BANDWIDTH_GAUGE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_rpc_bandwidth_outbound",
        "Total RPC outbound bandwidth in bytes"
    ))
    .expect("Failed to register OUTBOUND_RPC_BANDWIDTH_GAUGE")
});

pub static MSG_COUNTER_VEC: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "stacks_node_message_count",
        "Stacks message count by type of message",
        &["name"]
    )
    .expect("Failed to register MSG_COUNTER_VEC")
});

pub static STX_MEMPOOL_GC: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_node_mempool_gc_count",
        "Total count of all mempool garbage collections"
    ))
    .expect("Failed to register STX_MEMPOOL_GC")
});

pub static CONTRACT_CALLS_PROCESSED_COUNT: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "stacks_contract_calls_processed",
        "Total count of processed contract calls"
    ))
    .expect("Failed to register CONTRACT_CALLS_PROCESSED_COUNT")
});

pub static MEMPOOL_OUTSTANDING_TXS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_mempool_outstanding_txs",
        "Number of still-unprocessed transactions received by this node since it started",
        labels! {"handler" => "all",}
    ))
    .expect("Failed to register MEMPOOL_OUTSTANDING_TXS")
});

pub static MEMPOOL_TX_CONFIRM_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(histogram_opts!(
        "stacks_node_mempool_tx_confirm_times",
        "Time (seconds) between when a tx was received by this node's mempool and when a tx was first processed in a block",
        vec![300.0, 600.0, 900.0, 1200.0, 1500.0, 1800.0, 2100.0, 2400.0, 2700.0, 3000.0, 3600.0, 4200.0, 4800.0, 6000.0],
        labels! {"handler".to_string() => "all".to_string(),}
    )).expect("Failed to register MEMPOOL_TX_CONFIRM_TIME")
});

pub static COMPUTED_RELATIVE_MINER_SCORE: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(opts!(
        "stacks_node_computed_relative_miner_score",
        "Percentage of the u256 range that this miner is assigned in a particular round of sortition"
    )).expect("Failed to register COMPUTED_RELATIVE_MINER_SCORE")
});

pub static COMPUTED_MINER_COMMITMENT_HIGH: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_computed_miner_commitment_high",
        "High 64 bits of a miner's effective commitment (min of the miner's previous commitment and their median commitment)"
    )).expect("Failed to register COMPUTED_MINER_COMMITMENT_HIGH")
});

pub static COMPUTED_MINER_COMMITMENT_LOW: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_computed_miner_commitment_low",
        "Low 64 bits of a miner's effective commitment (min of the miner's previous commitment and their median commitment)"
    )).expect("Failed to register COMPUTED_MINER_COMMITMENT_LOW")
});

pub static MINER_CURRENT_MEDIAN_COMMITMENT_HIGH: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_miner_current_median_commitment_high",
        "High 64 bits of a miner's median commitment over the mining commitment window."
    ))
    .expect("Failed to register MINER_CURRENT_MEDIAN_COMMITMENT_HIGH")
});

pub static MINER_CURRENT_MEDIAN_COMMITMENT_LOW: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!(
        "stacks_node_miner_current_median_commitment_low",
        "Low 64 bits of a miner's median commitment over the mining commitment window."
    ))
    .expect("Failed to register MINER_CURRENT_MEDIAN_COMMITMENT_LOW")
});

pub fn new_rpc_call_timer(path: &str) -> HistogramTimer {
    let histogram = RPC_CALL_LATENCIES_HISTOGRAM.with_label_values(&[path]);
    histogram.start_timer()
}
