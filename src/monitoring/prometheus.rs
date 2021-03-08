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

use prometheus::{Histogram, HistogramTimer, IntCounter, IntGauge, HistogramVec};

lazy_static! {
    pub static ref RPC_CALL_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_rpc_requests_total",
        "Total number of RPC requests made.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref RPC_CALL_LATENCIES_HISTOGRAM: HistogramVec = register_histogram_vec!(histogram_opts!(
        "stacks_node_rpc_call_latencies_histogram",
        "Time (seconds) measuring RPC calls latency"
        // Will use DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0] by default
    ), &["path"]).unwrap();

    pub static ref P2P_MSG_UNAUTHENTICATED_HANDSHAKE_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_p2p_msg_unauthenticated_handshake_received_total",
        "Total number of authenticated Handshake messages received.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref P2P_MSG_AUTHENTICATED_HANDSHAKE_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_p2p_msg_authenticated_handshake_received_total",
        "Total number of authenticated Handshake messages received.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref P2P_MSG_GET_NEIGHBORS_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_p2p_msg_get_neighbors_received_total",
        "Total number of GetNeighbors messages received.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref P2P_MSG_GET_BLOCKS_INV_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_p2p_msg_get_blocks_inv_received_total",
        "Total number of GetBlocksInv messages received.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref P2P_MSG_NACK_SENT_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_p2p_msg_nack_sent_total",
        "Total number of Nack messages sent.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref P2P_MSG_PING_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_p2p_msg_ping_received_total",
        "Total number of Ping messages received.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref P2P_MSG_NAT_PUNCH_REQUEST_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_p2p_msg_nat_punch_request_received_total",
        "Total number of NatPunchRequest messages received.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref STX_BLOCKS_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_blocks_received_total",
        "Total number of Stacks blocks received.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref STX_MICRO_BLOCKS_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_micro_blocks_received_total",
        "Total number of Stacks micro blocks received.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref STX_BLOCKS_SERVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_blocks_served_total",
        "Total number of Stacks blocks served.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref STX_MICRO_BLOCKS_SERVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_micro_blocks_served_total",
        "Total number of Stacks micro blocks served.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref STX_CONFIRMED_MICRO_BLOCKS_SERVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_confirmed_micro_blocks_served_total",
        "Total number of Stacks blocks served.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref TXS_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_transactions_received_total",
        "Total number of transactions received and relayed.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref BTC_BLOCKS_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_btc_blocks_received_total",
        "Total number of blocks processed from the burnchain.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref BTC_OPS_SENT_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_btc_ops_sent_total",
        "Total number of ops (key registrations, block commits, user burn supports) submitted to the burnchain.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref STX_BLOCKS_PROCESSED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_blocks_processed_total",
        "Total number of stacks blocks processed.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref STX_BLOCKS_MINED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_blocks_mined_total",
        "Total number of stacks blocks mined by node.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref WARNING_EMITTED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_warning_emitted_total",
        "Total number of warning logs emitted by node.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref ERRORS_EMITTED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_errors_emitted_total",
        "Total number of error logs emitted by node.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref ACTIVE_MINERS_COUNT_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_active_miners_total",
        "Total number of active miners.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref MEMPOOL_OUTSTANDING_TXS: IntGauge = register_int_gauge!(opts!(
        "stacks_node_mempool_outstanding_txs",
        "Number of still-unprocessed transactions received by this node since it started",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref MEMPOOL_TX_CONFIRM_TIME: Histogram = register_histogram!(histogram_opts!(
        "stacks_node_mempool_tx_confirm_times",
        "Time (seconds) between when a tx was received by this node's mempool and when a tx was first processed in a block",
        vec![300.0, 600.0, 900.0, 1200.0, 1500.0, 1800.0, 2100.0, 2400.0, 2700.0, 3000.0, 3600.0, 4200.0, 4800.0, 6000.0],
        labels! {"handler".to_string() => "all".to_string(),}
    )).unwrap();
}

pub fn new_rpc_call_timer(path: &str) -> HistogramTimer {
    let histogram = RPC_CALL_LATENCIES_HISTOGRAM.with_label_values(&[path]);
    histogram.start_timer()
}