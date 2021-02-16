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

#[cfg(feature = "monitoring_prom")]
mod prometheus;

pub fn increment_rpc_calls_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::RPC_CALL_COUNTER.inc();
}

// pub fn increment_p2p_msg_unauthenticated_handshake_received_counter() {
//     #[cfg(feature = "monitoring_prom")]
//     prometheus::P2P_MSG_UNAUTHENTICATED_HANDSHAKE_RECEIVED_COUNTER.inc();
// }

// pub fn increment_p2p_msg_authenticated_handshake_received_counter() {
//     #[cfg(feature = "monitoring_prom")]
//     prometheus::P2P_MSG_AUTHENTICATED_HANDSHAKE_RECEIVED_COUNTER.inc();
// }

// pub fn increment_p2p_msg_get_neighbors_received_counter() {
//     #[cfg(feature = "monitoring_prom")]
//     prometheus::P2P_MSG_GET_NEIGHBORS_RECEIVED_COUNTER.inc();
// }

// pub fn increment_p2p_msg_get_blocks_inv_received_counter() {
//     #[cfg(feature = "monitoring_prom")]
//     prometheus::P2P_MSG_GET_BLOCKS_INV_RECEIVED_COUNTER.inc();
// }

// pub fn increment_p2p_msg_nack_sent_counter() {
//     #[cfg(feature = "monitoring_prom")]
//     prometheus::P2P_MSG_NACK_SENT_COUNTER.inc();
// }

// pub fn increment_p2p_msg_ping_received_counter() {
//     #[cfg(feature = "monitoring_prom")]
//     prometheus::P2P_MSG_PING_RECEIVED_COUNTER.inc();
// }

// pub fn increment_p2p_msg_nat_punch_request_received_counter() {
//     #[cfg(feature = "monitoring_prom")]
//     prometheus::P2P_MSG_NAT_PUNCH_REQUEST_RECEIVED_COUNTER.inc();
// }

pub fn increment_stx_blocks_received_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_BLOCKS_RECEIVED_COUNTER.inc();
}

pub fn increment_stx_micro_blocks_received_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_MICRO_BLOCKS_RECEIVED_COUNTER.inc();
}

pub fn increment_stx_blocks_served_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_BLOCKS_SERVED_COUNTER.inc();
}

pub fn increment_stx_micro_blocks_served_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_MICRO_BLOCKS_SERVED_COUNTER.inc();
}

pub fn increment_stx_confirmed_micro_blocks_served_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_CONFIRMED_MICRO_BLOCKS_SERVED_COUNTER.inc();
}

pub fn increment_txs_received_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::TXS_RECEIVED_COUNTER.inc();
}

pub fn increment_btc_blocks_received_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::BTC_BLOCKS_RECEIVED_COUNTER.inc();
}

pub fn increment_btc_ops_sent_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::BTC_OPS_SENT_COUNTER.inc();
}

pub fn increment_stx_blocks_processed_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_BLOCKS_PROCESSED_COUNTER.inc();
}

pub fn increment_stx_blocks_mined_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_BLOCKS_MINED_COUNTER.inc();
}

pub fn increment_warning_emitted_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::WARNING_EMITTED_COUNTER.inc();
}

pub fn increment_errors_emitted_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::ERRORS_EMITTED_COUNTER.inc();
}

#[allow(unused_variables)]
pub fn update_active_miners_count_gauge(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::ACTIVE_MINERS_COUNT_GAUGE.set(value);
}

pub fn update_stacks_tip_height(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STACKS_TIP_HEIGHT_GAUGE.set(value);
}

pub fn update_burnchain_height(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::BURNCHAIN_HEIGHT_GAUGE.set(value);
}

pub fn update_inbound_neighbors(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::INBOUND_NEIGHBORS_GAUGE.set(value);
}

pub fn update_outbound_neighbors(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::OUTBOUND_NEIGHBORS_GAUGE.set(value);
}

pub fn update_inbound_bandwidth(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::INBOUND_BANDWIDTH_GAUGE.add(value);
}
pub fn update_outbound_bandwidth(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::OUTBOUND_BANDWIDTH_GAUGE.add(value);
}

// pub fn update_inbound_bandwidth(name: String, value: i64) {
//     #[cfg(feature = "monitoring_prom")]
//     prometheus::INBOUND_BANDWIDTH_GAUGE.with_label_values(&[&name]).add(value);
// }

// pub fn update_outbound_bandwidth(name: String, value: i64) {
//     #[cfg(feature = "monitoring_prom")]
//     prometheus::OUTBOUND_BANDWIDTH_GAUGE.with_label_values(&[&name]).add(value);
// }

pub fn update_inbound_rpc_bandwidth(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::INBOUND_RPC_BANDWIDTH_GAUGE.add(value);
}

pub fn update_outbound_rpc_bandwidth(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::OUTBOUND_RPC_BANDWIDTH_GAUGE.add(value);
}

pub fn update_anchor_block(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::ANCHOR_BLOCK_GAUGE.set(value);
}

pub fn update_reward_cycle(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::REWARD_CYCLES_GAUGE.set(value);
}

pub fn update_pox_inv(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::POX_INV_GAUGE.set(value);
}

pub fn increment_msg_counter(name: String) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::MSG_COUNTER_VEC.with_label_values(&[&name]).inc();
}

pub fn increment_rpc_request_counter(path: String, method: String) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::RPC_REQUEST_COUNTER_VEC.with_label_values(&[&path, &method]).inc();
}

// first_burnchain_block_height
pub fn update_pox_first_burnchain_block(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::POX_FIRST_BURNCHAIN_BLOCK.set(value);
}
// first_burnchain_block_height
pub fn update_pox_reward_cycle_countdown(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::POX_REWARD_CYCLE_COUNTDOWN.set(value);
}
// first_burnchain_block_height
pub fn update_pox_reward_cycle_length(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::POX_REWARD_CYCLE_LENGTH.set(value);
}
