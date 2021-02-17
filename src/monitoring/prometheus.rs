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

use prometheus::{IntCounter, IntCounterVec, IntGauge, IntGaugeVec};

lazy_static! {
    // pub static ref P2P_MSG_UNAUTHENTICATED_HANDSHAKE_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
    //     "stacks_node_p2p_msg_unauthenticated_handshake_received_total",
    //     "Total number of authenticated Handshake messages received.",
    //     labels! {"handler" => "all",}
    // )).unwrap();

    // pub static ref P2P_MSG_AUTHENTICATED_HANDSHAKE_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
    //     "stacks_node_p2p_msg_authenticated_handshake_received_total",
    //     "Total number of authenticated Handshake messages received.",
    //     labels! {"handler" => "all",}
    // )).unwrap();

    // pub static ref P2P_MSG_GET_NEIGHBORS_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
    //     "stacks_node_p2p_msg_get_neighbors_received_total",
    //     "Total number of GetNeighbors messages received.",
    //     labels! {"handler" => "all",}
    // )).unwrap();

    // pub static ref P2P_MSG_GET_BLOCKS_INV_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
    //     "stacks_node_p2p_msg_get_blocks_inv_received_total",
    //     "Total number of GetBlocksInv messages received.",
    //     labels! {"handler" => "all",}
    // )).unwrap();

    // pub static ref P2P_MSG_NACK_SENT_COUNTER: IntCounter = register_int_counter!(opts!(
    //     "stacks_node_p2p_msg_nack_sent_total",
    //     "Total number of Nack messages sent.",
    //     labels! {"handler" => "all",}
    // )).unwrap();

    // pub static ref P2P_MSG_PING_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
    //     "stacks_node_p2p_msg_ping_received_total",
    //     "Total number of Ping messages received.",
    //     labels! {"handler" => "all",}
    // )).unwrap();

    // pub static ref P2P_MSG_NAT_PUNCH_REQUEST_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
    //     "stacks_node_p2p_msg_nat_punch_request_received_total",
    //     "Total number of NatPunchRequest messages received.",
    //     labels! {"handler" => "all",}
    // )).unwrap();

    pub static ref RPC_REQUEST_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_rpc_request_total",
        "Total number of RPC requests made."
    )).unwrap();

    pub static ref STX_BLOCKS_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_blocks_received_total",
        "Total number of Stacks blocks received."
    )).unwrap();

    pub static ref STX_MICRO_BLOCKS_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_micro_blocks_received_total",
        "Total number of Stacks micro blocks received."
    )).unwrap();

    pub static ref STX_BLOCKS_SERVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_blocks_served_total",
        "Total number of Stacks blocks served."
    )).unwrap();

    pub static ref STX_MICRO_BLOCKS_SERVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_micro_blocks_served_total",
        "Total number of Stacks micro blocks served."
    )).unwrap();

    pub static ref STX_CONFIRMED_MICRO_BLOCKS_SERVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_confirmed_micro_blocks_served_total",
        "Total number of Stacks blocks served."
    )).unwrap();

    pub static ref TXS_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_transactions_received_total",
        "Total number of transactions received and relayed."
    )).unwrap();

    pub static ref BTC_BLOCKS_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_btc_blocks_received_total",
        "Total number of blocks processed from the burnchain."
    )).unwrap();

    pub static ref BTC_OPS_SENT_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_btc_ops_sent_total",
        "Total number of ops (key registrations, block commits, user burn supports) submitted to the burnchain."
    )).unwrap();

    pub static ref STX_BLOCKS_PROCESSED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_blocks_processed_total",
        "Total number of stacks blocks processed."
    )).unwrap();

    pub static ref STX_BLOCKS_MINED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_blocks_mined_total",
        "Total number of stacks blocks mined by node."
    )).unwrap();

    pub static ref WARNING_EMITTED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_warning_emitted_total",
        "Total number of warning logs emitted by node."
    )).unwrap();

    pub static ref ERRORS_EMITTED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_errors_emitted_total",
        "Total number of error logs emitted by node."
    )).unwrap();

    pub static ref ACTIVE_MINERS_COUNT_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_active_miners_total",
        "Total number of active miners."
    )).unwrap();

    pub static ref STACKS_TIP_HEIGHT_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_tip_height",
        "Stacks Chain Tip Height"
    )).unwrap();
    
    pub static ref BURNCHAIN_HEIGHT_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_burn_block_height",
        "Burnchain Tip Height"
    )).unwrap();

    pub static ref INBOUND_NEIGHBORS_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_inbound_neighbors",
        "Current Inbound Neighbors"
    )).unwrap();

    pub static ref OUTBOUND_NEIGHBORS_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_outbound_neighbors",
        "Current Outbound Neighbors"
    )).unwrap();

    pub static ref INBOUND_BANDWIDTH_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_inbound_bandwidth",
        "Inbound Bandwidth Total in bytes"
    )).unwrap();
    
    pub static ref OUTBOUND_BANDWIDTH_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_outbound_bandwidth",
        "Outbound Bandwidth Total in bytes"
    )).unwrap();

    pub static ref INBOUND_RPC_BANDWIDTH_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_rpc_inbound_bandwidth",
        "RPC Inbound Bandwidth in bytes"
    )).unwrap();

    pub static ref OUTBOUND_RPC_BANDWIDTH_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_rpc_outbound_bandwidth",
        "RPC Outbound Bandwidth in bytes"
    )).unwrap();

    pub static ref ANCHOR_BLOCK_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_anchor_block",
        "Anchor Block"
    )).unwrap();

    pub static ref REWARD_CYCLES_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_reward_cycles",
        "Reward Cycles"
    )).unwrap();

    pub static ref POX_INV_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_pox_inv",
        "POX Inventory"
    )).unwrap();

    pub static ref MSG_COUNTER_VEC: IntCounterVec = register_int_counter_vec!(
        "stacks_node_messages", 
        "Stacks Node Messages", 
        &["name"]
    ).unwrap();

    pub static ref RPC_REQUEST_COUNTER_VEC: IntCounterVec = register_int_counter_vec!(
        "stacks_node_rpc_requests", 
        "Stacks Node RPC Requests", 
        &["path", "method"]
    ).unwrap();

    pub static ref STX_MEMPOOL_SIZE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_mempool_size",
        "Stacks Node Mempool Size"
    )).unwrap();

    pub static ref STX_MEMPOOL_GC: IntCounter = register_int_counter!(opts!(
        "stacks_node_mempool_gc",
        "Stacks Node Mempool GC Count"
    )).unwrap();

    pub static ref STX_SMART_CONTRACT_COUNT: IntCounter = register_int_counter!(opts!(
        "stacks_node_smart_contracts",
        "Stacks Node Smart Contract Count"
    )).unwrap();

    pub static ref STX_ADDRESSES_CREATED: IntCounter = register_int_counter!(opts!(
        "stacks_node_addresses",
        "Stacks Node Addresses Created Count"
    )).unwrap();

    pub static ref STACK_STX_OP: IntCounter = register_int_counter!(opts!(
        "stacks_node_stack_stx_op",
        "Stacks Node Stack Stx Op Count"
    )).unwrap();

    pub static ref TRANSFER_STX_OP: IntCounter = register_int_counter!(opts!(
        "stacks_node_transfer_stx_op",
        "Stacks Node Transfer Stx Op Count"
    )).unwrap();
}


