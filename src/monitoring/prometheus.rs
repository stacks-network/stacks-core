use prometheus::IntCounter;

lazy_static! {
    pub static ref RPC_CALL_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_rpc_requests_total",
        "Total number of RPC requests made.",
        labels! {"handler" => "all",}
    )).unwrap();

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
}
