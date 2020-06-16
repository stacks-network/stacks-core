use prometheus::{IntCounter, Gauge, HistogramVec, TextEncoder};

lazy_static! {
    pub static ref RPC_CALL_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_rpc_requests_total",
        "Total number of RPC requests made.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref P2P_CONTROL_PLAN_MSG_SENT_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_p2p_control_plan_msg_sent_total",
        "Total number of messages sent to p2p control plan.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref P2P_CONTROL_PLAN_MSG_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_p2p_control_plan_msg_received_total",
        "Total number of messages received from p2p control plan.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref P2P_DATA_PLAN_MSG_SENT_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_p2p_data_plan_msg_sent_total",
        "Total number of messages sent to p2p data plan.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref P2P_DATA_PLAN_MSG_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_p2p_data_plan_msg_received_total",
        "Total number of messages received from p2p data plan.",
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
