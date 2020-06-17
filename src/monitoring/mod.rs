#[cfg(feature = "monitoring")]
mod prometheus;

pub fn increment_rpc_calls_counter() {
    #[cfg(feature = "monitoring")]
    prometheus::RPC_CALL_COUNTER.inc();    
}

pub fn increment_p2p_control_plan_msg_received_counter() {
    #[cfg(feature = "monitoring")]
    prometheus::P2P_CONTROL_PLAN_MSG_RECEIVED_COUNTER.inc();    
}

pub fn increment_p2p_data_plan_msg_received_counter() {
    #[cfg(feature = "monitoring")]
    prometheus::P2P_DATA_PLAN_MSG_RECEIVED_COUNTER.inc();    
}

pub fn increment_txs_received_counter() {
    #[cfg(feature = "monitoring")]
    prometheus::TXS_RECEIVED_COUNTER.inc();    
}

pub fn increment_btc_blocks_received_counter() {
    #[cfg(feature = "monitoring")]
    prometheus::BTC_BLOCKS_RECEIVED_COUNTER.inc();    
}

pub fn increment_btc_ops_sent_counter() {
    #[cfg(feature = "monitoring")]
    prometheus::BTC_OPS_SENT_COUNTER.inc();    
}

pub fn increment_stx_blocks_processed_counter() {
    #[cfg(feature = "monitoring")]
    prometheus::STX_BLOCKS_PROCESSED_COUNTER.inc();    
}

pub fn increment_stx_blocks_mined_counter() {
    #[cfg(feature = "monitoring")]
    prometheus::STX_BLOCKS_MINED_COUNTER.inc();    
}

pub fn increment_warning_emitted_counter() {
    #[cfg(feature = "monitoring")]
    prometheus::WARNING_EMITTED_COUNTER.inc();    
}

pub fn increment_errors_emitted_counter() {
    #[cfg(feature = "monitoring")]
    prometheus::ERRORS_EMITTED_COUNTER.inc();    
}
