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

#[cfg(feature = "monitoring_prom")]
use ::prometheus::HistogramTimer;
#[cfg(feature = "monitoring_prom")]
use slog::slog_error;
#[cfg(not(feature = "monitoring_prom"))]
use slog::slog_warn;
#[cfg(feature = "monitoring_prom")]
use stacks_common::error;
#[cfg(not(feature = "monitoring_prom"))]
use stacks_common::warn;

use crate::config::GlobalConfig;

#[cfg(feature = "monitoring_prom")]
mod prometheus;

#[cfg(feature = "monitoring_prom")]
mod server;

/// Update stacks tip height gauge
#[allow(unused_variables)]
pub fn update_stacks_tip_height(height: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STACKS_TIP_HEIGHT_GAUGE.set(height);
}

/// Update the current reward cycle
#[allow(unused_variables)]
pub fn update_reward_cycle(reward_cycle: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::CURRENT_REWARD_CYCLE.set(reward_cycle);
}

/// Increment the block validation responses counter
#[allow(unused_variables)]
pub fn increment_block_validation_responses(accepted: bool) {
    #[cfg(feature = "monitoring_prom")]
    {
        let label_value = if accepted { "accepted" } else { "rejected" };
        prometheus::BLOCK_VALIDATION_RESPONSES
            .with_label_values(&[label_value])
            .inc();
    }
}

/// Increment the block responses sent counter
#[allow(unused_variables)]
pub fn increment_block_responses_sent(accepted: bool) {
    #[cfg(feature = "monitoring_prom")]
    {
        let label_value = if accepted { "accepted" } else { "rejected" };
        prometheus::BLOCK_RESPONSES_SENT
            .with_label_values(&[label_value])
            .inc();
    }
}

/// Increment the signer inbound messages counter
#[allow(unused_variables)]
pub fn increment_signer_inbound_messages(amount: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::SIGNER_INBOUND_MESSAGES.inc_by(amount);
}

/// Increment the coordinator inbound messages counter
#[allow(unused_variables)]
pub fn increment_coordinator_inbound_messages(amount: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::COORDINATOR_INBOUND_MESSAGES.inc_by(amount);
}

/// Increment the number of inbound packets received
#[allow(unused_variables)]
pub fn increment_inbound_packets(amount: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::INBOUND_PACKETS_RECEIVED.inc_by(amount);
}

/// Increment the number of commands processed
#[allow(unused_variables)]
pub fn increment_commands_processed(command_type: &str) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::COMMANDS_PROCESSED
        .with_label_values(&[command_type])
        .inc();
}

/// Increment the number of DKG votes submitted
#[allow(unused_variables)]
pub fn increment_dkg_votes_submitted() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::DGK_VOTES_SUBMITTED.inc();
}

/// Increment the number of commands processed
#[allow(unused_variables)]
pub fn increment_operation_results(operation_type: &str) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::OPERATION_RESULTS
        .with_label_values(&[operation_type])
        .inc();
}

/// Increment the number of block proposals received
#[allow(unused_variables)]
pub fn increment_block_proposals_received() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::BLOCK_PROPOSALS_RECEIVED.inc();
}

/// Update the stx balance of the signer
#[allow(unused_variables)]
pub fn update_signer_stx_balance(balance: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::SIGNER_STX_BALANCE.set(balance);
}

/// Update the signer nonce metric
#[allow(unused_variables)]
pub fn update_signer_nonce(nonce: u64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::SIGNER_NONCE.set(nonce as i64);
}

/// Start a new RPC call timer.
/// The `origin` parameter is the base path of the RPC call, e.g. `http://node.com`.
/// The `origin` parameter is removed from `full_path` when storing in prometheus.
#[cfg(feature = "monitoring_prom")]
pub fn new_rpc_call_timer(full_path: &str, origin: &str) -> HistogramTimer {
    let path = &full_path[origin.len()..];
    let histogram = prometheus::SIGNER_RPC_CALL_LATENCIES_HISTOGRAM.with_label_values(&[path]);
    histogram.start_timer()
}

/// NoOp timer uses for monitoring when the monitoring feature is not enabled.
pub struct NoOpTimer;
impl NoOpTimer {
    /// NoOp method to stop recording when the monitoring feature is not enabled.
    pub fn stop_and_record(&self) {}
}

/// Stop and record the no-op timer.
#[cfg(not(feature = "monitoring_prom"))]
pub fn new_rpc_call_timer(_full_path: &str, _origin: &str) -> NoOpTimer {
    NoOpTimer
}

/// Start serving monitoring metrics.
/// This will only serve the metrics if the `monitoring_prom` feature is enabled.
#[allow(unused_variables)]
pub fn start_serving_monitoring_metrics(config: GlobalConfig) -> Result<(), String> {
    #[cfg(feature = "monitoring_prom")]
    {
        if config.metrics_endpoint.is_none() {
            return Ok(());
        }
        let thread = std::thread::Builder::new()
            .name("signer_metrics".to_string())
            .spawn(move || {
                if let Err(monitoring_err) = server::MonitoringServer::start(&config) {
                    error!("Monitoring: Error in metrics server: {:?}", monitoring_err);
                }
            });
    }
    #[cfg(not(feature = "monitoring_prom"))]
    {
        if config.metrics_endpoint.is_some() {
            warn!("Not starting monitoring metrics server as the monitoring_prom feature is not enabled");
        }
    }
    Ok(())
}
