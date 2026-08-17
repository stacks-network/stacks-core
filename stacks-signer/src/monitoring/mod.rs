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

use stacks_common::define_named_enum;

#[cfg(feature = "monitoring_prom")]
mod prometheus;

#[cfg(feature = "monitoring_prom")]
mod server;

define_named_enum!(
/// Represent different state change reason on signer agreement protocol
SignerAgreementStateChangeReason {
    /// A new burn block has arrived
    BurnBlockArrival("burn_block_arrival"),
    /// A new stacks block has arrived
    StacksBlockArrival("stacks_block_arrival"),
    /// A miner is inactive when it should be starting its tenure
    InactiveMiner("inactive_miner"),
    /// Signer agreement protocol version has been upgraded
    ProtocolUpgrade("protocol_upgrade"),
    /// An update related to the Miner view
    MinerViewUpdate("miner_view_update"),
    /// A specific Miner View update related to the parent tenure
    MinerParentTenureUpdate("miner_parent_tenure_update"),
});

define_named_enum!(
/// Represent different conflict types on signer agreement protocol
SignerAgreementStateConflict {
    /// Waiting for burn block propagation to be aligned with the signer set
    BurnBlockDelay("burn_block_delay"),
    /// Waiting for stacks block propagation to be aligned with the signer set
    StacksBlockDelay("stacks_block_delay"),
    /// No agreement on miner view with the signer set
    MinerView("miner_view"),
});

/// Actions for updating metrics
#[cfg(feature = "monitoring_prom")]
pub mod actions {
    use ::prometheus::HistogramTimer;
    use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
    use stacks_common::error;

    use crate::config::GlobalConfig;
    use crate::monitoring::prometheus::*;
    use crate::monitoring::{SignerAgreementStateChangeReason, SignerAgreementStateConflict};
    use crate::v0::signer_state::LocalStateMachine;
    use libsigner::v0::signer_state::GlobalStateAgreementSnapshot;

    /// Update stacks tip height gauge
    pub fn update_stacks_tip_height(height: i64) {
        STACKS_TIP_HEIGHT_GAUGE.set(height);
    }

    /// Update the current reward cycle
    pub fn update_reward_cycle(reward_cycle: i64) {
        CURRENT_REWARD_CYCLE.set(reward_cycle);
    }

    /// Record whether the outer signer runloop has initialized successfully.
    pub fn update_runloop_ready(ready: bool) {
        SIGNER_RUNLOOP_READY.set(i64::from(ready));
    }

    /// Record whether this process can participate in the current and next
    /// reward cycles. Runloop initialization alone does not imply either.
    pub fn update_reward_cycle_registration(current: bool, next: bool) {
        SIGNER_REGISTERED_CURRENT_REWARD_CYCLE.set(i64::from(current));
        SIGNER_REGISTERED_NEXT_REWARD_CYCLE.set(i64::from(next));
    }

    /// Record the current signer's local agreement state and pending backlog.
    pub fn update_signer_state(
        burn_block_height: Option<u64>,
        last_changed_timestamp_seconds: Option<u64>,
        pending_block_validations: u64,
    ) {
        SIGNER_STATE_BURN_BLOCK_HEIGHT.set(
            burn_block_height
                .and_then(|height| i64::try_from(height).ok())
                .unwrap_or_default(),
        );
        SIGNER_STATE_LAST_CHANGED_TIMESTAMP_SECONDS.set(
            last_changed_timestamp_seconds
                .and_then(|timestamp| i64::try_from(timestamp).ok())
                .unwrap_or_default(),
        );
        SIGNER_PENDING_BLOCK_VALIDATIONS
            .set(i64::try_from(pending_block_validations).unwrap_or(i64::MAX));
    }

    /// Record a canonical burn height learned successfully from the companion.
    pub fn update_companion_burn_block_height(burn_block_height: u64) {
        SIGNER_COMPANION_BURN_BLOCK_HEIGHT
            .set(i64::try_from(burn_block_height).unwrap_or(i64::MAX));
    }

    /// Increment the block validation responses counter
    pub fn increment_block_validation_responses(accepted: bool) {
        let label_value = if accepted { "accepted" } else { "rejected" };
        BLOCK_VALIDATION_RESPONSES
            .with_label_values(&[label_value])
            .inc();
    }

    /// Increment the block responses sent counter
    pub fn increment_block_responses_sent(accepted: bool) {
        let label_value = if accepted { "accepted" } else { "rejected" };
        BLOCK_RESPONSES_SENT.with_label_values(&[label_value]).inc();
    }

    /// Increment the number of block proposals received
    pub fn increment_block_proposals_received() {
        BLOCK_PROPOSALS_RECEIVED.inc();
    }

    /// Increment the block pre-commit sent counter
    pub fn increment_block_pre_commits_sent() {
        BLOCK_PRE_COMMITS_SENT.inc();
    }

    /// Update the stx balance of the signer
    pub fn update_signer_stx_balance(balance: i64) {
        SIGNER_STX_BALANCE.set(balance);
    }

    /// Update the signer nonce metric
    pub fn update_signer_nonce(nonce: u64) {
        SIGNER_NONCE.set(nonce as i64);
    }

    /// Start a new RPC call timer.
    /// The `origin` parameter is the base path of the RPC call, e.g. `http://node.com`.
    /// The `origin` parameter is removed from `full_path` when storing in prometheus.
    pub fn new_rpc_call_timer(full_path: &str, origin: &str) -> HistogramTimer {
        let path = super::remove_origin_from_path(full_path, origin);
        let histogram = SIGNER_RPC_CALL_LATENCIES_HISTOGRAM.with_label_values(&[&path]);
        histogram.start_timer()
    }

    /// Record the time taken to issue a block response for
    /// a given block. The block's timestamp is used to calculate the latency.
    ///
    /// Call this right after broadcasting a BlockResponse
    pub fn record_block_response_latency(block: &NakamotoBlock) {
        use clarity::util::get_epoch_time_ms;

        let diff =
            get_epoch_time_ms().saturating_sub(block.header.timestamp.saturating_mul(1000).into());
        SIGNER_BLOCK_RESPONSE_LATENCIES_HISTOGRAM
            .with_label_values(&[])
            .observe(diff as f64 / 1000.0);
    }

    /// Record the time taken to validate a block, as reported by the Stacks node.
    pub fn record_block_validation_latency(latency_ms: u64) {
        SIGNER_BLOCK_VALIDATION_LATENCIES_HISTOGRAM
            .with_label_values(&[])
            .observe(latency_ms as f64 / 1000.0);
    }

    /// Record the current local state machine
    pub fn record_local_state(state: LocalStateMachine) {
        SIGNER_LOCAL_STATE_MACHINE
            .lock()
            .expect("Local state machine lock poisoned")
            .replace(state);
    }

    /// Increment signer agreement state change reason counter
    pub fn increment_signer_agreement_state_change_reason(
        reason: SignerAgreementStateChangeReason,
    ) {
        let label_value = reason.get_name();
        SIGNER_AGREEMENT_STATE_CHANGE_REASONS
            .with_label_values(&[&label_value])
            .inc();
    }

    /// Increment signer agreement state conflict counter
    pub fn increment_signer_agreement_state_conflict(conflict: SignerAgreementStateConflict) {
        let label_value = conflict.get_name();
        SIGNER_AGREEMENT_STATE_CONFLICTS
            .with_label_values(&[&label_value])
            .inc();
    }

    /// Record the current reward-cycle global-state support. Values are kept
    /// as separate bounded gauges so a lifecycle gate can fail closed without
    /// inferring agreement from proposal/rejection counters.
    pub fn update_global_state_agreement(snapshot: GlobalStateAgreementSnapshot) {
        SIGNER_GLOBAL_STATE_AVAILABLE.set(i64::from(snapshot.global_state_available));
        SIGNER_GLOBAL_STATE_TOTAL_WEIGHT.set(i64::from(snapshot.total_weight));
        SIGNER_GLOBAL_STATE_KNOWN_WEIGHT.set(i64::from(snapshot.known_weight));
        SIGNER_GLOBAL_STATE_MAXIMUM_VIEW_WEIGHT.set(i64::from(snapshot.maximum_state_view_weight));
        SIGNER_GLOBAL_STATE_EVALUATOR_THRESHOLD_WEIGHT
            .set(i64::from(snapshot.evaluator_threshold_weight));
        SIGNER_GLOBAL_STATE_CANONICAL_THRESHOLD_WEIGHT
            .set(i64::from(snapshot.canonical_threshold_weight));
    }

    /// Record the time (seconds) taken for a signer to agree with the signer set
    pub fn record_signer_agreement_capitulation_latency(latency_s: u64) {
        SIGNER_AGREEMENT_CAPITULATION_LATENCIES_HISTOGRAM
            .with_label_values(&[])
            .observe(latency_s as f64);
    }

    /// Start serving monitoring metrics.
    /// This will only serve the metrics if the `monitoring_prom` feature is enabled.
    pub fn start_serving_monitoring_metrics(config: GlobalConfig) -> Result<(), String> {
        if config.metrics_endpoint.is_none() {
            return Ok(());
        }
        let _ = std::thread::Builder::new()
            .name("signer_metrics".to_string())
            .spawn(move || {
                if let Err(monitoring_err) = super::server::MonitoringServer::start(&config) {
                    error!("Monitoring: Error in metrics server: {:?}", monitoring_err);
                }
            });
        Ok(())
    }
}

/// No-op actions for updating metrics
#[cfg(not(feature = "monitoring_prom"))]
pub mod actions {
    use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
    use stacks_common::info;

    use crate::monitoring::{SignerAgreementStateChangeReason, SignerAgreementStateConflict};
    use crate::v0::signer_state::LocalStateMachine;
    use crate::GlobalConfig;

    /// Update stacks tip height gauge
    pub fn update_stacks_tip_height(_height: i64) {}

    /// Update the current reward cycle
    pub fn update_reward_cycle(_reward_cycle: i64) {}

    /// No-op runloop readiness metric when Prometheus is disabled.
    pub fn update_runloop_ready(_ready: bool) {}

    /// No-op reward-cycle registration metrics when Prometheus is disabled.
    pub fn update_reward_cycle_registration(_current: bool, _next: bool) {}

    /// No-op local signer state metrics when Prometheus is disabled.
    pub fn update_signer_state(
        _burn_block_height: Option<u64>,
        _last_changed_timestamp_seconds: Option<u64>,
        _pending_block_validations: u64,
    ) {
    }

    /// No-op companion burn height metric when Prometheus is disabled.
    pub fn update_companion_burn_block_height(_burn_block_height: u64) {}

    /// Increment the block validation responses counter
    pub fn increment_block_validation_responses(_accepted: bool) {}

    /// Increment the block responses sent counter
    pub fn increment_block_responses_sent(_accepted: bool) {}

    /// Increment the number of block proposals received
    pub fn increment_block_proposals_received() {}

    /// Increment the block pre-commits sent counter
    pub fn increment_block_pre_commits_sent() {}

    /// Update the stx balance of the signer
    pub fn update_signer_stx_balance(_balance: i64) {}

    /// Update the signer nonce metric
    pub fn update_signer_nonce(_nonce: u64) {}

    /// NoOp timer uses for monitoring when the monitoring feature is not enabled.
    pub struct NoOpTimer;
    impl NoOpTimer {
        /// NoOp method to stop recording when the monitoring feature is not enabled.
        pub fn stop_and_record(&self) {}
    }

    /// Stop and record the no-op timer.
    pub fn new_rpc_call_timer(_full_path: &str, _origin: &str) -> NoOpTimer {
        NoOpTimer
    }

    /// Record the time taken to issue a block response for
    /// a given block. The block's timestamp is used to calculate the latency.
    ///
    /// Call this right after broadcasting a BlockResponse
    pub fn record_block_response_latency(_block: &NakamotoBlock) {}

    /// Record the time taken to validate a block, as reported by the Stacks node.
    pub fn record_block_validation_latency(_latency_ms: u64) {}

    /// Record the current local state machine
    pub fn record_local_state(_state: LocalStateMachine) {}

    /// Increment signer agreement state change reason counter
    pub fn increment_signer_agreement_state_change_reason(
        _reason: SignerAgreementStateChangeReason,
    ) {
    }

    /// Increment signer agreement state conflict counter
    pub fn increment_signer_agreement_state_conflict(_conflict: SignerAgreementStateConflict) {}

    /// No-op global state support metrics when Prometheus is disabled.
    pub fn update_global_state_agreement(
        _snapshot: libsigner::v0::signer_state::GlobalStateAgreementSnapshot,
    ) {
    }

    /// Record the time (seconds) taken for a signer to agree with the signer set
    pub fn record_signer_agreement_capitulation_latency(_latency_s: u64) {}

    /// Start serving monitoring metrics.
    /// This will only serve the metrics if the `monitoring_prom` feature is enabled.
    pub fn start_serving_monitoring_metrics(config: GlobalConfig) -> Result<(), String> {
        if config.metrics_endpoint.is_some() {
            info!("`metrics_endpoint` is configured for the signer, but the monitoring_prom feature is not enabled. Not starting monitoring metrics server.");
        }
        Ok(())
    }
}

// Allow dead code because this is only used in the `monitoring_prom` feature
// but we want to run it in a test
#[allow(dead_code)]
/// Remove the origin from the full path to avoid duplicate metrics for different origins
fn remove_origin_from_path(full_path: &str, origin: &str) -> String {
    full_path.replace(origin, "")
}

#[test]
fn test_remove_origin_from_path() {
    let full_path = "http://localhost:20443/v2/info";
    let origin = "http://localhost:20443";
    let path = remove_origin_from_path(full_path, origin);
    assert_eq!(path, "/v2/info");

    let full_path = "/v2/info";
    let origin = "http://localhost:20443";
    let path = remove_origin_from_path(full_path, origin);
    assert_eq!(path, "/v2/info");
}

#[cfg(all(test, feature = "monitoring_prom"))]
#[test]
fn lifecycle_metrics_export_bounded_gauges() {
    actions::update_runloop_ready(true);
    actions::update_reward_cycle_registration(true, false);
    actions::update_signer_state(Some(123), Some(456), 7);
    actions::update_companion_burn_block_height(125);

    assert_eq!(prometheus::SIGNER_RUNLOOP_READY.get(), 1);
    assert_eq!(prometheus::SIGNER_REGISTERED_CURRENT_REWARD_CYCLE.get(), 1);
    assert_eq!(prometheus::SIGNER_REGISTERED_NEXT_REWARD_CYCLE.get(), 0);
    assert_eq!(prometheus::SIGNER_STATE_BURN_BLOCK_HEIGHT.get(), 123);
    assert_eq!(
        prometheus::SIGNER_STATE_LAST_CHANGED_TIMESTAMP_SECONDS.get(),
        456
    );
    assert_eq!(prometheus::SIGNER_PENDING_BLOCK_VALIDATIONS.get(), 7);
    assert_eq!(prometheus::SIGNER_COMPANION_BURN_BLOCK_HEIGHT.get(), 125);

    let exposition = prometheus::gather_metrics_string();
    for metric in [
        "stacks_signer_runloop_ready",
        "stacks_signer_registered_for_current_reward_cycle",
        "stacks_signer_registered_for_next_reward_cycle",
        "stacks_signer_state_burn_block_height",
        "stacks_signer_state_last_changed_timestamp_seconds",
        "stacks_signer_companion_burn_block_height",
        "stacks_signer_pending_block_validations",
    ] {
        assert!(exposition.contains(metric), "missing metric {metric}");
    }
}
