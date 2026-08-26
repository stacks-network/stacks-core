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

use blockstack_lib::net::api::postblock_proposal::ValidateRejectCode;
#[cfg(feature = "monitoring_prom")]
use libsigner::v0::messages::RejectReason;
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

/// The finite epistemic classification of a proposal-policy evaluation.
#[cfg(feature = "monitoring_prom")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyClassification {
    /// Policy passed and companion validation may proceed.
    Proceed,
    /// Policy produced a validity verdict.
    VerdictReject,
    /// Policy could not produce a validity verdict.
    Unavailable,
}

#[cfg(feature = "monitoring_prom")]
impl PolicyClassification {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Proceed => "proceed",
            Self::VerdictReject => "verdict_reject",
            Self::Unavailable => "unavailable",
        }
    }
}

/// The effective action taken by current signer policy.
#[cfg(feature = "monitoring_prom")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyAction {
    /// Continue toward companion validation.
    Continue,
    /// Emit a rejection.
    Reject,
}

#[cfg(feature = "monitoring_prom")]
impl PolicyAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::Reject => "reject",
        }
    }
}

/// A finite block-validation lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationLifecycleEvent {
    /// Submission to the companion succeeded.
    Submitted,
    /// A queued validation is being attempted again.
    Retried,
    /// The companion accepted the proposal.
    Accepted,
    /// The companion rejected the proposal with a bounded code.
    Rejected(ValidateRejectCode),
    /// The submitted validation exceeded its response deadline.
    Expired,
}

impl ValidationLifecycleEvent {
    #[cfg(feature = "monitoring_prom")]
    fn labels(self) -> (&'static str, &'static str) {
        match self {
            Self::Submitted => ("submitted", "none"),
            Self::Retried => ("retried", "none"),
            Self::Accepted => ("accepted", "none"),
            Self::Rejected(code) => ("rejected", validate_reject_code_label(code)),
            Self::Expired => ("expired", "none"),
        }
    }
}

#[cfg(feature = "monitoring_prom")]
fn policy_classification(reason: Option<&RejectReason>) -> (PolicyClassification, PolicyAction) {
    match reason {
        None => (PolicyClassification::Proceed, PolicyAction::Continue),
        Some(
            RejectReason::ConnectivityIssues(_)
            | RejectReason::NoSortitionView
            | RejectReason::NoSignerConsensus,
        ) => (PolicyClassification::Unavailable, PolicyAction::Reject),
        Some(_) => (PolicyClassification::VerdictReject, PolicyAction::Reject),
    }
}

#[cfg(feature = "monitoring_prom")]
fn reject_reason_label(reason: &RejectReason) -> &'static str {
    match reason {
        RejectReason::ValidationFailed(_) => "validation_failed",
        RejectReason::ConnectivityIssues(_) => "connectivity_issues",
        RejectReason::RejectedInPriorRound => "rejected_in_prior_round",
        RejectReason::NoSortitionView => "no_sortition_view",
        RejectReason::SortitionViewMismatch => "sortition_view_mismatch",
        RejectReason::TestingDirective => "testing_directive",
        RejectReason::ReorgNotAllowed => "reorg_not_allowed",
        RejectReason::InvalidBitvec => "invalid_bitvec",
        RejectReason::PubkeyHashMismatch => "pubkey_hash_mismatch",
        RejectReason::InvalidMiner => "invalid_miner",
        RejectReason::NotLatestSortitionWinner => "not_latest_sortition_winner",
        RejectReason::InvalidParentBlock => "invalid_parent_block",
        RejectReason::DuplicateBlockFound => "duplicate_block_found",
        RejectReason::InvalidTenureExtend => "invalid_tenure_extend",
        RejectReason::IrrecoverablePubkeyHash => "irrecoverable_pubkey_hash",
        RejectReason::NoSignerConsensus => "no_signer_consensus",
        RejectReason::ConsensusHashMismatch { .. } => "consensus_hash_mismatch",
        RejectReason::ProblematicTransactions => "problematic_transactions",
        RejectReason::Unknown(_) => "unknown",
        RejectReason::NotRejected => "not_rejected",
    }
}

#[cfg(feature = "monitoring_prom")]
const fn validate_reject_code_label(code: ValidateRejectCode) -> &'static str {
    match code {
        ValidateRejectCode::BadBlockHash => "bad_block_hash",
        ValidateRejectCode::BadTransaction => "bad_transaction",
        ValidateRejectCode::InvalidBlock => "invalid_block",
        ValidateRejectCode::ChainstateError => "chainstate_error",
        ValidateRejectCode::UnknownParent => "unknown_parent",
        ValidateRejectCode::NonCanonicalTenure => "non_canonical_tenure",
        ValidateRejectCode::NoSuchTenure => "no_such_tenure",
        ValidateRejectCode::InvalidTransactionReplay => "invalid_transaction_replay",
        ValidateRejectCode::InvalidParentBlock => "invalid_parent_block",
        ValidateRejectCode::InvalidTimestamp => "invalid_timestamp",
        ValidateRejectCode::NetworkChainMismatch => "network_chain_mismatch",
        ValidateRejectCode::NotFoundError => "not_found_error",
        ValidateRejectCode::ProblematicTransaction => "problematic_transaction",
    }
}

/// Actions for updating metrics
#[cfg(feature = "monitoring_prom")]
pub mod actions {
    use ::prometheus::HistogramTimer;
    use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
    use libsigner::v0::messages::RejectReason;
    use stacks_common::error;

    use crate::config::GlobalConfig;
    use crate::monitoring::prometheus::*;
    use crate::monitoring::{
        policy_classification, reject_reason_label, SignerAgreementStateChangeReason,
        SignerAgreementStateConflict, ValidationLifecycleEvent,
    };
    use crate::v0::signer_state::LocalStateMachine;

    /// Update stacks tip height gauge
    pub fn update_stacks_tip_height(height: i64) {
        STACKS_TIP_HEIGHT_GAUGE.set(height);
    }

    /// Update the current reward cycle
    pub fn update_reward_cycle(reward_cycle: i64) {
        CURRENT_REWARD_CYCLE.set(reward_cycle);
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

    /// Record the proposal policy's epistemic classification separately from
    /// the action taken by the current protocol implementation.
    pub fn record_policy_evaluation(reason: Option<&RejectReason>) {
        let (classification, action) = policy_classification(reason);
        POLICY_EVALUATIONS
            .with_label_values(&[classification.as_str(), action.as_str()])
            .inc();
        if let Some(reason) = reason {
            POLICY_REJECTIONS
                .with_label_values(&[reject_reason_label(reason)])
                .inc();
        }
    }

    /// Record a block-validation lifecycle transition.
    pub fn record_validation_lifecycle(event: ValidationLifecycleEvent) {
        let (event, reason) = event.labels();
        BLOCK_VALIDATION_LIFECYCLE
            .with_label_values(&[event, reason])
            .inc();
    }

    /// Record whether a final signer response was delivered to StackerDB.
    pub fn record_block_response_delivery(accepted: bool, delivered: bool) {
        let response_type = if accepted { "accepted" } else { "rejected" };
        let outcome = if delivered { "sent" } else { "failed" };
        BLOCK_RESPONSE_DELIVERIES
            .with_label_values(&[response_type, outcome])
            .inc();
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
    use libsigner::v0::messages::RejectReason;
    use stacks_common::info;

    use crate::monitoring::{
        SignerAgreementStateChangeReason, SignerAgreementStateConflict, ValidationLifecycleEvent,
    };
    use crate::v0::signer_state::LocalStateMachine;
    use crate::GlobalConfig;

    /// Update stacks tip height gauge
    pub fn update_stacks_tip_height(_height: i64) {}

    /// Update the current reward cycle
    pub fn update_reward_cycle(_reward_cycle: i64) {}

    /// Increment the block validation responses counter
    pub fn increment_block_validation_responses(_accepted: bool) {}

    /// Increment the block responses sent counter
    pub fn increment_block_responses_sent(_accepted: bool) {}

    /// Increment the number of block proposals received
    pub fn increment_block_proposals_received() {}

    /// No-op proposal-policy evaluation recorder.
    pub fn record_policy_evaluation(_reason: Option<&RejectReason>) {}

    /// No-op block-validation lifecycle recorder.
    pub fn record_validation_lifecycle(_event: ValidationLifecycleEvent) {}

    /// No-op final response-delivery recorder.
    pub fn record_block_response_delivery(_accepted: bool, _delivered: bool) {}

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
mod tests {
    use blockstack_lib::net::api::postblock_proposal::ValidateRejectCode;
    use libsigner::v0::messages::RejectReason;

    use super::actions::{
        record_block_response_delivery, record_policy_evaluation, record_validation_lifecycle,
    };
    use super::prometheus::{
        BLOCK_RESPONSE_DELIVERIES, BLOCK_VALIDATION_LIFECYCLE, POLICY_EVALUATIONS,
        POLICY_REJECTIONS,
    };
    use super::{
        policy_classification, validate_reject_code_label, PolicyAction, PolicyClassification,
        ValidationLifecycleEvent,
    };

    #[test]
    fn proposal_outcome_metrics_use_bounded_truthful_labels() {
        assert_eq!(
            policy_classification(None),
            (PolicyClassification::Proceed, PolicyAction::Continue)
        );
        assert_eq!(
            policy_classification(Some(&RejectReason::ConnectivityIssues(
                "arbitrary RPC text must not become a label".into()
            ))),
            (PolicyClassification::Unavailable, PolicyAction::Reject)
        );
        assert_eq!(
            policy_classification(Some(&RejectReason::InvalidTenureExtend)),
            (PolicyClassification::VerdictReject, PolicyAction::Reject)
        );

        let proceed = POLICY_EVALUATIONS.with_label_values(&["proceed", "continue"]);
        let unavailable = POLICY_EVALUATIONS.with_label_values(&["unavailable", "reject"]);
        let verdict = POLICY_EVALUATIONS.with_label_values(&["verdict_reject", "reject"]);
        let connectivity = POLICY_REJECTIONS.with_label_values(&["connectivity_issues"]);
        let invalid_tenure = POLICY_REJECTIONS.with_label_values(&["invalid_tenure_extend"]);
        let before = (
            proceed.get(),
            unavailable.get(),
            verdict.get(),
            connectivity.get(),
            invalid_tenure.get(),
        );

        record_policy_evaluation(None);
        record_policy_evaluation(Some(&RejectReason::ConnectivityIssues("first".into())));
        record_policy_evaluation(Some(&RejectReason::ConnectivityIssues("second".into())));
        record_policy_evaluation(Some(&RejectReason::InvalidTenureExtend));

        assert_eq!(proceed.get(), before.0 + 1);
        assert_eq!(unavailable.get(), before.1 + 2);
        assert_eq!(verdict.get(), before.2 + 1);
        assert_eq!(connectivity.get(), before.3 + 2);
        assert_eq!(invalid_tenure.get(), before.4 + 1);

        let submitted = BLOCK_VALIDATION_LIFECYCLE.with_label_values(&["submitted", "none"]);
        let rejected =
            BLOCK_VALIDATION_LIFECYCLE.with_label_values(&["rejected", "invalid_parent_block"]);
        let submitted_before = submitted.get();
        let rejected_before = rejected.get();
        record_validation_lifecycle(ValidationLifecycleEvent::Submitted);
        record_validation_lifecycle(ValidationLifecycleEvent::Rejected(
            ValidateRejectCode::InvalidParentBlock,
        ));
        assert_eq!(submitted.get(), submitted_before + 1);
        assert_eq!(rejected.get(), rejected_before + 1);

        let sent = BLOCK_RESPONSE_DELIVERIES.with_label_values(&["accepted", "sent"]);
        let failed = BLOCK_RESPONSE_DELIVERIES.with_label_values(&["accepted", "failed"]);
        let sent_before = sent.get();
        let failed_before = failed.get();
        record_block_response_delivery(true, true);
        record_block_response_delivery(true, false);
        assert_eq!(sent.get(), sent_before + 1);
        assert_eq!(failed.get(), failed_before + 1);

        let validation_labels = [
            (ValidateRejectCode::BadBlockHash, "bad_block_hash"),
            (ValidateRejectCode::BadTransaction, "bad_transaction"),
            (ValidateRejectCode::InvalidBlock, "invalid_block"),
            (ValidateRejectCode::ChainstateError, "chainstate_error"),
            (ValidateRejectCode::UnknownParent, "unknown_parent"),
            (
                ValidateRejectCode::NonCanonicalTenure,
                "non_canonical_tenure",
            ),
            (ValidateRejectCode::NoSuchTenure, "no_such_tenure"),
            (
                ValidateRejectCode::InvalidTransactionReplay,
                "invalid_transaction_replay",
            ),
            (
                ValidateRejectCode::InvalidParentBlock,
                "invalid_parent_block",
            ),
            (ValidateRejectCode::InvalidTimestamp, "invalid_timestamp"),
            (
                ValidateRejectCode::NetworkChainMismatch,
                "network_chain_mismatch",
            ),
            (ValidateRejectCode::NotFoundError, "not_found_error"),
            (
                ValidateRejectCode::ProblematicTransaction,
                "problematic_transaction",
            ),
        ];
        for (code, expected) in validation_labels {
            assert_eq!(validate_reject_code_label(code), expected);
        }
    }
}
