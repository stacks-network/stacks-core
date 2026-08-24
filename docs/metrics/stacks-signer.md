# `stacks-signer` metrics

## Lifecycle and state

These metrics are exported by `stacks-signer` when it is built with the
`monitoring_prom` feature and `metrics_endpoint` is configured. They describe
process readiness and observed state; they do not alter signer policy,
thresholds, retries, persistence, or protocol messages.

These gauges have process-lifetime reset semantics. A missing series can mean
the process is not being scraped or the runloop has not initialized that metric
family; it must not be interpreted as a zero value. Use the scrape `up` metric
and `stacks_signer_runloop_ready` to distinguish those cases.

| Metric | Type | Meaning |
| --- | --- | --- |
| `stacks_signer_runloop_ready` | gauge | `1` after successful outer-runloop initialization, otherwise `0`. |
| `stacks_signer_registered_for_current_reward_cycle` | gauge | Whether this process hosts a registered signer for the current cycle. |
| `stacks_signer_registered_for_next_reward_cycle` | gauge | Whether this process hosts a registered signer for the next cycle. |
| `stacks_signer_state_burn_block_height` | gauge | Burn height represented by the current signer's committed local state. A pending update continues to report its prior committed height. |
| `stacks_signer_state_last_changed_timestamp_seconds` | gauge | Process wall-clock timestamp when the current local state was initialized or last changed. A process restart resets this freshness origin; re-observing an unchanged state does not refresh it. |
| `stacks_signer_companion_burn_block_height` | gauge | Latest canonical burn height learned successfully from the companion node. |
| `stacks_signer_pending_block_validations` | gauge | Current pending-validation backlog. It is initialized once from signer DB and maintained at successful queue transitions; scrapes do not query SQLite. |
| `stacks_signer_global_state_available` | gauge | Whether the current-cycle evaluator can derive a supported exact global state. |
| `stacks_signer_global_state_total_weight` | gauge | Total configured signer weight. |
| `stacks_signer_global_state_known_weight` | gauge | Weight for which a latest state update is known. |
| `stacks_signer_global_state_maximum_view_weight` | gauge | Greatest weight supporting one exact state view. |
| `stacks_signer_global_state_evaluator_threshold_weight` | gauge | Threshold used by the current evaluator implementation. |
| `stacks_signer_global_state_canonical_threshold_weight` | gauge | Rounded-up weight required by canonical Nakamoto signature validation. |

The evaluator and canonical thresholds are deliberately separate observations.
They can differ for signer sets whose weighted threshold is not an integer.
Exporting both does not change either threshold.

Signer/companion drift is calculated by subtracting
`stacks_signer_state_burn_block_height` or the companion height from an
independently collected node burn height. Do not label these metrics with
signer keys, block hashes, or peer identities; deployment systems can attach a
bounded actor identity at scrape time.

`stacks_signer_state_last_changed_timestamp_seconds` is sampled from the signer
process wall clock and is initialized from the state loaded when the signer
instance starts. Clock-fault experiments must compare it with an independent
collector clock before interpreting apparent staleness.
