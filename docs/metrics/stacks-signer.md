# `stacks-signer` metrics

## Proposal policy and validation outcomes

These metrics are available when `stacks-signer` is built with the
`monitoring_prom` feature and `metrics_endpoint` is configured.

All labels are selected from finite enums. Proposal hashes, peer identities,
addresses, error text, and other unbounded values are deliberately excluded.
Counters reset when the signer process restarts.

## Metrics

### `stacks_signer_policy_evaluations_total`

Counts proposal-policy evaluations after all policy checks and test overrides.

- `classification`: `proceed`, `verdict_reject`, or `unavailable`
- `action`: `continue` or `reject`

Classification describes what the signer knew; action describes what the
current implementation did. In particular, current protocol behavior records
availability failures as `classification="unavailable",action="reject"`.
This metric does not change or conceal that behavior.

`ConnectivityIssues`, `NoSortitionView`, and `NoSignerConsensus` are classified
as unavailable. `InvalidTenureExtend` remains a verdict rejection because the
legacy reason represents both genuine policy verdicts and some RPC failures;
separating those cases requires a behavior/API change outside this
instrumentation-only change.

### `stacks_signer_policy_rejections_total`

Counts policy rejections by the finite `reason` derived from `RejectReason`.
Free-form reason text is never used as a label. This is intentionally distinct
from node validation rejections.

### `stacks_signer_block_validation_lifecycle_total`

Counts effective companion-node validation lifecycle transitions.

- `event`: `submitted`, `retried`, `accepted`, `rejected`, or `expired`
- `reason`: `none`, except rejected validations use a finite
  `ValidateRejectCode` label

Accepted and rejected events are recorded only after the response is matched
to a tracked, undecided, statically valid proposal. Duplicate, late, and stray
responses therefore remain visible in the older raw response counter but do
not double-count this effective lifecycle metric.

### `stacks_signer_block_response_deliveries_total`

Counts final response delivery attempts.

- `response_type`: `accepted` or `rejected`
- `outcome`: `sent` or `failed`

An RPC call returning an acknowledgement with `accepted=false` is a failed
delivery. The existing `stacks_signer_block_responses_sent` metric is
retained unchanged for compatibility.

## Operational examples

Availability failures that current code turns into rejections:

```promql
rate(stacks_signer_policy_evaluations_total{classification="unavailable",action="reject"}[5m])
```

Effective validation outcomes by reason:

```promql
sum by (event, reason) (rate(stacks_signer_block_validation_lifecycle_total[5m]))
```

Failed final response deliveries:

```promql
sum by (response_type) (rate(stacks_signer_block_response_deliveries_total{outcome="failed"}[5m]))
```

These counters are observational. They do not alter proposal policy,
validation, retries, response delivery, threshold arithmetic, or consensus.
