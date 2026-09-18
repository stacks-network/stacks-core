---
applyTo: "**/*.clar"
---

# Clarity review guidance

Clarity files include deployable contracts and parser, analysis, and type-checker fixtures. Apply the contract checks below only to executable contracts. For fixture changes, verify that the source and expected acceptance, diagnostic, or error result exercise the intended language behavior under the relevant Clarity version and epoch.

## Contract semantics and validation

- Check caller identity and authorization across `contract-caller`, `tx-sender`, trait dispatch, nested `contract-call?`, cross-contract calls, and read-only behavior, including relevant failure cases.
- Verify value flows and privileged operations, such as payouts, fees, withdrawals, and admin or sweep behavior, against the documented and intended behavior, including at boundary amounts.
- Check contract-call boundaries for malformed or duplicate inputs and repeated or replayed requests.
- Check map and variable updates for partial state changes and failure behavior; verify contract state after failed execution, not only the returned error.
- Verify changed public and read-only functions preserve their documented response types and error behavior.
- Check epoch-gated behavior and compatibility with callers and state created under older epochs.
- Treat boot contracts, public interfaces, and externally visible comments as compatibility-sensitive.
- Check comments and API documentation against the exact value credited, returned, transferred, burned, or retained.
