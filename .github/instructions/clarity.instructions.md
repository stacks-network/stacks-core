---
applyTo: "**/*.clar"
---

# Clarity review guidance

Clarity files include deployable contracts and parser, analysis, and type-checker fixtures. Apply the contract checks below only to executable contracts. For fixture changes, verify that the source and expected acceptance, diagnostic, or error result exercise the intended language behavior under the relevant Clarity version and epoch.

## Contract semantics

- Check `contract-caller`, `tx-sender`, trait dispatch, nested `contract-call?`, cross-contract calls, and read-only behavior affected by the PR.
- Verify payout amounts, fee treatment, request IDs, return values, authorization, withdrawal behavior, and admin or sweep behavior.
- Check map and variable updates for partial state changes, duplicate requests, replay, and failure behavior.
- Verify changed public and read-only functions preserve their documented response types and error behavior.
- Check epoch-gated behavior and compatibility with callers and state created under older epochs.
- Treat boot contracts, public interfaces, and externally visible comments as compatibility-sensitive.

## Contract-specific validation

- Check relevant caller identities, authorization failures, boundary amounts, and repeated operations.
- Check nested calls, trait dispatch, contract-call boundaries, and malformed or duplicate contract inputs.
- Verify contract state after failed execution, not only the returned error.
- Check comments and API documentation against the exact value credited, returned, transferred, burned, or retained.
