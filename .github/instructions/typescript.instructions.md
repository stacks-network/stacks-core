---
applyTo: "**/*.ts"
---

# TypeScript contract-test review guidance

The TypeScript in this repository currently primarily exercises boot and core contracts. Apply the test-specific checks below to those integration and property-test changes; for configuration, tooling, or generated TypeScript, apply only the relevant checks.

- Verify the changed test uses the deployment, epoch, account, and caller configuration required to reproduce the contract behavior.
- Check that assertions cover the relevant responses, receipts, events, balances, and contract state rather than only transaction success.
- Verify tests exercise the material authorization, boundary-amount, duplicate or repeated-operation, nested-call, trait-dispatch, indirect-caller, and `tx-sender` versus `contract-caller` cases affected by the change.
- Ensure a changed model or expected-value calculation does not reproduce the contract implementation so closely that both can contain the same bug.
- For property tests, check that changed generators reach the important boundaries and invalid cases and that failures are reproducible.
- Identify generated bindings or fixtures before commenting on generated output; report the issue against the source or generator when appropriate.
- Check that changed asynchronous setup and assertions are awaited and that ordering or shared state cannot make the test pass or fail spuriously.
