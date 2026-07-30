---
applyTo: "**/*.ts"
---

# TypeScript contract-test review guidance

The TypeScript in this repository currently primarily exercises boot and core contracts. Apply these checks to those integration and property-test changes.

- Verify the changed test uses the deployment, epoch, account, and caller configuration required to reproduce the contract behavior.
- Check that assertions cover the relevant responses, receipts, events, balances, and contract state rather than only transaction success.
- Check authorization failures, boundary amounts, duplicate requests, and repeated operations relevant to the changed contract behavior.
- Check nested calls, trait dispatch, indirect callers, and differences between `tx-sender` and `contract-caller`.
- Ensure a changed model or expected-value calculation does not reproduce the contract implementation so closely that both can contain the same bug.
- For property tests, check that changed generators reach the important boundaries and invalid cases and that failures are reproducible.
- Identify generated bindings or fixtures before commenting on generated output; report the issue against the source or generator when appropriate.
- Check that changed asynchronous setup and assertions are awaited and that ordering or shared state cannot make the test pass or fail spuriously.
