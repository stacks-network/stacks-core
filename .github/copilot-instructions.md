# Copilot PR review guidance for stacks-core

## Scope

These instructions apply only to pull-request review. Review the proposed diff and enough surrounding code to validate it. Do not recommend optional rewrites, style preferences, or unrelated cleanup unless they address a concrete risk introduced or exposed by the PR.

This repository implements the Stacks blockchain. Prioritize correctness, consensus safety, security, operational safety, and compatibility over general maintainability or style feedback.

Path-specific guidance under `.github/instructions/` adds language- and subsystem-specific review checks. Apply only the sections relevant to the changed behavior.

## Review priorities

- Determine the intended behavior from the PR description, changed code, tests, and documentation; comment only when the implementation does not safely establish that behavior.
- Prioritize defects with a concrete triggering condition and user, protocol, data, security, or operational impact.
- Treat consensus behavior, persistent data, wire formats, configuration, RPCs, events, public APIs, and smart-contract interfaces as compatibility-sensitive.
- Check compatibility for downstream consumers such as Clarinet, stacks-bench, stacks-inspect, RPC clients, and node operators.
- Trace error paths for incomplete cleanup, rollback, partial writes, leaked resources, or state that can affect later work.
- Verify that changed tests prove the intended invariant through the affected production path and cover material boundary, negative, and regression cases.
- Check whether behavior changes require matching configuration, RPC, event, operator, contract, or other user-facing documentation.
- When documentation changes, verify factual claims, commands, paths, examples, links, and sample output against the implementation.
- Check repository conventions for changelog or no-changelog handling and license headers on new files.
- Raise maintainability concerns only when the PR introduces duplication, coupling, misleading structure, or complexity that creates a specific correctness or future-change risk.

## Review comment threshold

- Leave fewer, higher-confidence comments rather than exhaustive observations.
- Identify the triggering condition, explain the impact in stacks-core terms, and suggest a specific fix or validation.
- Point to the exact changed call, state transition, path, invariant, or input that causes the issue.
- Trace nearby callers, invariants, and tests before reporting an issue; do not report cases already ruled out by the changed context.
- If a required invariant cannot be confirmed, state the concern conditionally and suggest an assertion or test that would establish it.
- Avoid issues already handled reliably by the compiler, clippy, rustfmt, prettier, or existing CI.
- Do not request broad architectural changes, unrelated refactors, or style-only edits.
- Do not request tests for mechanical or no-op changes without a realistic behavioral risk.
- Avoid multiple comments with the same root cause; report the clearest instance and describe the broader impact there.
