---
applyTo: ".github/workflows/**/*,.github/actions/**/*,.github/scripts/**/*"
---

# GitHub Actions and CI review guidance

## Workflow correctness

- Verify referenced workflow, action, script, and configuration paths exist with the exact spelling and case used.
- Verify artifact names and downloaded directory layouts match the producing workflow.
- Check `gh` CLI subcommands and flags against the installed version and the event context.
- Verify event triggers, branch filters, workflow-call inputs, and merge-queue or merged-PR semantics match the stated intent.
- Distinguish PR head SHA, synthetic merge SHA, merge commit SHA, and target branch where the workflow depends on commit identity.
- Check expressions for unavailable event fields, incorrect output names, quoting errors, and values that differ between trigger types.
- Verify permissions are sufficient but not excessive, especially for fork-originated pull requests.
- Check caches and artifacts for keys, retention, trust boundaries, and accidental reuse across incompatible builds.

## Failure behavior

- Ensure required failures cannot be silently skipped or masked by shell pipelines, conditional steps, or `continue-on-error`.
- Check cleanup, status reporting, and dependent jobs when a preceding command or reusable workflow fails.

## Example of a high-value comment

If an artifact already contains `code_coverage_files/...` and the workflow downloads it into a directory with the same name, the resulting nested path can break a non-recursive consumer. Align the upload layout, download destination, and consuming path, or make the consumer intentionally recursive.
