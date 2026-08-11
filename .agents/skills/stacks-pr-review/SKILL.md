---
name: stacks-pr-review
description: Review repository changes as they would be reviewed in a pull request. Use when asked to review my changes, review code changes, pre-review a branch, review the current branch or a diff, review an open pull request, simulate PR feedback locally, or check committed, staged, unstaged, or untracked changes before a PR. Resolve and apply the repository's authoritative GitHub Copilot PR-review instructions without treating them as code-generation requirements.
---

# Stacks PR review

Perform a read-only review of the requested changes and, for local reviews, relevant work not yet committed. Do not edit files unless the user separately asks for fixes.

## Establish the review scope

1. Determine the repository root and inspect the current branch and working-tree status.
2. Determine the pull request's base branch from available PR metadata or branch configuration. If it cannot be determined reliably, infer the repository's default branch and state the assumption.
3. Include committed changes from the merge base with the base branch through `HEAD` in the review scope.
4. For local reviews, also include staged and unstaged changes and relevant untracked files. Distinguish findings that apply only to uncommitted work when that distinction matters.
5. Build the complete changed-file list before selecting review instructions.

If the user specifies a commit, range, branch, or subset of changed files, use that as the primary scope and say whether uncommitted changes were included. If the user names a pull request, use that pull request's diff against its base branch as the scope; include local uncommitted work only when explicitly requested, and distinguish it from the pull-request findings.

Treat IDE-provided selections and automatically attached editor context as focus context, not an implicit scope limit. Review the full requested change set and give that context particular attention; narrow the scope only when the user explicitly asks. If the request is solely to review existing selected code and identifies no change set, perform a normal code review rather than this diff-based workflow.

For local reviews without a PR description, use the user's request and commit messages as intent context alongside the changed code, tests, and documentation. State assumptions when the intended behavior remains unclear.

## Load the authoritative review policy

1. Read `.github/copilot-instructions.md` for repository-wide review criteria.
2. Find every `*.instructions.md` file under `.github/instructions/`. Read only each file's YAML frontmatter and match its comma-separated `applyTo` globs against the complete changed-file list.
3. Read and apply the full contents of every matching file. Apply all matches when scopes overlap; if none match, use only the repository-wide instructions. Do not read the bodies of unmatched files.

Treat the `.github` files as authoritative. Do not reproduce or invent a separate scope mapping, and do not apply their review criteria as code-generation requirements.

## Review the changes

- Review only defects introduced or exposed by the selected diff.
- Inspect enough surrounding code, callers, tests, and documentation to validate each potential finding.
- Prefer validation commands documented in `CONTRIBUTING.md` and the relevant CI workflows over generic tool defaults.
- Run focused validation when it materially increases confidence and is safe in the current environment. Report what was and was not run.
- Follow the repository-wide comment threshold and every applicable path-specific instruction.
- Do not report an issue that is merely hypothetical when the changed context rules it out.

## Report findings

List actionable findings first, ordered by severity. For each finding:

- Give a concise title labelled critical (a merge-blocking risk of consensus failure, security compromise, irreversible data loss, or severe compatibility break), major (incorrect behavior with a realistic trigger and material user, protocol, data, security, or operational impact), or minor (a real defect with limited impact).
- Cite the changed file and the narrowest useful line location.
- Explain the triggering condition and concrete impact.
- Suggest a specific fix or validation when useful.

Avoid duplicate findings with the same root cause. After the findings, briefly state the reviewed scope, applicable instruction files, and validation performed. If there are no findings, say so explicitly and mention any material validation gaps.
