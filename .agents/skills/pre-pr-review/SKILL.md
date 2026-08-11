---
name: pre-pr-review
description: Review local repository changes before opening, updating, or pushing a pull request. Use when asked to pre-review, review the current branch or diff, simulate PR feedback locally, or check committed, staged, unstaged, or untracked changes before a PR. Resolve and apply the repository's authoritative GitHub Copilot PR-review instructions without treating them as code-generation requirements.
---

# Pre-PR review

Perform a read-only review of the changes that would appear in the pull request, plus relevant local work not yet committed. Do not edit files unless the user separately asks for fixes.

## Establish the review scope

1. Determine the repository root and inspect the current branch and working-tree status.
2. Determine the pull request's base branch from available PR metadata or branch configuration. If it cannot be determined reliably, infer the repository's default branch and state the assumption.
3. Review committed changes from the merge base with the base branch through `HEAD`.
4. Also review staged and unstaged changes and relevant untracked files. Distinguish findings that apply only to uncommitted work when that distinction matters.
5. Build the complete changed-file list before selecting review instructions.

If the user specifies a commit, range, branch, or subset of files, use that as the primary scope and say whether uncommitted changes were included.

## Load the authoritative review policy

1. Read `.github/copilot-instructions.md` for repository-wide review criteria.
2. Recursively enumerate `.github/instructions/**/*.instructions.md`.
3. Read each instruction file's `applyTo` frontmatter and match its comma-separated glob patterns against the changed repository-relative paths.
4. Apply every matching instruction file when scopes overlap. If no path-specific file matches, apply only the repository-wide instructions.

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

- Give a concise severity-labelled title.
- Cite the changed file and the narrowest useful line location.
- Explain the triggering condition and concrete impact.
- Suggest a specific fix or validation when useful.

Avoid duplicate findings with the same root cause. After the findings, briefly state the reviewed scope, applicable instruction files, and validation performed. If there are no findings, say so explicitly and mention any material validation gaps.
