# Agent guidance

## Pull-request reviews

The files under `.github/` define this repository's pull-request review criteria. They are not code-generation requirements.

For every PR review:

1. Ensure `.github/copilot-instructions.md` is in context for the repository-wide review scope, priorities, and comment threshold.
2. Enumerate `.github/instructions/*.instructions.md`, read each file's `applyTo` frontmatter, and apply every instruction file whose glob matches a changed file.
3. Apply all matching instruction files when scopes overlap, but only the sections relevant to the changed behavior. If no path-specific scope matches, use only the repository-wide instructions.

Do not maintain a separate scope mapping in this file; the `applyTo` frontmatter is authoritative. Do not reread or duplicate instruction content that is already present in the agent's context.

## Non-review tasks

Outside pull-request review, do not treat the Copilot instruction files as implementation requirements. Follow the repository's existing documentation and conventions, including `CONTRIBUTING.md`.
