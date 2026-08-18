---
applyTo: "**/*.md"
---

# Markdown and repository-documentation review guidance

- Verify operator, upgrade, release, mining, signing, and security documentation strictly against the implementation; errors there cause operational incidents.
- For ordinary PRs, flag direct edits to `CHANGELOG.md` or `stacks-signer/CHANGELOG.md`; use the appropriate changelog fragment unless the PR is assembling a release.
- For Copilot instruction changes, verify the file location, frontmatter, scope, and globs match GitHub's supported formats and avoid brittle paths.
