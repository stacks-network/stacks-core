---
applyTo: "**/*.md"
---

# Markdown and repository-documentation review guidance

- Check descriptions of RPC responses, configuration defaults, events, contract return values, fees, and credited amounts against the changed implementation.
- Verify changed commands, filenames, workflow names, flags, code examples, links, anchors, and sample output.
- Treat operator, upgrade, release, mining, signing, and security documentation as correctness-sensitive.
- Verify changelog entries describe the user-visible impact and use the repository's expected category and component.
- For Copilot instruction changes, verify the file location, frontmatter, scope, and globs match GitHub's supported formats and avoid brittle paths.
- Report factual, compatibility, or usability defects rather than wording preferences.
