---
applyTo: "changelog.d/*,stacks-signer/changelog.d/*"
---

# Changelog fragment review guidance

Treat each changelog directory's `README.md` as the canonical source for its fragment rules. Apply the checks below to fragment files other than the READMEs; when a README itself changes, check that its rules remain internally consistent with the fragment workflow.

- Verify the fragment is placed in `changelog.d/` for node or stackslib changes, or `stacks-signer/changelog.d/` for signer changes.
- Verify the filename follows `<short-description>.<category>` and uses one of the supported categories: `added`, `changed`, `fixed`, or `removed`.
- Verify the category matches the nature of the change described by the fragment.
- Verify each non-empty line stands alone as a complete sentence, because it becomes a separate bullet in the assembled `CHANGELOG.md`.
- Verify the fragment accurately describes the PR's impact and identifies the affected component precisely enough for release readers. Describe user, operator, API, protocol, or developer impact when applicable; do not reject an accurate fragment merely because the change is internal.
- Check Markdown syntax and references that will be copied into the assembled changelog.
