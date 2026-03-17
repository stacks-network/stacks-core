# Changelog Fragments (Signer)

Instead of editing `CHANGELOG.md` directly, each PR should add a **fragment
file** to this directory. This avoids merge conflicts and makes the release
process clearer.

## How to add a changelog entry

1. Create a file in this directory named: `<PR#>-<short-description>.<category>`

   **Categories:** `added`, `changed`, `fixed`, `removed`

   **Examples:**
   - `6800-track-pending-blocks.added`
   - `6801-db-schema-v19.changed`

2. Write the changelog entry text in the file (one or more lines of markdown):

   ```
   Added support for tracking pending block responses in the signer database
   ```

3. That's it. The fragment will be assembled into `stacks-signer/CHANGELOG.md`
   at release time using `contrib/assemble-changelog.sh`.

## Notes

- One fragment per PR is typical, but you can add multiple if your PR spans
  categories.
- If your PR doesn't need a changelog entry (e.g., docs-only, CI changes,
  test-only), you can skip this. Add the `no changelog` label to your PR to
  bypass the CI check.
- Fragment files are deleted after they are assembled into the changelog during
  a release.
