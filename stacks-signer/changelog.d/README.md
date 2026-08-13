# Changelog Fragments (Signer)

The changelog helps developers keep track of the changes happening across the
codebase. All PRs, other than those which are purely "chore" tasks (e.g.
formatting, typos) should include a changelog entry. The changelog is NOT
limited to only user-facing changes.

Instead of editing `CHANGELOG.md` directly, each PR should add a **fragment
file** to this directory. This avoids merge conflicts and makes the release
process clearer. Each fragment should be one or more complete sentences. Each
line in the fragment file will become a separate bullet point in the final
CHANGELOG.md.

## How to add a changelog entry

1. Create a file in this directory named: `<short-description>.<category>`

   **Categories:** `breaking`, `added`, `changed`, `fixed`, `removed`

   **Examples:**
   - `track-pending-blocks.added`
   - `db-schema-v19.changed`
   - `require-auth-password.breaking`

2. Write the changelog entry text in the file (one or more lines of markdown):

   ```
   Added support for tracking pending block responses in the signer database
   ```

3. That's it. The fragment will be assembled into `stacks-signer/CHANGELOG.md`
   at release time using `contrib/tools/assemble-changelog.sh`.

## Breaking changes

Use the `breaking` category for anything that is likely to break signer
operators if they upgrade without taking action, for example:

- renamed, removed, or newly-required configuration options
- changed or removed CLI subcommands and flags
- signer database or state changes that require a migration or manual step
- changed defaults that alter signing behavior in a way operators must notice

`breaking` entries are assembled into a dedicated **⚠️ Breaking Changes**
section placed *first* in the release's changelog section, ahead of Added /
Changed / Fixed / Removed, and that section is carried into the GitHub release
notes. Write the entry so it says both **what breaks** and **what the operator
must do about it**.

If a PR has both a breaking aspect and ordinary changes worth listing, add two
fragments (e.g. `foo.breaking` and `foo.changed`) rather than duplicating the
whole entry.

## Notes

- One fragment per PR is typical, but you can add multiple if your PR spans
  categories.
- If your PR doesn't need a changelog entry (e.g., docs-only, CI changes,
  test-only), you can skip this. Add the `no changelog` label to your PR to
  bypass the CI check.
- Fragment files are deleted after they are assembled into the changelog during
  a release.
