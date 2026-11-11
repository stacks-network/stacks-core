# Git Branching

## Main Branches

- **main** - `main` is the default branch and the single trunk for development. The source code of HEAD always reflects the latest delivered changes for the next release.
- **release/X.Y.Z** is the release branch.

When the source code in `main` reaches a stable point and is ready to be released, a release branch is created as `release/X.Y.Z` (see [release-process.md](./release-process.md)).
After release, `release/X.Y.Z` is merged back into `main`.

The older `master`, `develop`, and `next` branches are retired and are no longer merge targets.

## Supporting Branches

Branch names should use a prefix that conveys the overall goal of the branch.
All branches should be based off of `main`.

- `feat/some-fancy-new-thing`: For new features.
- `fix/some-broken-thing`: For hot fixes and bug fixes.
- `chore/some-update`: Any non code related change (ex: updating CHANGELOG.md, adding comments to code).
- `docs/something-needs-a-comment`: For documentation.
- `ci/build-changes`: For continuous-integration changes.
- `test/more-coverage`: For branches that only add more tests.
- `refactor/formatting-fix`: For refactors of the codebase.

The full branch name **must**:

- Have a maximum of 128 characters.
- Only includes ASCII lowercase and uppercase letters, digits, underscores, periods and dashes.
