# Git Branching

The following is a modified version of the gitflow branching strategy described in <https://nvie.com/posts/a-successful-git-branching-model/>

## Main Branches

- **master** - `origin/master` is the main branch where the source code of HEAD always reflects a production-ready state.
- **develop** - `origin/develop` is the branch where the source code of HEAD always reflects a state with the latest delivered development changes for the next release.
- **next** - `origin/next` may contain consensus-breaking changes.
- **release/X.Y.Z.A.n** is the release branch.

When the source code in the develop branch reaches a stable point and is ready to be released, a release branch is created as `release/X.Y.Z.A.n` (see [release-process.md](./release-process.md)).
After release, the following will happen:

- `release/X.Y.Z.A.n` branch is merged back to `origin/master`.
- `origin/master` is then merged into `origin/develop`, and development continues in the `origin/develop` branch.
- `origin/develop` is then merged into `origin/next`.

## Supporting Branches

Branch names should use a prefix that conveys the overall goal of the branch.
All branches should be based off of `origin/develop`, with the exception being a hotfix branch which may be based off of `origin/master`.

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
