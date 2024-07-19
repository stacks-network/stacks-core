# Release Process

## Platform support

| Platform                    | Supported                            |
| --------------------------- | ------------------------------------ |
| Linux 64-bit                | :white_check_mark:                   |
| MacOS 64-bit                | :white_check_mark:                   |
| Windows 64-bit              | :white_check_mark:                   |
| MacOS Apple Silicon (ARM64) | _builds are provided but not tested_ |
| Linux ARMv7                 | _builds are provided but not tested_ |
| Linux ARM64                 | _builds are provided but not tested_ |


## Release Schedule and Hotfixes

Normal releases in this repository that add new or updated features shall be released in an ad-hoc manner. The currently staged changes for such releases
are in the [develop branch](https://github.com/stacks-network/stacks-core/tree/develop). It is generally safe to run a `stacks-signer` from that branch, though it has received less rigorous testing than release branches. If bugs are found in the `develop` branch, please do [report them as issues](https://github.com/stacks-network/stacks-core/issues) on this repository.

For fixes that impact the correct functioning or liveness of the signer, _hotfixes_ may be issued. These hotfixes are categorized by priority
according to the following rubric:

- **High Priority**. Any fix for an issue that could deny service to the network as a whole, e.g., an issue where a particular kind of invalid transaction would cause nodes to stop processing requests or shut down unintentionally. 
- **Medium Priority**. ny fix for an issue that could deny service to individual nodes.
- **Low Priority**. Any fix for an issue that is not high or medium priority. 

## Versioning

This project uses a 6 part version number. When there is a stacks-core release, `stacks-signer` will assume the same version as the tagged `stacks-core` release (5 part version). When there are changes in-between stacks-core releases, the signer binary will assume a 6 part version. 

```
X.Y.Z.A.n.x

X = 2 and does not change in practice unless there’s another Stacks 2.0 type event
Y increments on consensus-breaking changes
Z increments on non-consensus-breaking changes that require a fresh chainstate (akin to semantic MAJOR)
A increments on non-consensus-breaking changes that do not require a fresh chainstate, but introduce new features (akin to semantic MINOR)
n increments on patches and hot-fixes (akin to semantic PATCH)
x increments on the current stacks-core release version
```

For example, if there is a stacks-core release of 2.6.0.0.0, `stacks-signer` will also be versioned as 2.6.0.0.0. If a change is needed in the signer, it may be released apart from the stacks-core as version 2.6.0.0.0.1 and will increment until the next stacks-core release.

## Release Process


1. The release must be timed so that it does not interfere with a _prepare
   phase_. The timing of the next Stacking cycle can be found
   [here](https://stx.eco/dao/tools?tool=2). A release should happen
   at least 48 hours before the start of a new cycle, to avoid interfering
   with the prepare phase.

2. Before creating the release, the release manager must determine the _version
   number_ for this release, and create a release branch in the format: `release/signer-X.Y.Z.A.n.x`.
   The factors that determine the version number are discussed in [Versioning](#versioning).

3. _Blocking_ PRs or issues are enumerated and a label should be applied to each
   issue/PR such as `signer-X.Y.Z.A.n.x-blocker`. The Issue/PR owners for each should be pinged
   for updates on whether or not those issues/PRs have any blockers or are waiting on feedback.
   __Note__: It may be necessary to cherry-pick these PR's into the target branch `release/signer-X.Y.Z.A.n.x`

4. The [CHANGELOG.md](./CHANGELOG.md) file shall be updated with summaries of what
   was `Added`, `Changed`, and `Fixed` in the base branch. For example, pull requests
   merged into `develop` can be found [here](https://github.com/stacks-network/stacks-blockchain/pulls?q=is%3Apr+is%3Aclosed+base%3Adevelop+sort%3Aupdated-desc).
   Note, however, that GitHub apparently does not allow sorting by _merge time_,
   so, when sorting by some proxy criterion, some care should be used to understand
   which PR's were _merged_ after the last release.

5. Once any blocker PRs have merged, a new tag will be created
   by manually triggering the [`CI` Github Actions workflow](https://github.com/stacks-network/stacks-core/actions/workflows/ci.yml)
   against the `release/signer-X.Y.Z.A.n.x` branch.

6. Ecosystem participants will be notified of the release candidate in order
   to test the release on various staging infrastructure.

7. If bugs or issues emerge from the rollout on staging infrastructure, the release
   will be delayed until those regressions are resolved. As regressions are resolved,
   additional release candidates shall be tagged.

8. Once the final release candidate has rolled out successfully without issue on staging
   infrastructure, the tagged release shall no longer marked as Pre-Release on the [Github releases](https://github.com/stacks-network/stacks-blockchain/releases/)
   page. Announcements will then be shared in the `#stacks-core-devs` channel in the
   Stacks Discord, as well as the [mailing list](https://groups.google.com/a/stacks.org/g/announce).

9. Finally, the release branch `release/signer-X.Y.Z.A.n.x` will be PR'ed into the `master` branch, and once merged, a PR for `master->develop` will be opened. 
