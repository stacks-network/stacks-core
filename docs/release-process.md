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

Normal releases in this repository that add new features are released on a monthly schedule.
The currently staged changes for such releases are in the [main branch](https://github.com/stacks-network/stacks-core/tree/main).
It is generally safe to run a `stacks-node` from that branch, though it has received less rigorous testing than release tags.
If bugs are found in the `main` branch, please do [report them as issues](https://github.com/stacks-network/stacks-core/issues) in this repository.

For fixes that impact the correct functioning or liveness of the network, _hotfixes_ may be issued.
These are patches to the release branch, shipped as a new patch release following the process below.
These hotfixes are categorized by priority according to the following rubric:

- **High Priority**. Any fix for an issue that could deny service to the network as a whole, e.g., an issue where a particular kind of invalid transaction would cause nodes to stop processing requests or shut down unintentionally. Any fix for an issue that could cause honest miners to produce invalid blocks.
- **Medium Priority**. Any fix for an issue that could cause miners to waste funds.
- **Low Priority**. Any fix for an issue that could deny service to individual nodes.

## Versioning

This repository uses a 3 part version number:

```
X.Y.Z

X major version - this changes when there is a significant network update, e.g. Nakamoto (3.0) or Bitcoin Staking (4.0).
Y increments on smaller consensus-breaking changes (akin to semantic MINOR)
Z increments on non-consensus-breaking changes (akin to semantic PATCH)
```

The node and the signer share this single version and are released together.

Optionally, an extra pre-release field may be appended to the version to specify a release candidate in the format `-rc[0-9]+`.

## Non-Consensus Breaking Release Process

The release must be timed so that it does not interfere with a _prepare phase_.
The timing of the next Stacking cycle can be found [here](https://stx.eco/dao/tools?tool=2); to avoid interfering with the prepare phase, all releases should happen at least 24 hours before the start of a new cycle.

1. Before creating the release, the _version number_ must be determined, where the factors that determine the version number are discussed in [Versioning](#versioning).

   - Determine whether the release contains consensus-breaking changes, which require incrementing `Y`. Otherwise, only `Z` is incremented.
   - Determine whether the release requires a fresh chainstate, in other words, whether the database schema has changed without an automatic migration being implemented.
     This does not affect the version number, but it must be called out as a **⚠️ Breaking Changes** changelog entry, since operators have to resync.
   - A new branch in the format `release/X.Y.Z(-rc[0-9]+)` is created from the base branch `main`.

2. Enumerate PRs and/or issues that would _block_ the release.

   - A label should be applied to each such issue/PR as `X.Y.Z-blocker`.

3. Perform a [block-validation](../contrib/tools/block-validation.sh) using an existing chainstate, or sync from genesis

4. Since development is continuing in the `main` branch, it may be necessary to cherry-pick some commits into the release branch or open a PR against the release branch.

   - Create a feature branch from `release/X.Y.Z`, ex: `feat/X.Y.Z-pr_number`.
   - Add cherry-picked commits to the `feat/X.Y.Z-pr_number` branch
   - Merge `feat/X.Y.Z-pr_number` into `release/X.Y.Z`.

5. Open a PR to assemble the changelog and update the version in the `release/X.Y.Z` branch.

   - Create a chore branch from `release/X.Y.Z`, ex: `chore/X.Y.Z-changelog`.
   - Update `workspace.package.version` in [Cargo.toml](../Cargo.toml) to match this release version.
   - Refresh all affected Cargo lockfiles, then commit them:

     ```bash
     ./contrib/tools/update-release-lockfiles.sh
     ```
   - Assemble changelog fragments into `CHANGELOG.md`:

     ```bash
     ./contrib/tools/assemble-changelog.sh X.Y.Z
     ```

     This will collect all fragment files from `changelog.d/`, group them by category
     (⚠️ Breaking Changes/Added/Changed/Fixed/Removed), insert them as a new `## [X.Y.Z]`
     section in `CHANGELOG.md`, and delete the assembled fragments.

     Review the assembled changelog for accuracy and make any manual adjustments if needed.

     If the release has a **⚠️ Breaking Changes** section, it is emitted first in the version
     section and is carried verbatim into the drafted GitHub release notes. Give it extra
     scrutiny: every entry should state what breaks and what the operator must do, and the
     release announcement should call the section out explicitly.

   - This PR must be merged before continuing to the next steps

6. A build may be started by manually triggering the [`CI` workflow](../.github/workflows/ci.yml) against the `release/X.Y.Z` branch.

   - **Note**: The node and signer are released together, so this workflow produces a single release containing both the `stacks-core` and `stacks-signer` binaries and Docker images.

7. Once the release candidate has been built and binaries are available, ecosystem participants shall be notified to test the tagged release on various staging infrastructure.

8. If bugs or issues emerge from the rollout on staging infrastructure, the release will be delayed until those regressions are resolved.

   - As regressions are resolved, additional release candidates should be tagged.
   - Repeat steps 3-7 as necessary.

9. Once the final release candidate has rolled out successfully without issue on staging infrastructure, the tagged release shall no longer marked as Pre-Release on the [Github releases](https://github.com/stacks-network/stacks-core/releases/) page.
   Announcements will then be shared in the `#stacks-core-devs` channel in the Stacks Discord, as well as the [mailing list](https://groups.google.com/a/stacks.org/g/announce).

10. Finally, to complete the release process, the release branch, `release/X.Y.Z`, must be merged back into the `main` branch.

## Consensus Breaking Release Process

Consensus breaking releases shall follow the same overall process as a non-consensus release, with the following considerations:

- The release must be timed so that sufficient time is given to perform a genesis sync.
- The release must take into account the activation height at which the new consensus rules will take effect.
