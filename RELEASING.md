# Releases

All releases are built via a Github Actions workflow named `CI`, and is responsible for building binary archives, checksums, and resulting docker images.
This workflow will also trigger any tests that need to be run, like integration tests.

1. Releases are only created if a tag is manually provided when the ci workflow is triggered _on the default branch_.
2. Pushing a new feature branch -> nothing is triggered automatically. PR's are required, or the ci workflow can be triggered manually on a specific branch to build a docker image for the specified branch.

## TL;DR

1. A tagged release will produce 2 versions of the docker image (along with all binary archives):
   - An Alpine image for several architectures tagged with:
     - `x.x.x.x.x`
     - `latest`
   - An Debian image for several architectures tagged with:
     - `x.x.x.x.x-debian`
     - `latest-debian`
2. A PR will produce a single image built from source on Debian with glibc with 2 tags:
   - `branch-name`
   - `pr-number`
3. A merged PR will produce a single image built from source on Debian with glibc:
   - `branch-name`
   -

## Release workflow:

1. Create a feature branch: `feat/112-fix-something`
2. PR `feat/112-fix-something` to the `develop` branch
   1. Workflow is triggered, resulting in a docker image for the branch and PR number
3. PR `develop` to the default branch
   1. Workflow is triggered, resulting in a docker image for the branch and PR number
4. Merge `develop` branch to the default branch
   1. Workflow is triggered, resulting in a docker image for the default branch
5. CI workflow is manually triggered with a version, i.e. `2.05.0.3.0`
   1. Github release is created with binaries
   2. docker images are created for the input version and latest

## PR a branch to develop:

ex: branch is named `feat/112-fix-something` and the PR is numbered `112`

- rust format is run
- docker image built from source on a debian distribution is built and pushed with the branch name and PR number as tags
  - `blockstack/stacks-blockchain:feat-112-fix-something`
  - `blockstack/stacks-blockchain:pr-112`

## PR develop to master branches:

ex: branch is named `develop` and the PR is numbered `113`

- rust format is run
- docker image built from source on a debian distribution is built and pushed with the branch name and PR number as tags
  - `blockstack/stacks-blockchain:develop`
  - `blockstack/stacks-blockchain:pr-113`

## Merging a PR from develop to master:

- rust format is run
- docker image built from source on a debian distribution is built and pushed with the branch name as a tag
  - `blockstack/stacks-blockchain:master`

## Manually triggering workflow without tag (any branch):

- rust format is run
- no binaries are built
- no github release is created
- no integration tests are run
- docker image built from source on a debian distribution is built and pushed with the branch name as a tag
  - `blockstack/stacks-blockchain:<branch name>`

## Manually triggering workflow with tag (non-default branch):

- rust format is run
- no binaries are built
- no github release
- no integration tests
- docker image built from source on a debian distribution is built and pushed with the branch name
  - `blockstack/stacks-blockchain:<branch name>`

## Manually triggering workflow with tag on default branch (i.e. tag of `2.05.0.3.0`):

- rust format is run
- integration tests
- leaked credential test
- binaries built for specified architectures
  - archives and checksum added to github release
- github release (with artifacts/checksum) is created using the manually input tag
- docker image built from source on a debian distribution is built and pushed with the provided nput tag and `latest`
  - `blockstack/stacks-blockchain:2.05.0.3.0-debian`
  - `blockstack/stacks-blockchain:latest-debian`
  - `blockstack/stacks-blockchain:2.05.0.3.0`
  - `blockstack/stacks-blockchain:latest`
