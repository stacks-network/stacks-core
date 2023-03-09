# Releases

All releases are built via a Github Actions workflow named `CI`, and is responsible for building binary archives, checksums, and resulting docker images.
This workflow will also trigger any tests that need to be run, like integration tests.

1. Releases are only created if a tag is manually provided when the ci workflow is triggered.
2. Pushing a new feature branch: Nothing is triggered automatically. PR's are required, or the ci workflow can be triggered manually on a specific branch to build a docker image for the specified branch.

The following workflow steps are currently disabled:

- Clippy
- Net-test
- Crate audit

## TL;DR

1. A PR will produce a single image built from source on Debian with glibc with 2 tags:
   - `stacks-blockchain:<branch-name>`
   - `stacks-blockchain:<pr-number>`
2. A merged PR from `develop` to the default branch will produce a single image built from source on Debian with glibc:
   - `stacks-blockchain:<default-branch-name>`
3. An untagged build of any branch will produce a single image built from source on Debian with glibc:
   - `stacks-blockchain:<branch-name>`
4. A tagged release on a non-default branch will produce 2 versions of the docker image (along with all binary archives):
   - An Alpine image for several architectures tagged with:
     - `stacks-blockchain:<x.x.x.x.x>`
   - An Debian image for several architectures tagged with:
     - `stacks-blockchain:<x.x.x.x.x-debian>`
5. A tagged release on the default branch will produce 2 versions of the docker image (along with all binary archives):
   - An Alpine image for several architectures tagged with:
     - `stacks-blockchain:<x.x.x.x.x>`
     - `stacks-blockchain:<latest>`
   - An Debian image for several architectures tagged with:
     - `stacks-blockchain:<x.x.x.x.x-debian>`
     - `stacks-blockchain:<latest-debian>`

## Release workflow:

1. Create a feature branch: `feat/112-fix-something`
2. PR `feat/112-fix-something` to the `develop` branch
   1. CI Workflow is automatically triggered, resulting in a pushed docker image tagged with the **branch name** and **PR number**
3. PR `develop` to the default branch
   1. CI Workflow is automatically triggered, resulting in a pushed docker image tagged with the **branch name** and **PR number**
4. Merge `develop` branch to the default branch
   1. CI Workflow is triggered, resulting in a pushed docker image tagged with the **default branch name**
5. CI workflow is manually triggered on **non-default branch** with a version, i.e. `2.1.0.0.0-rc0`
   1. Github release for the manually input version is created with binaries
   2. Docker image pushed with tags of the **input version** and **branch**
6. CI workflow is manually triggered on **default branch** with a version, i.e. `2.1.0.0.0`
   1. Github release for the manually input version is created with binaries
   2. Docker image pushed with tags of the **input version** and **latest**

## PR a branch to develop:

ex: Branch is named `feat/112-fix-something` and the PR is numbered `112`

- Steps executed:
  - Rust Format
  - Integration Tests
  - Leaked credential test
  - Docker image is built from source on a debian distribution and pushed with the branch name and PR number as tags
  - ex:
    - `stacks-blockchain:feat-112-fix-something`
    - `stacks-blockchain:pr-112`
- Steps _not_ executed:
  - No binaries are built
  - No github release
  - No docker images built from binary artifacts

## Merging a branch to develop:

Nothing is triggered automatically

## PR develop to master branches:

ex: Branch is named `develop` and the PR is numbered `113`

- Steps executed:
  - Rust format
  - Integration tests
  - Leaked credential test
  - Docker image is built from source on a debian distribution and pushed with the branch name and PR number as tags
  - ex:
    - `stacks-blockchain:develop`
    - `stacks-blockchain:pr-113`
- Steps _not_ executed:
  - No binaries are built
  - No github release
  - No docker images built from binary artifacts

## Merging a PR from develop to master:

- Steps executed:
  - Rust format
  - Integration tests
  - Leaked credential test
  - Docker image is built from source on a debian distribution and pushed with the branch name as a tag
  - ex:
    - `stacks-blockchain:master`
- Steps _not_ executed:
  - No binaries are built
  - No github release
  - No docker images built from binary artifacts

## Manually triggering workflow without tag (any branch):

- Steps executed:
  - Rust format
  - Integration tests
  - Leaked credential test
  - Docker image is built from source on a debian distribution and pushed with the branch name as a tag
  - ex:
    - `stacks-blockchain:<branch name>`
- Steps _not_ executed:
  - No binaries are built
  - No github release
  - No docker images built from binary artifacts

## Manually triggering workflow with tag on a non-default branch (i.e. tag of `2.1.0.0.0-rc0`):

- Steps executed:
  - Rust format
  - Integration tests
  - Leaked credential test
  - Binaries built for specified architectures
    - Archive and checksum files added to github release
  - Github release (with artifacts/checksum) is created using the manually input tag
  - Docker image built from binaries on debian/alpine distributions and pushed with the provided input tag and `latest`
  - ex:
    - `stacks-blockchain:2.1.0.0.0-rc0`
- Steps _not_ executed:
  - No docker images built from source

## Manually triggering workflow with tag on default branch (i.e. tag of `2.1.0.0.0`):

- Steps executed:
  - Rust format
  - Integration tests
  - Leaked credential test
  - Binaries built for specified architectures
    - Archive and checksum files added to github release
  - Github release (with artifacts/checksum) is created using the manually input tag
  - Docker image built from binaries on debian/alpine distributions and pushed with the provided input tag and `latest`
  - ex:
    - `stacks-blockchain:2.1.0.0.0-debian`
    - `stacks-blockchain:latest-debian`
    - `stacks-blockchain:2.1.0.0.0`
    - `stacks-blockchain:latest`
- Steps _not_ executed:
  - No docker images built from source
