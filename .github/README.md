# GitHub Actions Workflows

This directory contains GitHub Actions workflows, along with composites, helper scripts, and Dockerfiles. The system is organized around a central **CI orchestrator** (`ci.yml`) that triggers reusable workflows and composites for testing, building, and releasing.

---

## Permissions Model

- **ci.yml**: `contents: read` (default) – minimal permissions for linting/checks
- **release-github.yml**: `contents: write`, `packages: write`, `id-token: write` – required for release creation and image push
- **Individual workflows**: Request specific permissions (principle of least privilege)

---

## Triggers

### CI Workflow (`ci.yml`) — The Orchestrator

Triggered by:
- **Pull requests**: Opened, reopened, or when new commits are pushed
- **Merge queue**: `merge_group` event when PR is queued for merge
- **Manual dispatch**

### Test Workflows

In addition to being triggered as reusable workflows from `ci.yml`, each test workflow may be run manually via dispatch. 
If the required caches do not exist, they will be created to run the workflow steps. 


### Release Detection

Releases are detected automatically by analyzing the **branch name** in the check-release step of `ci.yml`:
- **Node release**: Branch matches `release/X.Y.Z.A.B` (5-part version) → builds stacks-node + all tests
- **Signer-only release**: Branch matches `release/signer-X.Y.Z.A.B.C` (6-part version) → builds stacks-signer + all tests
- **No release**: Any other branch or PR → skips release jobs and epoch-tests

Detection is handled by `.github/scripts/check_release.sh` and controlled by the `check-release` job outputs.

---

### PR, Manual Dispatch, and Merge Queue Workflow
**Duration**: ~45-90 min

**Trigger**: Pull Request (*Note*: `clippy`, `nix-check`, `proptest-extra` are not triggered via the orchestrator workflow but will run on a PR event)

```
┌────────────────┐  ┌─────────────────┐   ┌────────────────┐    ┌────────────────┐         ┌─────────────────┐
│ clippy         │  │ changelog-check │-▷ │ rustfmt        │ -▷ │ check-release  │ ------▷ │ constants-check │
│ nix-check      │  └─────────────────┘   └────────────────┘    └────────────────┘         │ cargo-hack      │
│ proptest-extra │                                                   │                     └─────────────────┘
└────────────────┘                                                   │
                                                                     │                    ┌─────────────────┐
                                                                     ▽                    │ stacks-core     │
                                                               ┌────────────────┐         │ bitcoin         │
                                                               │ create-cache   │ ------▷ │ bitcoin-rpc     │
                                                               └────────────────┘         │ p2p-tests       │
                                                                                          └─────────────────┘
                                                                                                   │
                                                                                                   ▽
                                                                                           ┌─────────────────┐
                                                                                           │ codecov         │
                                                                                           └─────────────────┘
```

### Release Branch Workflow
**Duration**: ~45-90 min + release pipeline

**Triggers**: Manual dispatch on a release branch - `release/X.Y.Z.A.B` or `release/signer/X.Y.Z.A.B.C`
```
┌─────────────-───┐   ┌────────────────┐    ┌────────────────┐           ┌─────────────────┐
│ changelog-check │-▷ │ rustfmt        │ -▷ │ check-release  │ --------▷ │ constants-check │
└─────────────-───┘   └────────────────┘    └────────────────┘      │    │ cargo-hack      │
                                                 │                  │    └─────────────────┘   ┌─────────────────┐
                                                 │                  │                          │ build-binaries  │
                                                 │                  └────────────────────────▷ │ release-docker  │
                                                 │                                             │ github-release  │
                                                 │                    ┌─────────────────┐      └─────────────────┘
                                                 ▽                    │ stacks-core     │
                                           ┌────────────────┐         │ bitcoin         │     ┌─────────────────┐
                                           │ create-cache   │ ------▷ │ bitcoin-rpc     │ -─▷ │ codecov         │
                                           └────────────────┘         │ p2p-tests       │     └─────────────────┘
                                                                      │ epoch-tests     │
                                                                      └─────────────────┘
```

---

## Concurrency & Cancellation

```yaml
concurrency:
  group: ci-${{ github.head_ref || github.ref || github.run_id }}
  cancel-in-progress: true
```

**Behavior:**
- Each PR/branch has a single concurrency group
- When new commits are pushed to a PR, previous runs are **automatically cancelled**
- Release branches have their own concurrency group, independent of PR runs

**Example:**
- Push to PR → run 1 starts
- Push again immediately → run 1 is cancelled, run 2 starts
- Multiple PRs run in parallel (different concurrency groups)

---

## Independent Workflows

These workflows run **outside** the main `ci.yml` orchestrator and are triggered by different events:

### Branch Push, or Merge Queue
- **`nix-check.yml`** Validates Nix environment setup.
- **`clippy.yml`** – Runs additional Rust linting checks.
- **`proptest-extra-tests.yml`** – on-demand property tests (with configurable base branch and case count).

### Scheduled
- **`docker-image.yml`** – Scheduled daily (5am UTC) build of Docker images from the `develop` branch.
- **`proptest-nightly-tests.yml`** – Scheduled daily (5am UTC) property-based fuzz testing on `develop`.
- **`lock-threads.yml`** – Scheduled daily (midnight UTC) to lock stale issues and PRs.

### Manual Dispatch Only
- **`sbtc-tests.yml`** – Manual sBTC test suite.

**Note:** `nix-check.yml` and `clippy.yml` run independently on branch/PR events and are **not orchestrated by `ci.yml`**.

---

## Directory Structure

### `.github/workflows/`
GitHub Actions workflow definitions (`.yml` files). Each workflow can be:
- **Called by ci.yml** – Reusable workflows triggered by the orchestrator
- **Standalone** – Run manually or on schedule

Key workflows:
- `ci.yml` – Main orchestrator for PR/release CI
- `release-github.yml` – Release coordination (calls build and docker)
- `release-build.yml` – Builds binaries for multiple architectures
- `release-docker.yml` – Builds and publishes Docker images to GHCR
- `docker-image.yml` – Independent nightly Docker builds
- Test workflows – stacks-core-tests.yml, bitcoin-tests.yml, etc.

### `.github/actions/`
Reusable composite actions that encapsulate multi-step workflows:
- `docker/` – Docker setup, QEMU, buildx, registry login
- `setup-rust-toolchain/` – Rust environment configuration
- `cache/` – Cache management (bitcoin, cargo, test archives)
- `testenv/` – Test environment setup and cache restore
- `run-tests/` – Test execution with nextest
- `install-tool/` – Tool installation (nextest, grcov, etc.)
- `codecov/` – Code coverage integration
- `release/` – Release automation actions

### `.github/scripts/`
Shell scripts and utilities executed by workflows. Any non-trivial script step should be added here, and should be able to run locally:
- `check_release.sh` – Detects if branch is a release and sets version tags
- `build_binaries.sh` – Builds binaries for target platform (Rust cross-compilation)
- `draft_release.sh` – Creates draft GitHub release with artifacts
- `rustfmt.sh` – Enforces Rust code formatting
- `changelog.js` – Validates CHANGELOG.md updates
- `logging.sh` – Common logging functions

### `.github/dockerfiles/`
Dockerfile definitions for building images:
- `debian/` – Debian-based images (glibc)
- `alpine/` – Alpine-based images (musl)

---

## Release Process

When `ci.yml` is triggered via dispatch from a **release branch** (e.g., `release/1.2.3.4.5`):

1. **Branch detection** – `check-release` job identifies the version tags
2. **Validation** – rustfmt and changelog checks must pass
3. **Binary builds** – `release-build.yml` compiles binaries for:
   - Linux x86_64 (native for musl and glibc
   - Linux ARM64 (cross-compiled for musl and glibc)
   - Windows x86_64
   - MacOS ARM64 (native)
4. **Docker images** – `release-docker.yml` builds Linux based images and pushes to `ghcr.io/stacks-network/*`
5. **Release creation** – Draft GitHub release created with binary archive assets
6. **Attestation** – Build provenance attached to artifacts for supply chain security

---
