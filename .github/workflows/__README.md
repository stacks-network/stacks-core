## Enabling CI

Workflows always run on `stacks-network/stacks-core`, with forks and cloned repos able to
opt in. Every gated workflow calls the reusable `_check-ci-enabled.yml` and runs its real
jobs only when that gate says so.

The gate answers two independent questions and ANDs them:

```
enabled = (ENABLE_CI_WORKFLOWS || <extra-enable-var> || manual dispatch)
          && (repo == stacks-network/stacks-core || allow-fork-run)
```

To **enable** workflows within your fork or cloned repository, add the GitHub Actions
Variable `ENABLE_CI_WORKFLOWS` with value `true`. To enable a single workflow instead, set
only that workflow's own variable — see [Repository variables](#repository-variables).

Pressing **Run workflow** enables that one run without enabling anything persistently. This
matters for scheduled workflows: setting a variable would also start the cron on that
repository, whereas a dispatch runs once.

## Documentation

### Repository variables

Actions **Variables** (not secrets). Any value other than `true` — including unset — means
off.

| Variable | Description | Default |
| -------- | ----------- | ------- |
| `ENABLE_CI_WORKFLOWS` | Master switch for every gated workflow. Authoritative in the official repository too, so setting it to anything but `true` pauses all CI without a code change. Must be `true` on `stacks-network/stacks-core`. | unset |
| `ENABLE_CI_DOCKER_IMAGE` | Enables `docker-image.yml` on its own | unset |
| `ENABLE_CI_PROPTEST_EXTRA` | Enables `tests-proptest-extra.yml` on its own | unset |
| `ENABLE_CI_PROPTEST_NIGHTLY` | Enables `tests-proptest-nightly.yml` on its own | unset |

The per-workflow variables let a fork exercise one workflow — including on its schedule —
without `ENABLE_CI_WORKFLOWS` turning on all CI for every PR.

### `_check-ci-enabled.yml` inputs

| Input | Description | Required | Default |
| ----- | ----------- | -------- | ------- |
| `allow-fork-run` | Whether this workflow may run outside the official repository at all. Set `false` for workflows whose side effects land on upstream; no variable or manual dispatch can then enable them in a fork. | `false` | `true` |
| `extra-enable-var` | Name of an additional repository variable that enables this one workflow on its own, e.g. `ENABLE_CI_DOCKER_IMAGE`. Empty means no workflow-specific variable. | `false` | `""` |

### `_check-ci-enabled.yml` outputs

| Output | Description |
| ------ | ----------- |
| `enabled` | `'true'` when this workflow's jobs should run in this repository |

### Upstream-only workflows

These pass `allow-fork-run: false`, so no variable or manual dispatch can enable them in a
fork:

| Workflow | Why |
| -------- | --- |
| `slack-pr-nag.yml` | reads `stacks-network/stacks-core` PRs and posts to team Slack |
| `lock-closed-threads.yml` | upstream-only by convention; keeps forks from locking their own stale threads |

## Usage

```yaml
jobs:
  check-ci-enabled:
    name: "Check: CI Enabled"
    uses: ./.github/workflows/_check-ci-enabled.yml
    
  build:
    name: Job
    needs:
      - check-ci-enabled
    if: needs.check-ci-enabled.outputs.enabled == 'true'
    runs-on: ubuntu-latest
    steps:
      - run: echo "gated work goes here"
```

## Folder Structure

ALL runnable workflows must be in the root of the `.github/` workflows folder. Subfolders are not allowed.

When adding or changing files, follow this file naming guidance:

- If the file is a "top level" workflow that will be triggered by an event such as a PR being opened or via CRON schedule, name it without any `_` prefix.
- If the file is a reusable workflow intended to be called by other workflows (and will include the `on: workflow_call:` trigger), prefix the filename with `_`.
