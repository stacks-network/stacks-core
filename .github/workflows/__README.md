## Enabling CI

The CI will always run on `stacks-network/stacks-core` with other forks and cloned repos able to opt-in.

To **enable** CI workflows within your fork or cloned repository, add a GitHub Actions Variable:

- Name: `ENABLE_CI_WORKFLOWS`
- Value: `true`

This will enable CI functionality within your repo or fork.

## Folder Structure

ALL runnable workflows must be in the root of the .github/workflows folder. Subfolders are not allowed.

When adding or changing files, follow this file naming guidance:

- If the file is a "top level" workflow that will be triggered by an event such as a PR being opened or via CRON schedule, name it without any `_` prefix.
- If the file is a reusable workflow intended to be called by other workflows (and will include the `on: workflow_call:` trigger), prefix the filename with `_`.

## Check CI Functionality

Typically, you will want to start your "top level" workflow with a call to the `__check-ci.yml` file, like so:

```
  # Check if CI is enabled
  check-ci:
    uses: ./.github/workflows/__check-ci.yml
```

This workflow checks if CI is enabled, providing useful output variables. Using these outputs is a best practice so that forks and clones do not have to run CI unless they choose to opt-in.

### Inputs

| Input | Description | Required | Default |
| ----- | ----------- | -------- | ------- |
| `allow-fork-runs` | Whether this workflow may run outside of the official repository at all. Set `false` for workflows whose side effects land on upstream, so no variable can enable them in a fork. | `false` | `true` |
| `extra-enable-var` | Name of an additional repository variable that enables this one workflow on its own, e.g. `ENABLE_CI_PROPTEST_NIGHTLY`. Lets a fork run a single scheduled workflow — on its schedule, not just by hand — without `ENABLE_CI_WORKFLOWS` turning on all of CI. Empty means no workflow-specific variable. | `false` | `""` |

### Outputs

| Output | Description |
| ------ | ----------- |
| `enabled` | `'true'` if CI is enabled in this repository, `'false'` otherwise |

### Per-workflow variables

Workflows that name their own variable via `extra-enable-var`. Set one to `true` to enable
just that workflow:

| Workflow | Variable |
| -------- | -------- |
| `docker-image.yml` | `ENABLE_CI_DOCKER_IMAGE` |
| `tests-proptest-nightly.yml` | `ENABLE_CI_PROPTEST_NIGHTLY` |
