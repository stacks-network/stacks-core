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
