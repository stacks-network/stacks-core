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

## Bootstrap Functionality

Typically, you will want to start your "top level" workflow with a call to the `_bootstrap.yml` file, like so:

```
# Check CI & Bootstrap the .github folder so local actions can be called 
  bootstrap:
    uses: ./.github/workflows/_bootstrap.yml
```

This workflow checks if CI is enabled, and if so bootstraps the .github folder by checking it out automatically. This enables local actions access, such as our wrappers for official actions.
