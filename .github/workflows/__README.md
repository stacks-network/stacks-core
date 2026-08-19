## Enabling CI

To **enable** CI workflows within your fork or repository, add a GitHub Actions Variable:

- Name: `ENABLE_CI_WORKFLOWS`
- Value: `true`

This will enable CI functionality within your repo or fork, as our CI workflow files check for it as follows:

```
# Execute if ENABLE_CI_WORKFLOWS GitHub Actions variable is 'true'
if: vars.ENABLE_CI_WORKFLOWS == 'true'
```

## Folder Structure

ALL runnable workflows must be in the root of the .github/workflows folder. Subfolders are not allowed.

When adding or changing files, follow this file naming guidance:

- If the file is a "top level" workflow that will be triggered by an event such as a PR being opened or via CRON schedule, name it without any `_` prefix.
- If the file is a reusable workflow intended to be called by other workflows (and will include the `on: workflow_call:` trigger), prefix the filename with `_`.
