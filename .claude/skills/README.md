# Claude Code skill wrappers

The canonical, harness-neutral skill workflows live under `.agents/skills/`. Claude Code discovers
project skills under `.claude/skills/`, so this parallel directory contains thin wrappers that
direct Claude Code to the corresponding canonical workflows.

Keep workflow instructions in `.agents/skills/` and duplicate only the metadata required for
discovery in each wrapper. The wrappers are regular files rather than symbolic links so that they
work reliably in Windows checkouts.

For discovery details, see the [Claude Code skills
documentation](https://code.claude.com/docs/en/skills).
