## steps to reproduce working version with different number lines:

in trials/mutants-stable/caught.txt replace line number 23 with 109
the append.sh won't work anymore
the append-match.sh works

```bash
sh append-match.sh

```

example run:

```bash
./modular-mutants-run.sh stx-genesis lib.rs test_this init_ next as.rs ab cd ef clarity lib.rs stacks-node
# the command above makes and runs 579 mutants on these regex matches:

# functions named 'test_this', 'init_' and 'next' (everything that starts with any of the given names) from 'lib.rs' file of 'stx-genesis' package (5 mutants)
stx-genesis/[^/]+/lib.rs.*(?:test_this|init_|next).*->

# functions that start with 'ab', 'cd' or 'ef' from files named 'as.rs' of 'stx-genesis' package (0 mutants)
stx-genesis/[^/]+/as.rs.*(?:ab|cd|ef).*->

# all functions from 'lib.rs' files of the 'clarity' package (4 mutants)
clarity/[^/]+/lib.rs.*(?:).*->

# all functions from all files of 'stacks-node' package (570 mutants)
stacks-node/[^/]+/.*(?:).*->
```

# Create Stable

Only run it once and the packages that should be updated from zero. Then it will be the reference point for the upcoming PRs that modify these functions

### recap flow for a developer which

1. works on functions and modifies them
2. before commiting -> `call git-diff.sh`
