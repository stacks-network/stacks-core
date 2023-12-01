# Mutation Testing

### What is mutation testing and how does it work?

Mutation testing is a technique of evaluating the effectiveness of a series of tests by introducing small changes to the code (mutations) and checking if the tests can detect these small changes.
Cargo-mutants is an external library installed to cargo, through which you can run mutants on the code, and it consists of:

- Building and testing the baseline code (no mutations).
- If the previous step fails, no mutants are applied, since the base code fails. Otherwise, copy the code to another location, apply mutations and then run `cargo build` and `cargo test` commands for each mutation.

### Install and run

In order to install cargo-mutants crate:

```
cargo install --locked cargo-mutants
```

In order to run mutated tests:

```bash
# In the whole workspace
cargo mutants
# Only in the 'clarity' package
cargo mutants --package clarity
# In files named 'signatures.rs' from the whole workspace
cargo mutants -f signatures.rs
# Only in files named 'signatures.rs' only from the 'clarity' package
cargo mutants --package clarity -f signatures.rs
# From all files except the ones named 'signatures.rs' and 'lib.rs' from the whole workspace
cargo mutants -e signatures.rs -e lib.rs
# Output from 'clarity' package to a specific directory in the workspace
cargo mutants --package clarity --output mutants/clarity
# To list all the possible mutants
cargo mutants --list
# To list all the files with possible mutants:
cargo mutants --list-files
```

In order to exclude a function from being mutated, parse the `#[mutants::skip]` attribute above it.

### Reading the output

There are 2 places where the progress of mutations are shown: terminal and [output folders](https://mutants.rs/mutants-out.html).
The terminal shows information about the progress of the mutants:

- How many mutants out of the total were tested (`1274/2912 mutants tested, 44% done`).
- Mutants status so far (`280 missed, 209 caught, 799 unviable`).
- Time elapsed and remaining (`141:36 elapsed, about 168 min remaining`).
- Tests missed so far (`clarity/src/vm/database/key_value_wrapper.rs:77: replace rollback_value_check with () ... NOT CAUGHT in 22.8s build + 17.2s test`).
- Current job (`clarity/src/vm/ast/parser/v2/mod.rs:167: replace Parser<'a>::skip_to_end with () ... 2.1s build`)

`mutants.out` - This is the folder where the mutants test output is written, and is composed of:

- log - The folder of the command log, here you can find the output of the cargo build and cargo test commands for every mutation.
- caught.txt - The file where caught mutations are logged (`clarity/src/vm/types/mod.rs:871: replace Value::size -> u32 with 1`).
- debug.log - The output of the cargo mutants command.
- lock.json - A file with fs2 lock on it in order to prevent 2 jobs from writing to the same directory at the same time, containing runtime information (cargo mutants version, start time, hostname, username).
- missed.txt - Missed mutations - mutations that are successful at cargo build, not detected in tests (`clarity/src/vm/types/signatures.rs:1766: replace TupleTypeSignature::size -> u32 with 1`).
- mutants.json - A list with every mutation applied, written before the testing begins (filename, line, return type, replacement etc).
- outcome.json - List of outcomes for every mutation (mutant applied, log path, results for build/test phases with status and command args)
- timeout.txt - Mutations that timed out
- unviable.txt - Unviable mutations (When a mutation is applied and it causes the cargo build command to fail)

`mutants.out.old` - This is the folder where _mutants.out_ folder’s content is copied into, on successive runs (it’s contents are being overwritten), making way for the next logs.
