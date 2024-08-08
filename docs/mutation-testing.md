# Mutation Testing

This document describes how to run mutation testing locally to mimic the outcome of a PR, without the CI limitation it provides by timing out after 6 hours.
[Here is the script](../contrib/tools/local-mutation-testing.sh) to run the tests locally by running the mutants created by the changes between `HEAD` and develop. 
It does automatically all the steps explained below.

From the root level of the stacks-core repository run
```sh
./contrib/tools/local-mutation-testing.sh
```

## Prerequirements

Install the cargo mutants library
```sh
cargo install --version 24.7.1 cargo-mutants --locked
```


## Steps 
1. Be on source branch you would use for the PR.
2. Create diff file comparing this branch with the `develop` branch
    ```sh
    git diff origin/develop..HEAD > git.diff
    ```
3. Clean up the diff file and create auxiliary files
   ```sh
    awk '
        /^diff --git/ {
            diff_line = $0
            getline
            if ($0 !~ /^(deleted file mode|similarity index)/) {
                print diff_line
                print
            }
        }
        !/^(diff --git|deleted file mode|similarity index|rename from|rename to)/ {print}
    ' git.diff > processed.diff
    
    # Extract mutants based on the processed diff
    cargo mutants --in-diff processed.diff --list > all_mutants.txt

    # Create a directory for organizing mutants
    mkdir -p mutants_by_package
    
    # Organize mutants into files based on their main folder
    while IFS= read -r line; do
          package=$(echo "$line" | cut -d'/' -f1)

          case $package in
            "stackslib")
              echo "$line" >> "mutants_by_package/stackslib.txt"
              ;;
            "testnet")
              echo "$line" >> "mutants_by_package/stacks-node.txt"
              ;;
            "stacks-signer")
              echo "$line" >> "mutants_by_package/stacks-signer.txt"
              ;;
            *)
              echo "$line" >> "mutants_by_package/small-packages.txt"
              ;;
          esac
        done < all_mutants.txt
   ```
4. Based on the package required to run the mutants for  
   a. Stackslib package 
   ```sh
    regex_pattern=$(sed 's/[][()\.^$*+?{}|]/\\&/g' "mutants_by_package/stackslib.txt" | paste -sd'|' -)

    RUST_BACKTRACE=1 BITCOIND_TEST=1 \
    cargo mutants --timeout-multiplier 1.5 --no-shuffle -vV \
        -F "$regex_pattern" \
        -E ": replace .{1,2} with .{1,2} in " \
        --output "./stackslib_mutants" \
        --test-tool=nextest \
        -- --all-targets --test-threads 1
   ```
   b. Stacks-node (testnet) package
   ```sh
    regex_pattern=$(sed 's/[][()\.^$*+?{}|]/\\&/g' "mutants_by_package/testnet.txt" | paste -sd'|' -)

    RUST_BACKTRACE=1 BITCOIND_TEST=1 \
    cargo mutants --timeout-multiplier 1.5 --no-shuffle -vV \
        -F "$regex_pattern" \
        -E ": replace .{1,2} with .{1,2} in " \
        --output "./testnet_mutants" \
        --test-tool=nextest \
        -- --all-targets --test-threads 1
   ```
   c. Stacks-signer
   ```sh
    regex_pattern=$(sed 's/[][()\.^$*+?{}|]/\\&/g' "mutants_by_package/stacks-signer.txt" | paste -sd'|' -)

    RUST_BACKTRACE=1 BITCOIND_TEST=1 \
    cargo mutants --timeout-multiplier 1.5 --no-shuffle -vV \
        -F "$regex_pattern" \
        -E ": replace .{1,2} with .{1,2} in " \
        --output "./stacks-signer_mutants" \
        --test-tool=nextest \
        -- --all-targets --test-threads 1
   ```
   d. All other packages combined  
    ```sh
    regex_pattern=$(sed 's/[][()\.^$*+?{}|]/\\&/g' "mutants_by_package/small-packages.txt" | paste -sd'|' -)

    cargo mutants --timeout-multiplier 1.5 --no-shuffle -vV \
        -F "$regex_pattern" \
        -E ": replace .{1,2} with .{1,2} in " \
        --output "./small-packages_mutants" \
        --test-tool=nextest \
        -- --all-targets --test-threads 1
   ```

## How to run one specific mutant to test it

Example of output which had a missing mutant
```sh
MISSED   stacks-signer/src/runloop.rs:424:9: replace <impl SignerRunLoop for RunLoop<Signer, T>>::run_one_pass -> Option<Vec<SignerResult>> with None in 3.0s build + 9.3s test
```

Example of fix for it
```sh
RUST_BACKTRACE=1 BITCOIND_TEST=1 \
cargo mutants -vV \
  -F "replace process_stackerdb_event" \
  -E ": replace <impl SignerRunLoop for RunLoop<Signer, T>>::run_one_pass -> Option<Vec<SignerResult>> with None in " \
  --test-tool=nextest \
  -- \
  --run-ignored all \
  --fail-fast \
  --test-threads 1
```

General command to run
```sh
RUST_BACKTRACE=1 BITCOIND_TEST=1 \
cargo mutants -vV \
  -F "replace process_stackerdb_event" \
  -E ": replace [modify this] with [modify this] in " \
  --test-tool=nextest \
  -- \
  --run-ignored all \
  --fail-fast \
  --test-threads 1
```
