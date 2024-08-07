# Mutation Testing

This document describes how to run mutation testing locally to mimic the outcome of a PR, without the CI limitation it provides by timing out after 6 hours.
[Here is the script](../contrib/tools/local-mutation-testing.sh) to run mutation locally running the mutants created by the changes between the current branch and develop. It does automatically all the steps explained below.

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
1. be on source branch you would use for the PR.
2. create diff file comparing this branch with the `develop` branch
    ```sh
    git diff origin/develop..HEAD > git.diff
    ```
3. clean up the diff file and create auxiliary files
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
4. based on the package required to run the mutants for  
   a. stackslib package 
   ```sh
    regex_pattern=$(sed 's/[][()\.^$*+?{}|]/\\&/g' "mutants_by_package/stackslib.txt" | paste -sd'|' -)

    cargo mutants --timeout-multiplier 1.5 --no-shuffle -vV \
        -F "$regex_pattern" \
        -E ": replace .{1,2} with .{1,2} in " \
        --output "./stackslib_mutants" \
        --test-tool=nextest \
        -- --all-targets --test-threads 1
   ```
   b. stacks-node (testnet) package
   ```sh
    regex_pattern=$(sed 's/[][()\.^$*+?{}|]/\\&/g' "mutants_by_package/testnet.txt" | paste -sd'|' -)

    cargo mutants --timeout-multiplier 1.5 --no-shuffle -vV \
        -F "$regex_pattern" \
        -E ": replace .{1,2} with .{1,2} in " \
        --output "./testnet_mutants" \
        --test-tool=nextest \
        -- --all-targets --test-threads 1
   ```
   c. stacks-signer
   ```sh
    regex_pattern=$(sed 's/[][()\.^$*+?{}|]/\\&/g' "mutants_by_package/stacks-signer.txt" | paste -sd'|' -)

    cargo mutants --timeout-multiplier 1.5 --no-shuffle -vV \
        -F "$regex_pattern" \
        -E ": replace .{1,2} with .{1,2} in " \
        --output "./stacks-signer_mutants" \
        --test-tool=nextest \
        -- --all-targets --test-threads 1
   ```
   d. all other packages combined  
    ```sh
    regex_pattern=$(sed 's/[][()\.^$*+?{}|]/\\&/g' "mutants_by_package/small-packages.txt" | paste -sd'|' -)

    cargo mutants --timeout-multiplier 1.5 --no-shuffle -vV \
        -F "$regex_pattern" \
        -E ": replace .{1,2} with .{1,2} in " \
        --output "./small-packages_mutants" \
        --test-tool=nextest \
        -- --all-targets --test-threads 1
   ```
