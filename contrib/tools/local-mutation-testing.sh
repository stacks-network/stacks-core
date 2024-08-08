#!/bin/bash

set -euo pipefail

# Install cargo-mutants
cargo install --version 24.7.1 cargo-mutants --locked

# Create diff file between current branch and develop branch
git diff origin/develop...HEAD > git.diff

# Remove git diff files about removed/renamed files
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

# Function to run mutants for a package
run_mutants() {
    local package=$1
    local threshold=$2
    local output_dir=$3
    local mutant_file="mutants_by_package/${package}.txt"

    if [ ! -f "$mutant_file" ]; then
        echo "No mutants found for $package"
        return 0
    fi

    local regex_pattern=$(sed 's/[][()\.^$*+?{}|]/\\&/g' "$mutant_file" | paste -sd'|' -)
    local mutant_count=$(cargo mutants -F "$regex_pattern" -E ": replace .{1,2} with .{1,2} in " --list | wc -l)
    
    if [ "$mutant_count" -gt "$threshold" ]; then
        echo "Running mutants for $package ($mutant_count mutants)"
        RUST_BACKTRACE=1 BITCOIND_TEST=1 \
        cargo mutants --timeout-multiplier 1.5 --no-shuffle -vV \
            -F "$regex_pattern" \
            -E ": replace .{1,2} with .{1,2} in " \
            --output "$output_dir" \
            --test-tool=nextest \
            --package "$package" \
            -- --all-targets --test-threads 1 || true

        echo $? > "${output_dir}/exit_code.txt"
    else
        echo "Skipping $package, only $mutant_count mutants (threshold: $threshold)"
    fi
    
    return 0
}

# Run mutants for each wanted package
run_mutants "stacks-signer" 500 "./stacks-signer_mutants" || true
run_mutants "stacks-node" 540 "./stacks-node_mutants" || true
run_mutants "stackslib" 72 "./stackslib_mutants" || true
