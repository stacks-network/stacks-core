#!/bin/bash

# Create mutants directory
mkdir mutants

### Run mutation testing on the packages uncommented

# Run mutation testing for clarity package
cargo mutants --package clarity --output mutants/clarity

# Run mutation testing for libsigner package
cargo mutants --package libsigner --output mutants/libsigner

# Run mutation testing for libstackerdb package
cargo mutants --package libstackerdb --output mutants/libstackerdb

# Run mutation testing for pox-locking package
cargo mutants --package pox-locking --output mutants/pox-locking

# Run mutation testing for stacks-common package
cargo mutants --package stacks-common --output mutants/stacks-common

# Run mutation testing for stx-genesis package
cargo mutants --package stx-genesis --output mutants/stx-genesis


# Run mutation testing for stacks-signer package - working, 10 min approx. 
# cargo mutants --package stacks-signer --output mutants/stacks-signer

# Commented out mutation testing for stacks-node package due to test errors and long compile/testing time
# cargo mutants --package stacks-node --output mutants/stacks-node

# Commented out mutation testing for stackslib package due to long compile/testing time
# cargo mutants --package stackslib --output mutants/stackslib
