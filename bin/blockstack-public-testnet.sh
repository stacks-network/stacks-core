#!/bin/sh

function exit_error() {
    echo $1
    exit 1
}

which blockstack-test-scenario 2>&1 > /dev/null || exit_error 'You must install the integration test suite first'
which blockstack-core 2>&1 > /dev/null || exit_error 'You must install Blockstack Core first'

# take all inbound requests
export BLOCKSTACK_TEST_CLIENT_BIND="0.0.0.0"

# activate public testnet features (i.e. make Atlas run at the normal speed)
export BLOCKSTACK_PUBLIC_TESTNET="1"

# make ourselves look like we're an old Core node, so mainnet nodes don't add us as peers
export BLOCKSTACK_CORE_VERSION="0.0.0.1"

blockstack-test-scenario blockstack_integration_tests.scenarios.testnet_public
