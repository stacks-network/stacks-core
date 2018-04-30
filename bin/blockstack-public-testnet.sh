#!/bin/sh

function exit_error() {
    echo $1
    exit 1
}

which blockstack-test-scenario 2>&1 > /dev/null || exit_error 'You must install the integration test suite first'
which blockstack-core 2>&1 > /dev/null || exit_error 'You must install Blockstack Core first'

BLOCKSTACK_TEST_CLIENT_BIND=0.0.0.0 BLOCKSTACK_PUBLIC_TESTNET=1 BLOCKSTACK_CORE_VERSION="0.0.0.1" blockstack-test-scenario blockstack_integration_tests.scenarios.testnet_public
