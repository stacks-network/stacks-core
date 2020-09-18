#!/bin/bash

# BLOCKSTACK_TEST_START_GAIA=0 BLOCKSTACK_TEST_START_BROADCASTER=0 BLOCKSTACK_TEST_CHECK_SUBDOMAIN_REGISTRAR=0 PYTHONPATH="$(pwd):$(pwd)/integration_tests" python2 integration_tests/bin/blockstack-test-scenario blockstack_integration_tests.scenarios.name_pre_reg_up_v2_upgrade_migration
# integration_tests/blockstack_integration_tests/scenarios/attic/name_preorder_multi_preorder_register.py

# BLOCKSTACK_TEST_START_GAIA=0 BLOCKSTACK_TEST_START_BROADCASTER=0 BLOCKSTACK_TEST_CHECK_SUBDOMAIN_REGISTRAR=0 PYTHONPATH="$(pwd):$(pwd)/integration_tests" python2 integration_tests/bin/blockstack-test-scenario blockstack_integration_tests.scenarios.name_pre_reg_v2_upgrade_migration

pkill bitcoind

BLOCKSTACK_TEST_START_GAIA=0 BLOCKSTACK_TEST_START_BROADCASTER=0 BLOCKSTACK_TEST_CHECK_SUBDOMAIN_REGISTRAR=0 PYTHONPATH="$(pwd):$(pwd)/integration_tests" python2 integration_tests/bin/blockstack-test-scenario blockstack_integration_tests.scenarios.name_pre_reg_quota_sameblock