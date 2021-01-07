This directory contains a Dockerfile that performs automated validation of the migration process from Stacks 1.0 to Stacks 2.0.

A sampling of STX balances and lockup schedules are tested.

The following steps are automatically performed:
1. Checkout and install Stacks 1.0.
2. Run a Stacks 1.0 fast-sync to get caught up to the latest chain state (as of the latest hosted snapshot).
3. Trigger a fast-sync-dump similar to how it will be triggered from the name threshold.
4. Perform the chainstate export step from the fast-sync-dump.
5. Checkout the Stacks 2.0 source, and copy over the newly exported chainstate.txt, and build.
6. Query the Stacks 1.0 db for 1000 address balances, and ~1000 lockup schedules.
7. Spin up both a Stacks 1.0 and Stacks 2.0 node, and validate the address balances match using the account RPC endpoints:
   * Stacks 1.0: `/v1/accounts/{address}/STACKS/balance`
   * Stacks 2.0: `/v2/accounts/{address-in-testnet-format}`
8. Validate lockup schedules in Stacks 2.0 match the samples dumped from the Stacks 1.0, using a contract map lookup:
   * `/v2/map_entry/ST000000000000000000002AMW42H/lockup/lockups`



### Running
This is a resources intensive process and can take upwards of an hour.

Ensure Docker is allocated at least 70GB disk size and 4GB memory.

Run the docker build:
```shell
cd migration-verification
DOCKER_BUILDKIT=1 BUILDKIT_PROGRESS=plain docker build --build-arg STACKS_V2_BRANCH=<branch or tag> .
```
