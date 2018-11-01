What's New in 20
================

Release 20 is a **consensus-breaking release** that introduces the first version
of the Stacks blockchain.  Versions 19 and prior are *incompatible* with this
release and will diverge from v20 nodes.

Release Highlights
------------------

**Native Stacks Token**.  This release completes the first version of the Stacks
blockchain.  Details can be found on this [forum
post](https://forum.blockstack.org/t/blockstack-annual-hard-fork-2018/6518).

**Blockstack Accounts API**.  This release adds `/v1/accounts` endpoints to the
RESTful API for querying account balances and transaction histories.  Please see
the relevant [documentation](https://core.blockstack.org) for details.

Getting Started
---------------

The recommended way to get started with v20 is through its fast-sync mode.  To
migrate from a v19 node to a v20 node, we recommend the following steps:

```
# stop the old node
$ blockstack-core stop
$ mv ~/.blockstack-server ~/.blockstack-server.19

# start the new node
$ blockstack-core fast_sync
$ blockstack-core start
```

The old chain state database directory structure has changed, and is 
incompatible with this new release.  If you are
upgrading from a v19 node or older, you will need to remove your `.blockstack-server`
directory.
