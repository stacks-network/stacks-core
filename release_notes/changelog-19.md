What's New in 19
=================

Release 19 brings several major improvements to Blockstack Core.  It is not a
consensus-breaking release.  19.x nodes will continue to agree with 0.18.x
nodes about the chain state.

This release is a refactoring/house-keeping release in which many little-used
and deprecated features were removed.  This release also changes the versioning
scheme for Blockstack Core -- starting with this release, each new release will
increment the major version number.  The next release will be version 20.

Release Highlights
------------------

**Removal of the Python CLI**:  This release drops over 27,000 lines of code by
removing the Python Blockstack CLI.  This tool was superceded by the Blockstack
Browser, [blockstack.js](https://github.com/blockstack/blockstack.js), and the
Node.js [Blockstack CLI](https://github.com/blockstack/cli-blockstack).  The
storage and transaction logic is now implemented solely in `blockstack.js`,
which both the Browser and the Node.js CLI use.

**Removal of most POST Endpoints**:  As discussed in the release notes for 0.18,
the `/v1/store` endpoints were deprecated.  This release removes them
completely, and along with them, nearly every non-GET endpoint.  The only POST
endpoint remaining is `/v1/zonefile`, which lets you broadcast an
already-announced zone file.

**Moved Storage API and Drivers to Gaia Hubs**:  All storage drivers and the
storage API are now part of the [Blockstack Gaia
hub](https://github.com/blockstack/gaia), which is deployed separately.
Users no longer need to run a locally-hosted storage proxy to give applications
access to their data.  Instead, they can deploy a Gaia hub on a server of their
choice (or use a public-use Gaia hub like https://hub.blockstack.org).  This
makes mobile development much simpler and removes a consistent pain point for
installing and running the Blockstack Browser.

**Moved Transaction API to a Transaction Broadcaster**:  This codebase no longer
generates and broadcasts transactions.  This code has instead been moved to the
[transaction broadcaster
service](https://github.com/blockstack/transaction-broadcaster).  A user no
longer has to run a transaction-broadcasting daemon locally to register names --
instead, users can leverage a publicly-hosted one that they trust (however,
users retain the ability to run their own local daemon if they wish).

**Merger of the Indexer and RESTful API Processes**:  Blockstack Core is now a
single process that implements the blockchain indexer, the peer-to-peer interface,
and the RESTful API.  Before, the RESTful API had been a separate process that
was part of the now-defunct Python CLI.  This makes deploying a Blockstack Core
node much simpler.

**Better Behavior under Load**:  This release is much better at
accepting and handling many simultaneous requests than 0.18.  While P2P requests are still
serialized, the server is able to accept and queue multiple inbound connections
and gracefully shed load if it has too many clients.  This fixes a pernicious
bug whereby the Linux kernel will assume a Blockstack Core node under load is
experiencing a TCP SYN flood.

**Subdomain Processing Speedup**:  This release improves subdomain indexing by
nearly 200x by using more efficient database queries than 0.18.  This allows it
to process many more subdomain updates while keeping pace with the blockchain.

**RESTful API Query Speedup**:  Some RESTful API queries are faster -- both
asymptotically faster and faster by constant factors than 0.18.  These include
`/v1/names`, `/v1/names/{:name}/zonefile/{:zonefileHash}`, `/v1/addresses`, and
a few others.

**Better Documentation**:  The RESTful API documentation has been fleshed out
with sample schemas and error messages for all API calls.  Also, the
documentation in `docs/` has been revamped into a searchable database hosted at
https://docs.blockstack.org.

Getting Started
---------------

The recommended way to get started with 19 is through its fast-sync mode.  To
migrate from a 0.18 node to a 19 node, we recommend the following steps:

```
# stop the old node
$ blockstack-core stop
$ mv ~/.blockstack-server ~/.blockstack-server.0.18

# start the new node
$ blockstack-core fast-sync
$ blockstack-core start
```

The old chain state database directory structure has changed, and is 
incompatible with this new release.  If you are
upgrading from a 0.18 node or older, you will need to remove your `.blockstack-server`
directory.

This release no longer requires you to run `blockstack api start` to start the
RESTful API.  It will be activated by default on port 6270.
