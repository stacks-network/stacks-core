What's New in 0.18
==================

Release 0.18 brings several major improvements to Blockstack Core.  It is not a
consensus-breaking release.  0.18.x nodes will continue to agree with 0.17.x
nodes about the chain state.

However, 0.18 is a **network-breaking release**.  In 0.18, a zone file can be
40kb, which is 10x larger than the maximum zone file size in 0.17.  Large zone
files announced to 0.18 will not be discovered by 0.17 nodes.  As such, all node
operators are encouraged to upgrade to 0.18 as soon as possible.

Release Highlights
------------------

**Server-side Subdomain Indexing**:  This release makes it so the
`blockstack-core` daemon eagerly indexes subdomain records found in zone files.
Name lookups and address lookups will return information for subdomains as well
as names.  The `blockstack_client` library will no longer be responsible for
maintaining subdomain state of its own.

**Any Name can Update a Subdomain**:  Any name can send out a subdomain update
record for a given subdomain.  It is no longer limited to the name that created
it.  However, subdomain transfers must be processed by the name that created
them for the time being.

**10x Zone File Size Increase**:  The 0.18 Atlas network allows a maximum zone
file size of 40kb.  This allows between 100 and 120 subdomains to be created in
a single transaction.

**New Subdomain Registrar**:  This version of the software ships with a new
subdomain registrar designed to take advantage of the above.

**Legacy Python Storage API Deprecation**:  This release deprecates the `/v1/store` API routes
in `blockstack api` in favor of Gaia hubs.  Gaia hubs are accessed directly by
`blockstack.js` via HTTP(S), and employ storage drivers to
communicate with non-HTTP data sources.  This was introduced in 0.16, and going
forward, will be the only supported way for reading and writing Blockstack app data.
The legacy Python API will be removed in the next release.

**Improved chain-state database**:  The
[virtualchain](https://github.com/blockstack/virtualchain) package has changed
the way it represents its consensus hashes and accepted transactions on disk.
The changes make certain queries much more efficient, such as name history
queries.  In addition, it makes block processing somewhat faster, and makes it
easier to add more opcodes in a future release.  It removes a lot of complexity
from Blockstack Core's consensus code.

Getting Started
---------------

The recommended way to get started with 0.18 is through its fast-sync mode.  To
migrate from a 0.17 node to a 0.18 node, we recommend the following steps:

```
# stop the old node
$ blockstack-core stop
$ mv ~/.blockstack-server ~/.blockstack-server.0.17

# start the new node
$ blockstack-core fast-sync
$ blockstack-core start
```

The old chain state database directory structure has changed, and is 
incompatible with this new release.  If you are
upgrading from a 0.17 node or older, you will need to remove your `.blockstack-server`
directory.

