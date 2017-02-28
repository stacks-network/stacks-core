What's New in 0.14.1
====================

Release 0.14.1 brings many incremental improvements over 0.14.  It does not
break consensus; 0.14 nodes are compatible with 0.14.1 nodes.

Release Highlights
------------------

* **Fast Synchronization**.  In its default setting, Blockstack needs to index
the underlying blockchain in order to construct its name database and Atlas
state.  This can take days.  To improve the user experience, 0.14.1 adds a
`fast_sync` command that allows the user to fetch, verify, and bootstrap off of
an existing node's recent state.  Synchronizing with `fast_sync` takes only
a few minutes.

* **RESTful API**.  Blockstack now comes with a RESTful API, available by
default at `http://localhost:6264`.  The API enables external applications to
register and manage names, send and receive wallet funds, fetch and store
off-chain data, and query the Blockstack network state.  Users control which
applications have access to which endpoints, so they have the final say over
which capabilities each application may access.  Documentation is available
[here](https://github.com/blockstack/blockstack-core/tree/master/api).

* **Zone file wizard**.  The CLI interface in 0.14.1 comes with an interactive
zone file wizard that makes it easy to add, remove, and change the priority of
URLs to off-chain data.  Before, users were expected to craft new zone files by
hand, which proved tedious and error-prone.

* **Data Stores (experimental)**.  This release comes with an experimental API
for creating data stores.  A data store is a per-application and per-name
filesystem whose data is replicated across a set of storage providers (specified
in the name's zone file).  The intended use-case is to give an application a way to 
persistently store a user's data in the place(s) the user chooses.  This way, users
always have access to their data and can take it with them from application to
application, and developers are no longer responsible for hosting it.

* **Merged Repositories**.  Blockstack's CLI, indexer, integration tests, and
  registrar are all now present in this repository.

Upgrade Notes
-------------

If you are upgrading from a previous installation of Blockstack:

    * In `~/.blockstack/client.ini`, you should change `rpc_token=...` to
    `api_password=...`.

    * You should upgrade your wallet to the latest supported format.  This can
      be done with `blockstack setup_wallet`.  Be sure to back up your wallet
      first, for safety (the wallet file is at `~/.blockstack/wallet.json`).

    * You must start the API server before carrying out name operations.  This can be done
      with `blockstack api start`.

Selected Bugfixes and Fixes
---------------------------

* You can specify the wallet password on the CLI with `--password PASS`.

* You can enable debug output on the CLI with `--debug`.

* You can have the CLI assume the default response with `--yes`.

* You can try out name registration commands with 

* Name registration commands are much more responsive now, due to
parallelization of the internal safety checks and queries the CLI tool needs
to make.

* Various ad-hoc safety-checks and error-reporting are now consolidated,
and the error-reporting logic has been made consistent.


