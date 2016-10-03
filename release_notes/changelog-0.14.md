What's New in 0.14
==================

Release 0.14 brings several major improvements.  It is a **consensus-breaking release.**  Users are encouraged to upgrade to 0.14 as soon as possible in order to stay on the same name set as everyone else.

Release Highlights
------------------

* **Sqlite3 Database**.  The consensus logic has been re-written from the ground up to use a sqlite3 database instead of a flat JSON file for storing the name set.  This reduces RAM usage by 20x (~3 GB to ~150MB).

* **P2P Blockchain Synchronization.**  The blockchain synchronization logic (in [virtualchain](https://github.com/blockstack/virtualchain)) has been re-written to use the Bitcoin p2p interface whenever possible, instead of the RPC interface.  This not only improves download performance by 6x, but also removes the need for a multiprocess work pool (improving reliability).

* **Atlas Protocol.**  Blockstack Core now implements its own unstructured p2p network (the Atlas network) for replicating the set of zonefiles amongst themselves.  Each node builds a 100% replica of all zonefiles using the set of zonefile hashes in the name database.  Nodes walk the peer graph to select K random neighbors; we reduce bias with a Metropolis-Hastings random walk with delayed acceptance.

* **Resolver API Server.**  As part of our ongoing consolidation efforts, Blockstack Core now ships with a resolver HTTP server and documentation.

* **Multisig Support.**  Blockstack Core now accepts name operations from multisig addresses.

* **Testnet Support.**  Blockstack Core can now operate on Bitcoin's testnet.  This can be achieved by setting `BLOCKSTACK_TESTNET=1` in the environment.


Upgrade Notes
-------------

* You will need to upgrade your client to v0.14 as well as your server.  Some RPC methods and semantics have changed.

Consensus-breaking Changes
--------------------------

* Support for pay-to-script-hash Bitcoin addresses has been added, in order to support multisig ownership and payment addresses.  Versions 0.13 and earlier will reject transactions with p2sh addresses.

* Name and namespace prices have been re-adjusted by a factor of 0.417 to preserve the $230 USD to 1 BTC exchange rate in 0.13.  They take effect at block XXX.

* Name lifetimes in all namespaces have been increased to 2 years.  This is phase 1 of a 2-phase name/identity improvement plan, discussed [here](https://github.com/blockstack/blockstack-core/issues/244#issuecomment-251226177).


Selected Changelog
------------------

* Do not accept zonefiles unless we can determine the name and transaction ID that paid for the `NAME_UPDATE`.

* Atlas: retry storage drivers for missing zonefiles every 12 hours.

* Add a notion of "epochs" to encode what the current name price and namespace lifetime are, based on the block height.

* Make expired `NAMESPACE_REVEAL` name operations restorable, so that `verifydb` database verification logic can handle them.

* Do not use `sys.exit(1)` on an assertion failure; use `os.abort()`.

* The `get_nameops_*` method family has been renamed to `get_records_*`.

* Run multiple instances of the core server in the test framework in order to enable Atlas testing.

* Check that the config files are compatible with the running version of the server.

* Do not require a transaction to have a single public key in its `scriptSig` field.

* Check for absurdly high-value transaction fees when broadcasting.

* Identify client storage drivers to use specifically for zonefiles or specifically for profiles.

* Cap profiles to 1MB when using Blockstack Core as a storage proxy.

* Improve SNV efficiency by serving batches of consensus hashes.

* Move most configuration-parsing logic to the client library.

* Remove old `testset` mode, since it never really worked anyway.

* Move all transaction-creation logic to the client.  Blockstack Core no longer creates transactions.

* Remove transaction subsidization logic from Blockstack Core.  This is the registrar's responsibility.

* Remove all remaining Twisted API server and Twisted DHT logic.

* Automatic database backups; access with `blockstack-server restore`.

* Remove UTXO service query logic from Blockstack Core.  This is the client's responsibility.

* Spin off `blockstack_zones`, `blockstack_utxo`, `blockstack_profiles`, and `blockstack_integration_tests` into separate packages.

* Fix `NAME_TRANSFER` name operation restoration and SNV logic to use the correct consensus hash.

* Remove unfinished `blockmirrord` code; merge zonefile and profile API code into the main API server.

* Log unavailability of blockchain announcement payloads.
