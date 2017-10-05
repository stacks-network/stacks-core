What's New in 0.17
==================

Release 0.17 brings several major improvements.  It is a **consensus-breaking release.**  Users are encouraged to upgrade to 0.17 as soon as possible in order to stay on the same name set as everyone else.

The hard fork block number is 488500.

Release Highlights
------------------

All of these changes are consensus-breaking.

* **Updated USD/BTC Exchange rate**.  Names and namespaces are made 10x cheaper in this release

* **Support for Segwit Transactions**.  This release adds support for Segwit transactions nested inside BIP16 pay-to-script-hash outputs.  Blockstack supports p2sh-p2wpkh and p2sh-p2wsh outputs, and can use the latter to support multisig-owned names.

* **Namespace creator receives register and renewal fees.**  This release adds support for a "version 2" namespace, where the `NAME_PREORDER` and `NAME_RENEWAL` operations must send their name fees to the address used by the namespace's `NAMESPACE_PREORDER` payment address.  This way, the person or group who creates a namespace can earn back the BTC burnt in doing so by encouraging other users to create names.  This is meant to encourage application developers to create their own namespaces, since this gives them a direct path to monetization.  The namespace creator will collect all fees starting from the block height of the `NAMESPACE_REVEAL`, and ending to 52595 blocks later (about 1 year).  After this period of time passes, name registration and renewl fees are sent to the default burn address `1111111111111111111114oLvT2`.  This behavior was implemented to remove the incentive to squat namespaces.

* **Combined `NAME_REGISTRATION` and `NAME_UPDATE`**.  A `NAME_REGISTRATION` operation may also include a zone file hash.  This reduces the number of transactions required to register a name and use it in Blockstack applications from three to two.  Normal `NAME_REGISTRATION` and `NAME_UPDATE` are still supported.

* **Combined `NAME_RENEWAL`, `NAME_TRANSFER`, and `NAME_UPDATE`**.  A `NAME_RENEWAL` operation may also include a zone file hash and the address of a new owner.  This reduces the number of transactions required by a name owner or registrar to transfer a name to a new owner.  The recipient does not need to immediately renew the name once received, and the recipient can have the sender write in the recipient's desired zone file hash so that when the recipient receives the name, it has the recipient's desired zone file in the Atlas network.  Normal `NAME_RENEWAL`, `NAME_TRANSFER`, and `NAME_UPDATE` operations are still supported.

* **Renewal Grace period**.  Once a name expires, the user has a 5000-block grace period in which to renew the name.  No other operation on the name will be accepted, and the name will stop resolving.  If the user does not renew within 5000 blocks, someone else will be able to preorder and register it.

Upgrade Notes
-------------

**Quick start (recommended):**  You can get up and running in 15 minutes or less using these instructions:

* Run `blockstack-core stop` to stop your currently-running node.

* If you have a `~/.blockstack-server` folder, you should move it out of the way.

* Run `blockstack-core fast_sync` to get a recent 0.17 snapshot.

* Run `blockstack-core start` to re-start your node.
   * Run `blockstack-core --debug start` for extra verbosity.
   * Logs will be written to `~/.blockstack-server/blockstack-server.log`.

* If you have a 0.14 node, you can verify that the 0.17 node is consistent with it by comparing the 0.14 node's consensus hash with the 0.17 node's consensus hash at the same block (both can be obtained with `blockstack getinfo` and `blockstack consensus $BLOCK_HEIGHT`).

**Full Re-index (experts only):**  If you are running a Blockstack Core 0.14 node, and want to avoid fast-sync, you will need to re-index the Bitcoin blockchain from scratch.  To do so, follow these instructions:

* Run `blockstack-core stop` to stop your currently-running node.

* Back up the `snapshots` file like so.  Remember the back up path; it will be used later.

```
    $ mv ~/.blockstack-server/blockstack-server.snapshots ~/.blockstack-server/blockstack-server.snapshots.bak.0.14
```

* Back up or remove the following files from your `~/.blockstack-server` directory: `blockstack-server.db`, `blockstack-server.lastblock`, and `atlas.db`.  Example:

```
    $ mv ~/.blockstack-server/atlas.db ~/.blockstack-server/atlas.db.bak.0.14`
    $ mv ~/.blockstack-server/blockstack-server.db ~/.blockstack-server/blockstack-server.db.bak.0.14
    $ mv ~/.blockstack-server/blockstack-server.lastblock ~/.blockstack-server/blockstack-server.lastblock.bak.0.14
```

* Remove the `blockstack-server.db.XXX` backups in `~/.blockstack-server/backups/`, since they will be unusable.

* Change the `server_version` field under `[blockstack]` in `~/.blockstack-server/blockstack-server.ini` to `0.17.0.0` once you have done all of the above.  **Your node will not start until you have done this.**

* Run the following to start your node.  Note the `--expected-snapshots` argument!
   * The `--expected-snapshots` argument should point to wherever you backed up your old `blockstack-server.snapshots` file.
   * Run with `--debug` for extra verbosity.
   * Logs will be written to `~/.blockstack-server/blockstack-server.log`.

```
    $ blockstack-core start --expected-snapshots ~/.blockstack-server/blockstack-server.snapshots.bak.0.14
```
  
