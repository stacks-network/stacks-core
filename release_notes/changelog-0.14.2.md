What's New in 0.14.2
====================

Release 0.14.2 brings many incremental improvements over 0.14.1.  It does not
break consensus; 0.14 and 0.14.1 nodes are compatible with 0.14.2 nodes.

Release Highlights
------------------

* **Single-player Storage**.  This release includes an initial stable release of Gaia,
the Blockstack storage system.  This was an experimental feature in the previous
release.  Using Gaia, applications have a `localStorage`-like data container
that is replicated to one or more back-end storage providers (so users own their
data, and developers do not host it).

* **Better Fee Estimation**.  The name registration fee estimation code has been
reworked to more accurely estimate the number of bytes each transaction will
require.  Moreover, the transaction-building logic will try to minimize the
number of "dust" UTXOs to consume, in order to keep the total size of the
transaction small.

* **Better Wallet Security**.  The wallet format consolidates all sensitive
information into one place and uses the `scrypt` key-lengthening algorithm to
make brute-forcing a wallet password memory-intensive.

* **Namespace Wizard**.  This release includes an interactive wizard for setting
up and activating namespaces.  The wizard gives users ample warnings about how
much namespace creations cost, and helps users decide on name price curves.

* **Dropbox and Indexed Storage Support**.  This release adds support for
Dropbox, by way of a data-indexing subsystem that makes it possible to use other
commodity cloud storage providers like Google Drive.  The indexing subsystem
addresses the problem that we can't tell what the URL to uploaded data is until
we actually upload it (i.e. this is not a problem for local disk or S3).  This
paves the way for support for more commodity storage systems in the future,
where the data URLs are derived from the data itself.

Selected Bugfixes and Fixes
---------------------------

* Garbage collection has been improved in the Indexer logic, so nodes under
  heavy load should not run out of memory.

* There is now a test harness for storage drivers, which will make them easier
  to develop and test in CI environments.

* The registrar will no longer give up on trying to broadcast name transactions,
  even if the process is stalled for over a day.

* Blockstack no longer depends on `pybitcoin` or `pybitcointools`.  The relevant
  functionality has been folded into `virtualchain`.

* The RESTful API offers some extra control points to allow clients to set up
  storage drivers and query the API endpoint's configuration.

