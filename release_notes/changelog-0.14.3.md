What's New in 0.14.3
====================

Release 0.14.3 brings many incremental improvements over 0.14.2.  It does not
break consensus; 0.14, 0.14.1, and 0.14.2 nodes are compatible with 0.14.3 nodes.

This marks the beginning of a per-sprint release cycle.  Release notes will be
shorter between releases, since new releases will be scheduled every two to
three weeks.

Release Highlights
--------------------------------

* **Gaia Performance Improvements.**  The read and write paths of Gaia have been
refactored to run many I/O operations in parallel.  This leads to faster data
interaction times, even for indexed storage systems like Dropbox.

* **Support for Fast Registrations.** This release adds an `unsafe` attribute to
registration requests which, when enabled, directs core's registrar to issue
the blockstack transactions _preorder_, _register_, and _update_, with only 4, 
1, and 1 confirmations respectively. To support this, core must ignore some
of the safety checks, because our resolvers will not have processed the name
before the _update_ is issued.

* **Better Packaging for Test Mode.**  This release makes it easier to get
started testing Blockstack Core and Blockstack Browser alongside a Bitcoin
node in `regtest` mode.  Developers can register names and interact with storage
without having to spend Bitcoin or wait hours for names to be registered.

Selected Bugfixes and Fixes
---------------------------
More information on bugfixes can be found in GitHub issues (#454-#488 span this release).

* Improved performance of price checks
* Added zero confirmation balance checks
* In regtest, core will rewrite testnet adddresses so that browser does not need to "understand" testnet addresses
* Fixed bad behavior of setting temporary wallet keys
* Support for logging in without blockchain ID
* Issue #469 : Blockstack Core used to die in error cases when it should be 
able to fail more gracefully. This release fixes several such cases.

