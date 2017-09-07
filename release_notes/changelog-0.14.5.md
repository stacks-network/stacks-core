What's New in 0.14.5
====================

Release 0.14.5 brings some improvements over 0.14.4.  It does not
break consensus; 0.14-0.14.4 nodes are compatible with 0.14.5 nodes.

Release Highlights
--------------------------------

* **Faster Search Indexing for New Names.** This release adds support scripts
to the `API` directory for supporting faster search indexing for new names. This
also includes support for indexing subdomains.

* **Added Docker Scripts.** This release includes support for running dockerized
versions of blockstack core and it's integration tests.

* **Include support for Transfers/Updates from Browser** This includes support
for supplying a key to perform updates and transfers on behalf of a RPC client.

* **Include support for HTTPS communication with Blockstack nodes** Clients now
by default attempt to communicate with node.blockstack.org servers over HTTPS.

