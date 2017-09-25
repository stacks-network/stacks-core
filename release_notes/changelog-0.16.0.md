What's New in 0.16
==================

Release 0.16 brings some improvements over 0.14.5.  It does not
break consensus; 0.14-0.14.5 nodes are compatible with 0.16 nodes.

Release Highlights
------------------

* **Support for Gaia Hub Storage Provider.** This release adds support for
connecting to our development gaia-hub.

* **New API Endpoint for Getting Name Count.** This release adds support scripts
to the `API` directory for supporting faster search indexing for new names. This
also includes support for indexing subdomains.

* **Include support better Support for using Client Payment Keys** This includes support
for supplying a key to perform payment operations on behalf of a client, and a mock insight-api
endpoint for obtaining balance for a particular address.

* **Better Support for Configuring Bind Address/Port in Regtest** This adds support for
setting bind addresses and ports.

Note on Versioning
------------------

To better align blockstack-core versioning and blockstack-browser versioning,
we skipped `0.15` entirely.

