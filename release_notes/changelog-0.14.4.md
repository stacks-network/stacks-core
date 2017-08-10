What's New in 0.14.4
====================

Release 0.14.4 brings some incremental improvements over 0.14.3, and
initial support for subdomains. It does not break consensus; 0.14,
0.14.1, and 0.14.2 nodes are compatible with 0.14.3 nodes.

Release Highlights
--------------------------------

* **Initial Support for Subdomains.**  This release includes initial support for
looking up subdomains. The blockstack client parses and correctly resolves
subdomain entries in zonefiles. This is done on the local client, with a cache
stored (by default) in `<home>/.blockstack/subdomains.db`

* **Simple Subdomain Registrar.** This release includes a simple subdomain
registrar which is configurable to accept subdomain registrations and include
those registrations in a user's zonefile by issuing periodic UPDATE transactions.

More information on the subdomain support is included in [/docs/subdomains.md]

Selected Bugfixes and Fixes
---------------------------

Information on bugfixes can be found in GitHub issues. The biggest bugfix over 0.14.3
is an updating of the test framework to fix some integration tests which were previously
failing.
