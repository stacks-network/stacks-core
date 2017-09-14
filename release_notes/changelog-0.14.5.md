What's New in 0.14.5
====================

Release 0.14.5 brings some improvements over 0.14.4.  It does not
break consensus; 0.14-0.14.4 nodes are compatible with 0.14.5 nodes.

Release Highlights
------------------

* **Faster Search Indexing for New Names.** This release adds support scripts
to the `API` directory for supporting faster search indexing for new names. This
also includes support for indexing subdomains.

* **Added Docker Scripts.** This release includes support for running dockerized
versions of blockstack core and it's integration tests.

* **Include support for Transfers/Updates from Browser** This includes support
for supplying a key to perform updates and transfers on behalf of a RPC client.

* **Include support for HTTPS communication with Blockstack nodes** Clients now
by default attempt to communicate with node.blockstack.org servers over HTTPS.

Hotfix 0.14.5.1
---------------

* A pair of bugs in the blockstackd port lookup code resulted in a `blockstack api`
service *always* using 6263, even if the client.ini specifies otherwise. This led
to issues for non-default blockstackd setups.

Pulls and Contributors
----------------

[Fix Broken Slack Badge](https://github.com/blockstack/blockstack-core/pull/537)
[Hotfix for CORS problem in Subdomain Registrar](https://github.com/blockstack/blockstack-core/pull/541 )
[Support for issuing updates with an owner key](https://github.com/blockstack/blockstack-core/pull/543)
[Adds HTTPS support to blockstack proxy](https://github.com/blockstack/blockstack-core/pull/544)
[Shell bang python2](https://github.com/blockstack/blockstack-core/pull/548)
[Persistent setting of keys](https://github.com/blockstack/blockstack-core/pull/550)
[Add Dockerfile and Build/Run Instructions](https://github.com/blockstack/blockstack-core/pull/551)
[Remove Wildcard Imports](https://github.com/blockstack/blockstack-core/pull/552)
[Add support for passing owner key to transfer](https://github.com/blockstack/blockstack-core/pull/555)
[Change generation path for index.html of the API Docs](https://github.com/blockstack/blockstack-core/pull/557)
[Add explicitely Python to uwsgi config](https://github.com/blockstack/blockstack-core/pull/559)
[Update search index with new profiles](https://github.com/blockstack/blockstack-core/pull/560)
[Update Readme with better Docker instructions](https://github.com/blockstack/blockstack-core/pull/562)
[Use newest version in API documentation](https://github.com/blockstack/blockstack-core/pull/564)
[Indexing subdomains on search endpoint](https://github.com/blockstack/blockstack-core/pull/570)
[Add CLI For Docker Images](https://github.com/blockstack/blockstack-core/pull/572)
[Integration Tests in Docker](https://github.com/blockstack/blockstack-core/pull/579)
[Add Snap builds for Blockstack](https://github.com/blockstack/blockstack-core/pull/580)

Thanks to the contributors to this release:

- @elopio
- @kantai
- @jackzampolin
- @peacekeeper
- @jcnelson
- @muneeb-ali
- @vbrandl
- @larrysalibra
