# Blockstack Core

[![PyPI](https://img.shields.io/pypi/v/blockstack.svg)](https://pypi.python.org/pypi/blockstack/)
[![Slack](https://img.shields.io/badge/join-slack-e32072.svg?style=flat)](http://slack.blockstack.org/)

This package provides the reference implementation of a [Blockstack](https://blockstack.org) node, as well
as tools and scripts for deploying it.

If you are looking to get started with Blockstack applications, we recommend you start with the [Blockstack Browser](https://github.com/blockstack/blockstack-browser) first.

## Table of Contents

- [What is the Blockstack project?](#what-is-blockstack)
- [What is Blockstack Core?](#what-is-blockstack-core)
- [Installing Blockstack Core](#installing-blockstack-core)
- [Running a Blockstack Core Node](#running-a-blockstack-core-node)
- [Using Blockstack Core](#using-blockstack-core)
- [Troubleshooting](#troubleshooting)
- [Developer Resources](#developer-resources)
- [Community](#community)
- [Further Information](#further-reading)
- [Copyright and License](#copyright-and-license)

## What is Blockstack?

Blockstack is a network for decentralized apps where users own their data.

Blockstack applications follow a **can't-be-evil** design
philosophy.  They *cannot* alter, transfer, or revoke the user's identity, and
they *cannot* read or write the user's data without permission.  Blockstack provides the
platform, network, and SDKs for building can't-be-evil
applications using existing Web tools.
If you are Web developer, all of your skills are
immediately transferrable to Blockstack.

Blockstack applications look and feel like traditional Web applications.
Under the hood they use Blockstack APIs for user authentication and storage.
Blockstack handles user authentication using the [Blockstack Naming
Service](docs/blockstack_naming_service.md)
(BNS), a decentralized naming and public key infrastructure built on top of the Bitcoin
blockchain.  It handles storage using [Gaia](https://github.com/blockstack/gaia), a scalable decentralized
key/value storage system that looks and feels like `localStorage`,
but lets users securely store and share application data
via existing storage systems like Dropbox or S3.

Blockstack applications differ from traditional Web applications in two key
ways.  First, **users own their identities**.
The [Blockstack Browser](https://github.com/blockstack/blockstack-browser)
gives users direct control over their private keys and profile data,
and fulfills the role of a SSO provider to Blockstack apps.
Blockstack Core provides BNS as a way for users to discover each other's public
keys.

The second key difference is that **users own their data**.  Users
choose *where* their app data gets hosted, and *who* is allowed to read it.
Gaia loads and stores data with the user's
chosen storage providers, and automatically signs and encrypts it with
their app-specific keys.  Only the intended recipients can authenticate and read
the data; the storage providers are treated as untrusted middlemen.

### Why use Blockstack?

Blockstack is a win/win for users and developers.  Users are not locked into
apps or services.  Instead, users take their identities and data with them from app to app.
Apps can only read user data if the user chooses to allow it.  If an app goes
offline, the user still keeps their data.  If users find a better app, they
can seamlessly switch over to using it.  Because data is end-to-end encrypted
and hosted separately from the app, data breaches are inconsequential to users
because there is nothing for hackers to steal.

Developers benefit from Blockstack as well.  Apps are simpler to build with
Blockstack and require less operational overhead, since they no longer have to
store user data.  Many non-trivial applications can be implemented
as single-page Javascript applications using
[blockstack.js](https://github.com/blockstack/blockstack.js), and deployed as a
static Web page.  The Blockstack API is small, simple, and straightforward to
integrate into existing Web apps.

## What is Blockstack Core?

Blockstack Core implements BNS and [Atlas](docs/atlas_network.md), the storage
routing system for Gaia.  Blockstack Core
nodes form the backbone of the Blockstack network.  Each node indexes the
Bitcoin blockchain and maintains a full replica of all names,
public keys, and storage routing information.  This makes the Blockstack network
particularly resilient to node failure---applications only need to talk to a
single Blockstack Core node to work, and a new or recovering node
can quickly reconstruct all of its missing state from its peers.

Power users are encouraged to run local Blockstack Core nodes on their laptops
or home/office networks in order to have reliable access to the Blockstack
network.  Your local node maintains the same state as the rest of the Blockstack
Core nodes, so it will keep serving names, public keys, and storage routes even
if upstream nodes are unreachable or go offline.

## Installing Blockstack Core

There are three supported methods to install Blockstack Core:
- [`source`](#install-from-source)
- [`pip`](#install-with-pip)
- [`docker`](#install-with-docker)

### Install from Source

Before installing Blockstack Core from source, you will need to install
[`libffi-dev`](https://sourceware.org/libffi/) and
[`libssl-dev`](https://www.openssl.org/source/).  Mac and Linux users can
usually grab these packages from their respective package managers.

Once these dependencies are installed, you can install Blockstack Core
from source via the included `setup.py` script, as follows:

```bash
$ git clone https://github.com/blockstack/blockstack-core
$ cd blockstack-core
$ python2 ./setup.py build
$ sudo python2 ./setup.py install
```

You can also use a [`virtualenv`](https://virtualenv.pypa.io/en/stable/) to
install Blockstack Core in a non-system directory.

### Install with `pip`

**NOTE:** Using `pip` is only supported for stable releases (i.e. `master`).

Blockstack is built against Python 2.7.  You should use `pip2` if you have it instead of `pip`.  If you do not have `pip2`, you should verify that your `pip` is configured for Python 2.

On Mac:

```bash
# Install blockstack
$ pip install blockstack --upgrade
```
On CentOS 7 & RHEL:

```
# Install dependencies
$ yum install epel-release
$ yum install python-pip python-devel openssl-devel libffi-devel rng-tools gmp-devel zlib-devel

# Install blockstack
$ sudo pip install blockstack --upgrade
```

You will need to open ports TCP:6264 and TCP:6270.  If you have trouble starting
`blockstack-core`, you can try disabling SELinux and/or `firewalld` as follows:

```bash
# Disable SELinux
$ setenforce 0
$ sed -i --follow-symlinks 's/^SELINUX=.*/SELINUX=disabled/g' /etc/sysconfig/selinux && cat /etc/sysconfig/selinux

# Stop firewalld
$ systemctl stop firewalld && systemctl disable firewalld
```

On Debian & Ubuntu:

```bash
# Install dependancies
$ sudo apt-get update && sudo apt-get install -y python-pip python-dev libssl-dev libffi-dev rng-tools libgmp3-dev
$ sudo pip install pyparsing

# Install blockstack
$ sudo pip install blockstack --upgrade
```

### Install with `docker`

**NOTE:** Using `docker` is only supported for stable releases (i.e. `master`).

Another way to run `blockstack-core` is through docker. We provide per-commit image builds of this repository that are [available on quay.io](https://quay.io/repository/blockstack/blockstack-core?tab=tags).

```shell
$ git clone git@github.com:blockstack/blockstack-core.git
$ cd blockstack-core
$ docker build -t blockstack-core:master .

# create directory to store Blockstack Core state
$ export BLOCKSTACK_DIR="/var/blockstack-core-data"
$ mkdir -p "$BLOCKSTACK_DIR"
$ docker run \
   -v $BLOCKSTACK_DIR:/root/.blockstack-server
   -p 6264:6264
   -p 6270:6270
   blockstack-core:master
```

These commands will fast-sync and run a Blockstack Core node in about 10
minutes.  The state for the Blockstack Core node will be stored to
`$BLOCKSTACK_DIR`.  You can see the node's logs with `docker logs -f` or with
`tail -f "$BLOCKSTACK_DIR/blockstack-server.log"`.

Notes:
- This method is currently only fully supported on Linux.
- You will need `sudo` access to run the above scripts, and/or be a member of the `docker` group.
- You can run more than one instance of this setup per host. Allow at least 1 CPU core for each container
- To configure a different `bitcoind` node, you must edit your `blockstack-server.ini` file before running the `./docker-tools.sh init-*` commands. After `init-*` has been run you must edit the `data/core/server/blockstack-server.ini` to change those settings. 

## Running a Blockstack Core Node

Before doing anything, you should configure your Blockstack Core node.

```bash
$ blockstack-core configure
```

It is safe to accept all defaults.  It will generate some configuration state in
`~/.blockstack-server/`.

Because each Blockstack Core node maintains a full copy of the network state
locally, it will need to synchronize its state with the Bitcoin blockchain when
it starts for the first time.  **This can take days.**  To overcome this,
we run some "fast-sync" servers that will serve a new Blockstack Core node a
recent snapshot of the network state.  Fast-sync only takes a few minutes.

To start up a Blockstack Core node from a snapshot, you should run

```bash
$ blockstack-core --debug fast_sync
```

By default, it will pull a snapshot from
`http://fast-sync.blockstack.org/snapshot.bsk` and use a built-in public key to
verify its authenticity.  It will populate your `~/.blockstack-server/`
directory with a recent snapshot of the network state (less than 24 hours old).

To start your Blockstack Core node, you should run

```bash
$ blockstack-core --debug start
```

This will start a Blockstack Core node in the background.  We recommend passing
the `--debug` flag so you will receive verbose output, which will help diagnose
any problems you may have.

You can find the node's log in `~/.blockstack-server/blockstack-server.log`.

## Using Blockstack Core

The standard way to interact with Blockstack Core is through its RESTful interface.  The full documentation for the API endpoints is available [here](https://core.blockstack.org).  Below are some common examples.

To check that your API endpoint is up, you can ping it with:

```
$ curl http://localhost:6270/v1/ping
{"status": "alive", "version": "20.0.0.0"}
```

You can confirm that your API endpoint can contact the `blockstack-core` daemon
by looking up a name as follows:

```
$ curl http://localhost:6270/v1/names/muneeb.id
{"status": "registered", "zonefile": "$ORIGIN muneeb.id\n$TTL 3600\n_http._tcp URI 10 1 \"https://gaia.blockstack.org/hub/1J3PUxY5uDShUnHRrMyU6yKtoHEUPhKULs/0/profile.json\"\n", "expire_block": 599266, "blockchain": "bitcoin", "last_txid": "7e16e8688ca0413a398bbaf16ad4b10d3c9439555fc140f58e5ab4e50793c476", "address": "1J3PUxY5uDShUnHRrMyU6yKtoHEUPhKULs", "zonefile_hash": "37aecf837c6ae9bdc9dbd98a268f263dacd00361"}
```

You can stop the Blockstack Core daemon with the following command:

```
$ blockstack-core stop
```

### Getting Verbose Debugging Output

Blockstack Core does not log very much non-error information by default.  To get
verbose output, you can pass `--debug` to both `blockstack-core` and `blockstack
api`, as follows:

```bash
$ blockstack-core --debug start && tail -f ~/.blockstack-server/blockstack-server.log
```

In addition `blockstack-core` can run in the
foreground, without becoming daemons.  To do so, run them as:

```bash
$ blockstack-core --debug start --foreground
```

## Developer Resources

**v20.0.0.0** is the current stable release of Blockstack Core.  It available on the `master` branch.

The next release is being built on the [develop](https://github.com/blockstack/blockstack-core/tree/develop). Please submit all
pull requests to the `develop` branch.

In the list of [release notes](./release_notes) you can find what has changed in each release.

Blockstack Core has an extensive integration test framework, which lets you
experiment with Blockstack in a sandboxed environment.  The test framework gives your Blockstack
Core node a local, private Bitcoin blockchain that lets you safely experiment
with different name and namespace transactions without spending Bitcoin.
We use the integration test
framework to test everything from new API calls to new Blockstack Browser
features.  Please see the relevant
[documentation](./integration_tests) to get started.

We welcome any small or big contributions! Please take a moment to
[review the guidelines for contributing to open source](https://guides.github.com/activities/contributing-to-open-source/) in order to make the contribution process easy and effective for everyone involved.

## Community

Beyond this Github project,
Blockstack maintains a public [forum](https://forum.blockstack.org) and a
permissioned [Slack](https://blockstack.slack.com) channel.  In addition, the project
maintains a [mailing list](https://blockstack.org/signup) which sends out
community announcements.

The greater Blockstack community regularly hosts in-person
[meetups](https://www.meetup.com/topics/blockstack/).  The project's
[YouTube channel](https://www.youtube.com/channel/UC3J2iHnyt2JtOvtGVf_jpHQ) includes
videos from some of these meetups, as well as video tutorials to help new
users get started and help developers wrap their heads around the system's
design.

## Further Reading

You can learn more by visiting [the Blockstack Website](https://blockstack.org) and checking out the in-depth articles and documentation:

- [How Blockstack Works (white paper)](https://blockstack.org/docs/how-blockstack-works)
- [Blockstack General FAQ](https://blockstack.org/faq)
- [Blockstack Technical FAQ](docs/faq_technical.md)
- [Blockstack In-depth Documentation Repository](docs/README.md)

You can also read peer-reviewed Blockstack papers:

- ["Blockstack: A Global Naming and Storage System Secured by Blockchains"](https://blockstack.org/blockstack.pdf), Proc. USENIX Annual Technical Conference ([ATC '16](https://www.usenix.org/conference/atc16)), June 2016
- ["Extending Existing Blockchains with Virtualchain"](https://blockstack.org/virtualchain_dccl2016.pdf), Distributed Cryptocurrencies and Consensus Ledgers ([DCCL '16](https://www.zurich.ibm.com/dccl/) workshop, at [ACM PODC 2016](https://www.podc.org/podc2016/)), July 2016

If you have high-level questions about Blockstack, try [searching our forum](https://forum.blockstack.org) and start a new question if your question is not answered there.

## Copyright and License

The code and documentation copyright are attributed to blockstack.org for the year of 2018.

This code is released under [the GPL v3 license](http://www.gnu.org/licenses/quick-guide-gplv3.en.html), and the docs are released under [the Creative Commons license](http://creativecommons.org/).
