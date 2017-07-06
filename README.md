# Blockstack Core

[![PyPI](https://img.shields.io/pypi/v/blockstack.svg)](https://pypi.python.org/pypi/blockstack/)
[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

Blockstack is a new decentralized internet where you own your data and your apps run locally without remote servers. 

Blockstack provides decentralized services for naming/DNS, identity, authentication and storage. Developers can use JavaScript libraries to build serverless apps and they don't need to worry about managing infrastructure.

For more info on Blockstack see: http://github.com/blockstack/blockstack

**Blockstack Core is the reference implementation of Blockstack.** It is responsible for processing blockchain transactions, creating virtualchain state, and building the peer network amongst other things. Blockstack Core provides a RESTful interface for clients and also comes with a command-line-interface (CLI).

## Table of Contents

- [Quick Start](#quick-start)
- [Development Status](#development-status)
- [Blockstack Docs](#blockstack-docs)
- [API Docs](#api-docs)
- [Contributing](#contributing)
- [Community](#community)

## Quick Start

The fastest way to get started with Blockstack is with `pip`.

You should use `pip2` if you have it instead of `pip`, since Blockstack requires Python 2.

For Debian & Ubuntu:
```
$ sudo apt-get update && sudo apt-get install -y python-pip python-dev libssl-dev libffi-dev rng-tools libgmp3-dev
$ sudo pip2 install pyparsing
$ sudo pip2 install blockstack --upgrade
```
For SUSE and openSUSE
```
$ sudo zypper update && zypper install rng-tools python-devel libffi-devel
$ sudo pip install blockstack --upgrade 
```
For macOS: 
```
$ brew install gmp libffi openssl
$ sudo pip install --upgrade pip
$ sudo pip install blockstack --upgrade
```

You can test your installation by trying:
```
$ blockstack info 
```
which should display the last block processed and the latest consensus hash.

After installation, you can (optionally) do a fast-sync that quickly syncs your node with the network:
```bash
$ blockstack-core --debug fast_sync http://fast-sync.blockstack.org/snapshot.bsk
```

And start Blockstack Core to index the blockchain:
```bash
$ blockstack-core --debug start
$ tail -f ~/.blockstack-server/blockstack-server.log
```

Next, visit the [basic usage docs](https://blockstack.org/docs) and [extended usage docs](https://blockstack.org/docs) to learn how to register names of your own, as well as transfer them and associate data with them.

If you encounter any technical issues in installing or using Blockstack, please [search the open issues](https://github.com/blockstack/blockstack-core/issues) and start a new one if your issue is not covered. 

## Development Status

**v0.14.2** is the current stable release of Blockstack Core (available on the master branch).<br>
**v0.14.3** is the next release candidate for Blockstack Core (available on the [v0.14.3 branch](https://github.com/blockstack/blockstack-core/tree/rc-0.14.3)).

Most of the development is happening in the [v0.14.3 branch](https://github.com/blockstack/blockstack-core/tree/rc-0.14.3). Please submit all
pull requests to that branch.

In the list of [release notes](https://github.com/blockstack/blockstack-core/tree/master/release_notes) you can find what has changed in these versions.

## Blockstack Docs

You can learn more by visiting [the Blockstack Website](https://blockstack.org) and checking out the in-depth articles and documentation:

- [How Blockstack Works](https://blockstack.org/docs/how-blockstack-works)
- [Blockstack vs. DNS](https://blockstack.org/docs/blockstack-vs-dns)
- [Blockstack vs. Namecoin](https://blockstack.org/docs/blockstack-vs-namecoin)
- [Blockstack Namespaces](https://blockstack.org/docs/namespaces)
- [Blockstack Light Clients](https://blockstack.org/docs/light-clients)

You can also read the Blockstack paper:

- ["Blockstack: A Global Naming and Storage System Secured by Blockchains"](https://blockstack.org/blockstack.pdf), Proc. USENIX Annual Technical Conference (ATC ’16), June 2016

If you have high-level questions about Blockstack, try [searching our forum](https://forum.blockstack.org) and start a new question if your question is not answered there.

## API Docs

A local core node will expose a RESTful API after starting the api with `blockstack api start`.
Documentation for that lives [here](https://kantai.github.io/blockstack-core/), which is generated from blueprint markdown [here](docs/api-specs.md).

## Contributing

We welcome any small or big contributions! Please take a moment to
[review the guidelines for contributing to open source](https://guides.github.com/activities/contributing-to-open-source/) in order to make the contribution process easy and effective for everyone involved.

**Developers**:  You can try out Blockstack Core in a local sandbox using our [integration test framework](https://github.com/blockstack/blockstack-integration-tests).

You can install the latest release candidate by:
```bash
$ git clone https://github.com/blockstack/blockstack-core.git
$ blockstack-core/images/scripts/debian-release-candidate.sh
```

## Community

We have an active community of developers and the best place to interact with the community is:

- [Mailing List](http://blockstack.us14.list-manage1.com/subscribe?u=394a2b5cfee9c4b0f7525b009&id=0e5478ae86) (3,000+ members)
- [Blockstack Forum](http://forum.blockstack.org)
- [Live chat on Slack](http://chat.blockstack.org/) (2,400+ members)

## Copyright and License

The code and documentation copyright are attributed to blockstack.org for the year of 2017.

This code is released under
[the GPL v3 license](http://www.gnu.org/licenses/quick-guide-gplv3.en.html), and the docs are released under [the Creative Commons license](http://creativecommons.org/).
