# Blockstack Core

[![PyPI](https://img.shields.io/pypi/v/blockstack.svg)](https://pypi.python.org/pypi/blockstack/)
[![Slack](https://img.shields.io/badge/join-slack-e32072.svg?style=flat)](http://slack.blockstack.org/)

**`blockstack-core` is the reference implementation of the Blockstack protocol.**
- `blockstack-core`
  * Creating and transmitting blockchain transactions,
  * Creating and parsing [virtualchain](https://github.com/blockstack/virtualchain) state, and
  * Communicating with the peer network, Atlas. The
- `blockstack-core api`
  * Provides a RESTful interface for clients to interact with `blockstack-core` functionality
  * Contains your bitcoin wallet
  * [API Docs](docs/api-specs.md) [(rendered)](https://blockstack.github.io/blockstack-core/)
- `blockstack`
  * A command-line-interface for the `blockstack-core api`, and `blockstack-core`

## What is Blockstack?

Blockstack is a new decentralized internet where you own your data and your apps run locally without remote servers.

Blockstack provides decentralized services for naming/DNS, identity, authentication and storage. Developers can use JavaScript libraries to build serverless apps and they don't need to worry about managing infrastructure.

If you are looking to get started with the blockstack platform and register a name, we recommend you start with the [Blockstack Browser](https://github.com/blockstack/blockstack-browser) first.

For more info on Blockstack here are some good links:
- [Join our Slack Channel!](http://forum.blockstack.org/)
- [Join our Forum!](http://forum.blockstack.org/)
- [Read the Whitepaper](blockstack.org/whitepaper.pdf)
- [Documentation](https://blockstack.org/docs)
- [Mailing List](http://blockstack.us14.list-manage1.com/subscribe?u=394a2b5cfee9c4b0f7525b009&id=0e5478ae86)
- [`blockstack/blockstack`](http://github.com/blockstack/blockstack)

## Table of Contents

- [Installing Blockstack](#installing-blockstack)
- [Development Status](#development-status)
- [Blockstack Docs](#blockstack-docs)
- [Contributing](#contributing)

## Installing Blockstack

If you are looking to register a name, or use blockstack application, we recommend that you start with the [blockstack-browser](https://github.com/blockstack/blockstack-browser)
You can find install instructions for:
- [Linux](https://github.com/blockstack/packaging/tree/master/browser-core-docker#installing-blockstack-browser-and-api-with-docker) using our Docker `launcher` script.
- [Windows](http://packages.blockstack.com/repositories/windows/) - Alpha installer which installs docker utilities and our docker images.
- [macOS](https://github.com/blockstack/blockstack-browser/releases)

If you are looking to install `blockstack-core`, there are two methods:
- [`pip install`](#install-with-pip)
- [`docker`](#install-with-docker)

### Install with `pip`

You should use `pip2` if you have it instead of `pip`. Blockstack is built against Python `2.7`.

On Mac:

```bash
# Install blockstack
$ pip2 install blockstack --upgrade
```

On Debian & Ubuntu:

```bash
# Install dependancies
$ sudo apt-get update && sudo apt-get install -y python-pip python-dev libssl-dev libffi-dev rng-tools libgmp3-dev
$ sudo pip2 install pyparsing

# Install blockstack
$ sudo pip2 install blockstack --upgrade
```

#### Setting up `blockstack-api`

If this is your first time installing blockstack first you will need to run `blockstack setup` and follow the prompts. Using the defaults is recommended. This process generates your wallet and the `blockstack` configuration files.

> NOTE: This process generates a wallet. *BE SURE TO SAVE THE WALLET PASSWORD YOU TYPE IN*.

Next you need to start the [`blockstack api`](https://blockstack.github.io/blockstack-core/) server: `blockstack api start`. Now, you can test your installation by running `blockstack info` which should display the last block processed and the latest consensus hash.


### Install with `docker`

> _*WARNING*_: This install path is currently in developer alpha state. We will be adding more features here in the coming months.

Blockstack API and the Blockstack Browser run well in docker. There is a provided CLI to help you build and launch the `docker` images if you are not comfortable with `docker`: `launcher`.
The CLI will pull down the images from our [Quay image repository](https://quay.io/organization/blockstack).

You can download the launcher script from our packaging repo: [download](https://raw.githubusercontent.com/blockstack/packaging/master/browser-core-docker/launcher)

```bash
# First run the pull command. This will fetch the latest docker images from our image repository.
$ ./launcher pull

# The first time you run ./launcher start, it will create a `$HOME/.blockstack` directory to
# store your Blockstack Core API config and wallet and prompt you for a password to protect those
# Next you can start the Blockstack Core API
$ ./launcher start

# When you are done you can clean up your environment by running
$ ./launcher stop
```

This will start the Blockstack browser and a paired `blockstack-api` daemon.

If you would like to build your own docker image, you can use the Dockerfile in the root of this repository.

### Running a `blockstack-core` instance

After installation, you can (optionally) do a fast-sync that quickly syncs a local `blockstack-core` node with the Atlas network:

```bash
# Download the Atlas snapshot
$ blockstack-core --debug fast_sync http://fast-sync.blockstack.org/snapshot.bsk

# start the blockstack-core daemon to index the blockchain
$ blockstack-core --debug start

# Check the server logs for errors
$ tail -f ~/.blockstack-server/blockstack-server.log
```

Next, visit the [usage docs](https://blockstack.org/docs) to learn how to register names of your own, as well as transfer them and associate data with them.

If you encounter any technical issues in installing or using Blockstack, please [search the open issues](https://github.com/blockstack/blockstack-core/issues) and start a new one if your issue is not covered. You can also visit the `forum` or `#support` channel in Slack.

## Development Status

**v0.14.5** is the current stable release of Blockstack Core (available on the master branch).<br>
**v0.14.6** will be the next release for `blockstack-core`.

The next release is being built on the [develop](https://github.com/blockstack/blockstack-core/tree/develop). Please submit all
pull requests to the `develop` branch.

In the list of [release notes](https://github.com/blockstack/blockstack-core/tree/master/release_notes) you can find what has changed in each release.

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

## Contributing

We welcome any small or big contributions! Please take a moment to
[review the guidelines for contributing to open source](https://guides.github.com/activities/contributing-to-open-source/) in order to make the contribution process easy and effective for everyone involved.

**Developers**:  You can try out Blockstack Core in a local sandbox using our [integration test framework](https://github.com/blockstack/blockstack-integration-tests).

You can install the latest release candidate by:
```bash
$ git clone https://github.com/blockstack/blockstack-core.git
$ blockstack-core/images/scripts/debian-release-candidate.sh
```

## Copyright and License

The code and documentation copyright are attributed to blockstack.org for the year of 2017.

This code is released under
[the GPL v3 license](http://www.gnu.org/licenses/quick-guide-gplv3.en.html), and the docs are released under [the Creative Commons license](http://creativecommons.org/).
