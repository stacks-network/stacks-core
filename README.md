# Blockstack Core

[![PyPI](https://img.shields.io/pypi/v/blockstack.svg)](https://pypi.python.org/pypi/blockstack/)
[![PyPI](https://img.shields.io/pypi/dm/blockstack.svg)](https://pypi.python.org/pypi/blockstack/)
[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

Blockstack is a new decentralized web, where users own their data and apps run on user devices without the need for hosting.

Blockstack Core handles the main functionality of the system. It is responsible for processing blockchain transactions, creating virtualchain state, and building the peer network amongst other things. Blockstack Core provides RPC and RESTful interfaces for Blockstack clients.

The latest stable release of Blockstack Core is 0.14.0.

Learn more by visiting [the Blockstack Website](https://blockstack.org) and checking out the in-depth articles and documentation:

- [How Blockstack Works](https://blockstack.org/docs/how-blockstack-works)
- [Blockstack vs. DNS](https://blockstack.org/docs/blockstack-vs-dns)
- [Blockstack vs. Namecoin](https://blockstack.org/docs/blockstack-vs-namecoin)
- [Blockstack Namespaces](https://blockstack.org/docs/namespaces)
- [Blockstack Light Clients](https://blockstack.org/docs/light-clients)

You can also read the Blockstack paper:

- ["Blockstack: A Global Naming and Storage System Secured by Blockchains"](https://blockstack.org/blockstack.pdf), Proc. USENIX Annual Technical Conference (ATC ’16), June 2016

**Developers**:  You can try out Blockstack Core in a local sandbox using our [integration test framework](https://github.com/blockstack/blockstack-integration-tests/tree/rc-0.14.0).

### Installation

The fastest way to get started with blockstack is with pip:

```
sudo pip install blockstack
```

If you encounter any problems during the pip install, see the [detailed installation
instructions](https://blockstack.org/docs/installation).

### Getting Started

First, start the Blockstack server and index the blockchain:

```bash
$ blockstack-server start
```

Next, visit the [basic usage docs](https://blockstack.org/docs/basic-usage) and [extended usage docs](https://blockstack.org/docs/basic-usage) to learn how to register names of your own, as well as transfer them and associate data with them.

### Contributing

We welcome any small or big contributions! Please take a moment to
[review the guidelines for contributing to open source](https://guides.github.com/activities/contributing-to-open-source/) in order to make the contribution process easy and effective for everyone involved.

#### Main Authors

- **[Jude Nelson](http://onename.com/judecn)** ([@jcnelson](https://github.com/jcnelson))
- **[Muneeb Ali](http://onename.com/muneeb)** ([@muneeb-ali](https://github.com/muneeb-ali))
- **[Ryan Shea](http://onename.com/ryan)** ([@ryaneshea](https://github.com/shea256))

#### All Code Contributors

- [Contributor Graph](../../graphs/contributors)
- [Code Overview](https://github.com/blockstack/blockstack/blob/master/overview.md)

### Community

We have an active community of developers and the best place to interact with the community is:

- [Live chat on Slack](http://chat.blockstack.org/) (1,200+ members)
- [Blockstack Reddit](http://reddit.com/r/blockstack)

### Copyright and License

The code and documentation copyright are attributed to blockstack.org for the year of 2016.

This code is released under
[the GPL v3 license](http://www.gnu.org/licenses/quick-guide-gplv3.en.html), and the docs are released under [the Creative Commons license](http://creativecommons.org/).
