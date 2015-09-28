
https://github.com/blockstack/blockstore


# Blockstore

[![PyPI](https://img.shields.io/pypi/v/blockstore.svg)](https://pypi.python.org/pypi/blockstore/)
[![PyPI](https://img.shields.io/pypi/dm/blockstore.svg)](https://pypi.python.org/pypi/blockstore/)
[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)



## Name registrations on the bitcoin blockchain

Blockstore enables human-readable name registrations on the Bitcoin blockchain, along with the ability to store associated data in external datastores. You can use it to register globally unique names, associate data with those names, and transfer them between Bitcoin addresses. Anyone can perform lookups on those names and securely obtain the data associated with them.

Blockstore uses the Bitcoin blockchain for storing name operations and data hashes, and the Kademlia-based distributed hash table (DHT) and other external datastores for storing the full data files outside of the blockchain.


> NOTE: This repo is going through rapid development for a planned release on Sep 24, 2015. If you notice any issues during installation etc please report them in Github issues. We hope to have a stable, easy to install, version out very soon!



## Table of contents

* [Overview](#overview)
* [Quick start](#get-start)
* [Requirements](#requirements)
* [Install blockstore using pip *recommended](#install-pip)
* [Getting started](#get-start)
* [What’s included](#whats-included)
* [Bugs and feature requests](#bugs-and-feature-requests)
* [Documentation](#documentation)
* [Design decisions](#design-decisions)
* [Protocol details](#protocol-details)
* [Definitions](#definitions)
* [FAQ](#faq)
* [Contributing](#contributing)
* [Community](#community)
* [Creators](#creators)
* [Copyright and license](#copyright-and-license)



## Overview

This document is meant to provide an overview of how to get blockstore up and running on Mac OS X, Linux, and similar UNIX-like operating systems. It is meant to be a high-level walk-through for application developers who want to run their own Blockstore instance. Basic proficiency with the command-line is required.



## Quick start

Several quick start options are available:

* [Requirements](#requirements)
* Install with [pip](https://pypi.python.org/pypi/pip): `pip install blockstore`.
* Install with [docker](https://www.npmjs.com): `npm install bootstrap`.



## Requirements

In order to install and run Blockstore, you will need the following:

- [x] Acccess to a bitcoin node with a full transaction index (i.e. txindex is enabled)
- You need to be able to connect to a specific bitcoin node that stores each transaction. Note: This is ​*not*​ the default behavior, the `txindex` option has to be explicitly enabled in the node.  For example, `btcd.onename.com` have this feature enabled.
- [x] [Python 2.6 or higher](https://www.python.org/). (Python 3.x not supported)
- [x] [The Python distutils package](https://docs.python.org/2/distutils/) (Verify as it is not always installed with Python)
- [x] [Python pip](https://pypi.python.org/pypi/pip)



## Install blockstore using pip
*recommended


The fastest way to get started with blockstore is to use pip:

```
pip install blockstore
```


## Getting started

Start blockstored and index the blockchain:

```
$ blockstored start
```

Then, perform name lookups:

```
$ blockstore-cli lookup swiftonsecurity
{
    "data": "{\"name\":{\"formatted\": \"Taylor Swift\"}}"
}
```

Next, learn how to register names of your own, as well as transfer them and associate data with them:

[Full usage docs](../../wiki/Usage)



## What's included

Within the install you'll find the following directories and files. You'll see something like this:

```
blockstore/
├── bin/
│   ├── blockstored
│   └── README.md
├── blockstore/
│   ├── __init__.py
│   ├── blockmirrord.py
│   ├── blockmirrord.tac
│   ├── blockstore.tac
│   ├── blockstored.py
│   ├── build_nameset.py
│   ├── coinkit.patch
│   ├── dht/
│   │   ├── __init__.py
│   │   ├── image/
│   │   │   ├── Dockerfile
│   │   │   └── README.md
│   │   ├── plugin.py
│   │   ├── README.md
│   │   ├── server.tac
│   │   ├── storage.py
│   │   └── test.py
│   ├── lib/
│   │   ├── __init__.py
│   │   ├── b40.py
│   │   ├── config.py
│   │   ├── hashing.py
│   │   ├── nameset/
│   │   │   ├── __init__.py
│   │   │   ├── namedb.py
│   │   │   └── virtualchain_hooks.py
│   │   ├── operations/
│   │   │   ├── __init__.py
│   │   │   ├── nameimport.py
│   │   │   ├── namespacepreorder.py
│   │   │   ├── namespaceready.py
│   │   │   ├── namespacereveal.py
│   │   │   ├── preorder.py
│   │   │   ├── register.py
│   │   │   ├── revoke.py
│   │   │   ├── transfer.py
│   │   │   └── update.py
│   │   ├── README.md
│   │   └── scripts.py
│   ├── tests/
│   │   └── unit_tests.py
│   └── TODO.txt
├── Dockerfile
├── images/
│   └── Dockerfile
├── LICENSE
├── MANIFEST.in
├── README.md
├── requirements.txt
└── setup.py
```



## Bugs and feature requests

Have a bug or a feature request? Please first read the issue guidelines and search for existing and closed issues. If your problem or idea is not addressed yet, please open a new issue.

Bugs are demonstrable problems that are caused by the code in the repository. Good bug reports are extremely helpful, so thanks!

Guidelines for bug reports:

1. Validate and lint your code — validate your HTML and lint your HTML to ensure your problem isn't caused by a simple error in your own code.

2. Use the GitHub issue search — check if the issue has already been reported.

3. Check if the issue has been fixed — try to reproduce it using the latest master or development branch in the repository.

4. Isolate the problem — ideally create a reduced test case and a live example.

A good bug report shouldn't leave others needing to chase you up for more information. Please try to be as detailed as possible in your report. What is your environment? What steps will reproduce the issue? What browser(s) and OS experience the problem? What would you expect to be the outcome? All these details will help people to fix any potential bugs.



## Documentation

Blockstore’s detailed documentation is located included in this repo’s [Wiki](https://github.com/blockstack/blockstore/wiki).



## Design decisions

[Design decisions](../../wiki/Design-Decisions)




## Protocol details

[Protocol details](../../wiki/Protocol-Details)




## Definitions

[Definitions](../../wiki/Definitions)



## FAQ

[FAQ](../../wiki/FAQ)



## Contributing
Looking to contribute something to Blockstore? Here's how you can help.

Please take a moment to review the following guidelines in order to make the contribution process easy and effective for everyone involved.

Following these guidelines helps to communicate that you respect the time of the developers managing and developing this open source project. In return, they should reciprocate that respect in addressing your issue or assessing patches and features.

The best way to contribute is to:

1. Decide what changes you'd like to make (you can find inspiration in the tab of issues)
2. Fork the repo
3. Make your changes
4. Submit a pull request

Feel free to view our list of [code contributors](../../graphs/contributors) or view the [full contributor list](../../wiki/Contributors).



## Community

The Blockstack community is a group of blockchain companies and nonprofits coming together to define and develop a set of software protocols and tools to serve as a common backend for blockchain-powered decentralized applications. We are opening membership to the public, welcoming all developers and companies that are interested in joining the consortium and contributing to Blockstack development.

For more information please visit the community website [Blockstack.org](http://blockstack.org)

Our community is highly active and welcoming on both, our [public Slack](http://chat.blockstack.org/) and [public Forum](http://forum.blockstack.org/).



## Creators

**[Jude Nelson](http://onename.com/judecn)**

* <https://twitter.com/judecnelson>
* <https://github.com/jcnelson>

**[Muneeb Ali](http://onename.com/muneeb)**

* <https://twitter.com/muneeb>
* <https://github.com/muneeb-ali>

**[Ryan Shea](http://onename.com/ryan)**

* <https://twitter.com/ryaneshea>
* <https://github.com/shea256>




## Copyright and license

Code and documentation copyright 2015 by Blockstack.org. Code released under [the GPL v3 license](http://www.gnu.org/licenses/quick-guide-gplv3.en.html). Docs released under [Creative Commons](http://creativecommons.org/).


