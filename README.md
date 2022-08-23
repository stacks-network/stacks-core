Code: [![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://opensource.org/licenses/) Docs: [![License: CC0-1.0](https://licensebuttons.net/l/zero/1.0/80x15.png)](https://creativecommons.org/publicdomain/zero/1.0/)
# Stacks 2.0

Reference implementation of the [Stacks blockchain](https://github.com/stacks-network/stacks) in Rust.

Stacks 2.0 is a layer-1 blockchain that connects to Bitcoin for security and enables decentralized apps and predictable smart contracts. Stacks 2.0 implements [Proof of Transfer (PoX)](https://community.stacks.org/pox) mining that anchors to Bitcoin security. Leader election happens at the Bitcoin blockchain and Stacks (STX) miners write new blocks on the separate Stacks blockchain. With PoX there is no need to modify Bitcoin to enable smart contracts and apps around it. See [this page](https://github.com/stacks-network/stacks) for more details and resources.

### Platform support

Officially supported platforms: `Linux 64-bit`, `MacOS 64-bit`, `Windows 64-bit`.

Platforms with second-tier status _(builds are provided but not tested)_: `MacOS Apple Silicon (ARM64)`, `Linux ARMv7`, `Linux ARM64`.

For help cross-compiling on memory-constrained devices, please see the community supported documentation here: [Cross Compiling](https://github.com/dantrevino/cross-compiling-stacks-blockchain/blob/master/README.md).


## Getting started

[Here](http://docs.stacks.co/docs/blockchain/) is a full guide on how to get started by downloading the Stacks blockchain and building it locally.

We also have guides to setup your own [Stacks node or miners](https://docs.stacks.co/docs/nodes-and-miners/).

## Contributing

For more information on how to contribute to this repository please refer to [CONTRIBUTORS](CONTRIBUTORS.md).

For more information on Stacks Improvement Proposals (SIPs) please refer to [SIPs documentation](https://docs.stacks.co/docs/governance/sips).

[Here](https://docs.stacks.co/docs/contribute/) you can find other ways to contribute to the Stacks ecosystem. 

## Community and Further reading

For more information please refer to the [Stacks official documentation](https://docs.stacks.co/).

Technical papers:

- ["PoX: Proof of Transfer Mining with Bitcoin"](https://community.stacks.org/pox), May 2020
- ["Stacks 2.0: Apps and Smart Contracts for Bitcoin"](https://stacks.org/stacks), Dec 2020

You can get in contact with the Stacks Community on:


* [![Forum](https://img.shields.io/discourse/users?label=Discourse%20forum&server=https%3A%2F%2Fforum.stacks.org)](https://forum.stacks.org)
* [![Discord Badge](https://img.shields.io/discord/621759717756370964?label=Discord%20chat)](https://discord.com/invite/XYdRyhf)
* [![Youtube badge](https://img.shields.io/youtube/channel/subscribers/UC3J2iHnyt2JtOvtGVf_jpHQ?label=Stacks&style=social)](https://www.youtube.com/channel/UC3J2iHnyt2JtOvtGVf_jpHQ)
* [![Youtube badge](https://img.shields.io/youtube/channel/subscribers/UCp7D42MyHXk4-J2TtF5I0Kg?label=Stacks%20Community&style=social)](https://www.youtube.com/channel/UCp7D42MyHXk4-J2TtF5I0Kg)
* [![Twitter](https://img.shields.io/twitter/follow/Stacks?style=social)](https://twitter.com/Stacks)
* [Stacks Newsletter](https://newsletter.stacks.org/)
* [Blockchain Announce Mailing List](https://groups.google.com/a/stacks.org/g/announce)
* [Meetups](https://www.meetup.com/topics/blockstack/)
