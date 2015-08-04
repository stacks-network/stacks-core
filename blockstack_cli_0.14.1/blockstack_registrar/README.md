registrar
==================

For registering and updating blockchain ID

## Setup Environment 

Blockchain ID currently uses the Namecoind blockchain for storing data. You'll need to compile a Namecoin Daemon (namecoind) to register/update opennames and profiles. You can follow the instructions for [compiling namecoind on Debian](https://github.com/namesystem/registrar/blob/master/doc/build-debian.md). 

We've also developed a Python RPC client, shipped with [pybitcoin](https://github.com/namesystem/pybitcoin/rpc) for easily interacting with namecoind. This RPC client can be used to register users and update their profiles once you've setup your own namecoind instance. See the [README](https://github.com/namesystem/pybitcoin/tree/master/pybitcoin/rpc) files for details.

We're in the process of releasing more tools/software for making this process easier for developers, so stay tuned!

## Blockchain ID

Usernames may be up to 60 characters long and contain lowercase letters, numbers, and underscores.

**Note:** usernames with ANY uppercase letters will be ignored by crawlers, so make sure to only use lowercase letters when you register a name.

Regex: ^[a-z0-9_]{1,60}$

## Registration

To register a blockchain ID:

1. choose an available username
2. construct a valid JSON object that adheres to the [profile schema specifications](https://github.com/blockstack/blockstack/wiki/Passcard-Schema-v2)
3. register the username and profile as an entry in the key-value store
