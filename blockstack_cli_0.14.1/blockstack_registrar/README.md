openname-registrar
==================

For registering and updating opennames and profiles

## Setup Environment 

Openname currently uses the Namecoind blockchain for storing data. You'll need to compile a Namecoin Daemon (namecoind) to register/update opennames and profiles. You can follow the instructions for [compiling namecoind on Debian](https://github.com/opennamesystem/openname-registrar/blob/master/doc/build-debian.md). 

We've open-sourced a Python RPC client, called [coinrpc](https://github.com/opennamesystem/coinrpc) for easily interacting with namecoind. Coinrpc can be used to register users and update their profiles once you've setup your own namecoind instance. See the README files of coinrpc for details.

We're in the process of releasing more tools/software for making this process easier for developers, so stay tuned!

## Openname Usernames

Usernames may be up to 60 characters long and contain lowercase letters, numbers, and underscores.

**Note:** usernames with ANY uppercase letters will be ignored by crawlers, so make sure to only use lowercase letters when you register a name.

Regex: ^[a-z0-9_]{1,60}$

## User Registration

To register a user:

1. choose an available username
2. construct a valid JSON object that adheres to the [user schema specifications](https://github.com/opennamesystem/openname-specifications#schema)
3. register the username and profile as an entry in the key-value store
