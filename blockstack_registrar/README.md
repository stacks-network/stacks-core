# registrar

[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

For registering and updating [blockchain IDs](https://github.com/blockstack/blockstack/wiki/Blockchain-ID). 

Blockchain IDs are registered on the Bitcoin blockchain, using [Blockstore](https://github.com/blockstack/blockstore), and associated data is stored on external data stores like a DHT. 

A registrar is a service that registers blockchain IDs and then transfers them to the respective users, along with writing/updating any associated data. Just like GoDaddy helps you manage domain names, a blockchain ID registrar helps you register/manage your blockchain ID. However, the end-users have complete control over the blockchain IDs registered (after a transfer is complete), and anyone can decide to run a registrar.

## Blockchain IDs

Usernames may be up to 60 characters long and contain lowercase letters, numbers, and underscores.

**Note:** usernames with ANY uppercase letters will be ignored by crawlers, so make sure to only use lowercase letters when you register a name.

Regex: ^[a-z0-9_]{1,60}$

## Registration

To register a blockchain ID:

1. choose an available username
2. construct a valid JSON object that adheres to the [profile schema specifications](https://github.com/blockstack/blockstack/wiki/Blockchain-ID-Schema-v2)
3. register the username and profile as an entry in the key-value store

## HD Wallet

Registrar comes with support a hierarchical deterministic wallet.

```
from registrar.wallet import HDWallet
from registrar.wallet import display_wallet_info

wallet = HDWallet()

no_of_children = 5

addresses = wallet.get_keypairs(no_of_children, include_privkey=False)
display_wallet_info(addresses)
```

## License

GPL v3. See LICENSE.

Copyright: (c) 2015 by Blockstack.org
