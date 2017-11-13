# registrar

For registering and updating [Blockstack IDs](https://explorer.blockstack.org). 

Blockstack IDs are registered on the Bitcoin blockchain, using [Blockstack](https://blockstack.org), and associated data is stored in Blockstack's Atlas peer network.

A registrar is a service that registers Blockstack IDs and then transfers them to the respective users, along with writing/updating any associated data. Just like GoDaddy helps you manage domain names, a Blockstack ID registrar helps you register/manage your Blockstack ID. However, the end-users have complete control over the Blockstack IDs registered (after a transfer is complete), and anyone can decide to run a registrar.

## Blockstack IDs

Usernames may be up to 40 characters long and contain lowercase letters, numbers, and underscores.

**Note:** usernames with ANY uppercase letters will be ignored by crawlers, so make sure to only use lowercase letters when you register a name.

Regex: ^[a-z0-9_]{1,60}$

## Registration

To register a Blockstack ID:

1. choose an available username
2. construct a valid JSON object that adheres to the [profile schema specifications](https://github.com/blockstack/blockstack/wiki/Blockchain-ID-Schema-v2)
3. register the username and profile

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
