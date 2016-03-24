[![Build Status](https://travis-ci.org/blockstack/blockstack-resolver.svg?branch=master)](https://travis-ci.org/blockstack/blockstack-resolver)
[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

blockstack-resolver
=======

## Overview:

Blockstack-resolver is a highly scalable server for querying Blockstack DNS
e.g., the .id namespace. It resolves names to data records. Resolver is
primarily meant for scaling read-only calls to the underlying blockchain.
For achieving high throughput the resolver loads the entire namespace into
memcached and then keeps the local copy consistent with the blockchain.
Read-only calls don't hit the blockchain daemon and their scalability is
completely decoupled from the scalability properties of the underlying
blockchain software. It is blockchain-agnostic, but currently uses the
Bitcoin blockchain. An earlier release (version 0.2) used the Namecoin blockchain.

## Contributing 

We welcome all contributions! to this open-source software! Some things to note: 

* The [develop](https://github.com/blockstack/resolver/tree/develop) branch is
the most active one and uses Bitcoin. Please use that branch for submitting
pull requests.
* An [earlier version](https://github.com/blockstack/resolver/releases/tag/v0.2)
of this package had support for Namecoin. We no longer support Namecoin.

## API Calls:

Example API call:

```
http://localhost:5000/v2/username/fredwilson
```

## For quick deployment:

```
pip install -r requirements.txt
./runserver
```

For deploying the resolver in production, see [this page](https://github.com/blockstack/resolver/tree/master/apache).

## Troubleshooting

If you're having issues installing pylibmc on OS X, try:

```
brew install memcached
brew install libmemcached
pip install pylibmc --install-option="--with-libmemcached=/usr/local/Cellar/libmemcached/1.0.18_1/"
```

## License:

MIT. See LICENSE.

Copyright: (c) 2016 by Blockstack.org
