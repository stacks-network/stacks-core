[![Build Status](https://travis-ci.org/blockstack/blockstack-resolver.svg?branch=master)](https://travis-ci.org/blockstack/blockstack-resolver)
[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

blockstack-resolver
=======

## Overview:

Blockstack-resolver is a highly scalable server for querying
[Blockstack](https://blockstack.org/docs/what-is-blockstack), the global Internet
database. It resolves names to data records. Resolver is
primarily meant for scaling read-only calls to Blockstack and introduces a caching
layer. For achieving high throughput the resolver loads the entire namespace into
memcached and then keeps the local copy consistent with the blockchain.
Read-only calls don't hit the blockchain daemon and their scalability is
completely decoupled from the scalability properties of the underlying
blockchain software. It is blockchain-agnostic, but currently uses the
Bitcoin blockchain.

## Contributing 

We welcome all contributions! to this open-source software! Some things to note: 

* The [develop](https://github.com/blockstack/resolver/tree/develop) branch is
the most active one and uses Bitcoin. Please use that branch for submitting
pull requests.
* We no longer support Namecoin.

## API Calls:

Example API call:

```
http://localhost:5000/v2/users/fredwilson
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

## Cron Job for Namespaces

Currently, the resolver indexes all valid names in a local file which can be
populated by running
> $ ./refresh_names.sh

On a production deployment, you should add a crond job to periodically run this
script. You can edit your crontab file by:
> $ crontab -e

Here is a sample crontab file that runs the refresh script every two hours: 
```
SHELL=/bin/bash
HOME=/home/ubuntu

#This is a comment
0 */2 * * * /home/ubuntu/resolver/resolver/refresh_names.sh
```

## License:

MIT. See LICENSE.

Copyright: (c) 2016 by Blockstack.org
