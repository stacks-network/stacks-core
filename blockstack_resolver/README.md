[![Build Status](https://travis-ci.org/blockstack/resolver.svg?branch=master)](https://travis-ci.org/namesystem/resolver)

resolver
=======

## Overview:

Resolver is a highly scalable server for [blockchain ID](https://github.com/blockstack). It resolves usernames to profile data. It is blockchain-agnostic (currently uses the Namecoin blockchain) and is primarily meant for scaling read-only calls to the underlying blockchain. For achieving high throughput the resolver loads the entire namespace into a local database and memcached and then keeps the local copy consistent with the blockchain. Read-only calls don't hit the blockchain daemon and their scalability is completely decoupled from the scalability properties of the underlying blockchain software.


## API Calls:

Example API call:

```
http://localhost:5000/v1/username/fredwilson
```

## For quick deployment:

```
pip install -r requirements.txt
./runserver
```

## License:

GPL v3. See LICENSE.