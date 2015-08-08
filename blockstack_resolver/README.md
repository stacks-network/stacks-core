[![Build Status](https://travis-ci.org/blockstack/resolver.svg?branch=master)](https://travis-ci.org/namesystem/resolver)

resolver
=======

## Overview:

Resolver is a highly scalable server for [blockchain ID](https://github.com/blockstack/blockstack/wiki/Blockchain-ID). It resolves usernames to profile data. It is blockchain-agnostic. Version 0.2 uses the Namecoin blockchain and v0.3 (currently under development) uses the Bitcoin blockchain. Resolver is primarily meant for scaling read-only calls to the underlying blockchain. For achieving high throughput the resolver loads the entire namespace into a local database and memcached and then keeps the local copy consistent with the blockchain. Read-only calls don't hit the blockchain daemon and their scalability is completely decoupled from the scalability properties of the underlying blockchain software.

## Contributing 

We welcome all contributions to this open-source software! Some things to note: 

* The [v0.3](https://github.com/blockstack/resolver/tree/v0.3) branch is the most active one and uses Bitcoin. Please use that branch for submitting pull requests.
* The last stable release with support for Namecoin is [v0.2](https://github.com/blockstack/resolver/releases/tag/v0.2). Use the [namecoin](https://github.com/blockstack/resolver/tree/namecoin) branch for further development on it. 

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

Copyright: (c) 2015 by Blockstack.org
