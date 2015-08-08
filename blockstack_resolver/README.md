[![Build Status](https://travis-ci.org/blockstack/resolver.svg?branch=master)](https://travis-ci.org/namesystem/resolver)

resolver
=======

## Overview:

Resolver is a highly scalable server for [blockchain ID](https://github.com/blockstack/blockstack/wiki/Blockchain-ID). It resolves usernames to profile data. A good analogy is [DNS resolvers](https://en.wikipedia.org/wiki/Domain_Name_System#DNS_resolvers). Unlike DNS resolvers, the resolution is not hierarchical. There are no "root servers" and a blockchain is used for consensus on the global view. Further, the resolver is meant to support many different types of resolutions e.g., (domain, IP address), (username, profile data), (digital object, data) etc.

The software is largely blockchain-agnostic and assumes that the most secure and reliable underlying blockchain will be used. Version 0.3 uses the Bitcoin blockchain which is the most secure blockchain as of 2015. The software focuses on scaling read-only calls to the underlying blockchain and pre-processing a lot of information. For achieving high throughput the resolver loads the entire namespace into a local cache (database and memcached) and then keeps the local copy consistent with the blockchain. Read-only calls don't hit the blockchain daemon and their scalability is completely decoupled from the scalability properties of the underlying blockchain software.


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