ONS Server
=======

## Overview: 

ONS-server is meant to be a highly scalable server for [Openname System](https://openname.org). It is meant to be blockchain-agnostic (currently uses the Namecoin blockchain) and is primarily meant for scaling read-only calls to the underlying blockchain. For achieving high throughput ons-server loads the entire namespace into memcached and then keeps the in-memory copy consistent with the blockchain. Read-only calls never hit disk and their scalability is completely decoupled from the scalability properties of the underlying database. 

## Setup Instructions:

ONS-server requires memcached:

```
sudo apt-get install memcached libmemcached-dev zlib1g-dev
sudo apt-get install python2.7-dev
```

Before installing pylibmc (listed in requirements.txt) install the above packages.

Install coinrpc:
```
pip install git+ssh://git@github.com/onenameio/coinrpc.git
```

For quick deployment:

```
pip install -r requirements.txt
./runserver 
```

Warmup cache and then keep memcached in sync with the blockchain:
```
source tools/setup_env.sh
python -m tools.warmup_cache
mkdir log
python -m tools.sync_cache
```

## API Calls: 


Example API call: 
```
http://localhost:5000/ons/value?key=u/naval
http://localhost:5000/ons/profile?openname=naval
```
