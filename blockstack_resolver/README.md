BNS-resolver
=======

## Overview:

BNS-resolver is a highly scalable server for [Blockchain Name System](https://github.com/namesystem). It resolves usernames to profile data (passcards). It is blockchain-agnostic (currently uses the Namecoin blockchain) and is primarily meant for scaling read-only calls to the underlying blockchain. For achieving high throughput BNS-resolver loads the entire namespace into memcached and then keeps the in-memory copy consistent with the blockchain. Read-only calls never hit disk and their scalability is completely decoupled from the scalability properties of the underlying database.


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

Warmup cache and then keep memcached in sync with the blockchain:

```
source tools/setup_env.sh
python -m tools.warmup_cache
mkdir log
python -m tools.sync_cache
```
