ONS Server
=======

## Setup Instructions:

Requires memcached:

```
sudo apt-get install memcached libmemcached-dev
sudo apt-get install python2.7-dev
```

Before installing pylibmc (listed in requirements.txt)

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
python -m tools.warmup_cache
python -m tools.sync_cache
```

## API Calls: 


Example API call: 
```
http://localhost:5000/ons/value?key=u/naval
http://localhost:5000/ons/profile?openname=naval
```
