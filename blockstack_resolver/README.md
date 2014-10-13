ONS Server
=======

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

Example API call: 
```
http://localhost:5000/ons/value?key=u/naval
http://localhost:5000/ons/profile?openname=naval
```