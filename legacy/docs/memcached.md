---
layout: core
permalink: /:collection/:path.html
---
# Installing Memcached

The Blockstack API optionally uses memcached and pylibmc for scaling read-only
calls. If you want to enable this functionality then you should have memcached
running locally.

### Memcached on Debian & Ubuntu:

```
$ sudo apt-get install -y python-dev libmemcached-dev zlib1g-dev
$ pip install pylibmc
```

### Memcached on macOS:

Easiest way to install memcached on macOS is by using [Homebrew](https://brew.sh/).

After installing Homebrew:

```
$ brew install memcached
$ brew install libmemcached
$ pip install pylibmc --install-option="--with-libmemcached=/usr/local/Cellar/libmemcached/1.0.18_1/"
```

After installing, you can start memcached and check if it's running properly:

```
$ memcached -d
$ echo stats | nc localhost 11211
```

### Memcached on Heroku

To deploy on Heroku:

```bash
$ heroku create
$ heroku addons:add memcachedcloud
$ git push heroku master
```
