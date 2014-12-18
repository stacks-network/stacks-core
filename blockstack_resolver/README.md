Openname-resolver
=======

## Overview: 

Openname-resolver is a highly scalable server for [Openname System](https://openname.org). It resolves opennames (usernames) to profile data. It is blockchain-agnostic (currently uses the Namecoin blockchain) and is primarily meant for scaling read-only calls to the underlying blockchain. For achieving high throughput openname-resolver loads the entire namespace into memcached and then keeps the in-memory copy consistent with the blockchain. Read-only calls never hit disk and their scalability is completely decoupled from the scalability properties of the underlying database. 

## Setup Instructions:


###1. Openname-resolver requires memcached:

###Linux:
```
sudo apt-get install memcached libmemcached-dev zlib1g-dev
```

Before installing pylibmc (listed in requirements.txt) install the above packages.

Install coinrpc:
```
pip install git+ssh://git@github.com/opennamesystem/coinrpc.git
```

------------------------------------------------------------------
###Mac OS X:

Easiest way is to make use of brew

brew can  be installed by:
```
	ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)”
```
After installation:
```
brew install libmemcached
```
libmemcached dependencies: 
		```
		memcached : brew intall memcached 
		libevent(should automatically install) :  brew intall libevent 
		```

------------------------------------------------------------------
###2. running memcache:
/usr/local/opt/memcached/bin/memcached


an easier way to launch memcache is to use Lunchy:

Lunchy is a gem that simplifies the command line interface to launchctl. To install Lunchy, do

gem install lunchy
```
  1. $ mkdir ~/Library/LaunchAgents
  2. $ cp /usr/local/Cellar/memcached/$version/homebrew.mxcl.memcached.plist ~/Library/LaunchAgents/
  3. $ lunchy start memcached
  4. $ lunchy stop memcached
```

------------------------------------------------------------------
###3. Ensure you have python 2.7 and python development headers installed:

on linux:
```
	sudo apt-get install python2.7-dev
```

on Mac:
	
	On mac headers are automatically installed during the process of python installation. Python 2.7 can be installed as follows.
  	```
  	1. brew install python
    2. brew link python

    3. ensure you GCC installed:
    	GCC can be obtained by downloading XCode, the smaller Command Line Tools (must have an Apple account) or the even smaller OSX-GCC-Installer package
    ```
	Comprehensive guide to installing python on mac:
	
		http://docs.python-guide.org/en/latest/starting/install/osx/#install-osx



------------------------------------------------------------------

###4. pip install git+ssh://git@github.com/onenameio/coinrpc.git

Note: above command may require sudo access :
	```
	sudo pip install git+ssh://git@github.com/onenameio/coinrpc.git
	```

	TODO: Add a non-ssh/HTTPS method as well for installing Coinrpc

------------------------------------------------------------------
###5. For quick deployment:

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
http://localhost:5000/resolver/value?key=u/naval
http://localhost:5000/resolver/profile?openname=naval
```

TODO/Suggestions:
 remove coinrpc from requirements.txt as it was already installed in the previous step. 
 It may give an exception: 'No distributions at all found for coinrpc==0.1.0 (from -r requirements.txt (line 5))'
 Also ensure requirments.txt is up-to-date. as a few things maybe missing from it. 

