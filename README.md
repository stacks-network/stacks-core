opendig
=======

Command-line tool for Open Name System (like dig is for DNS)

Installation
=======

```
$ sudo pip install opendig
```

Command-line Usage
=======

```
$ opendig -u naval
$ opendig bitcoin -u naval
$ opendig -d startupboy.com
```

Python Package Usage
=======
```
from opendig import ons_resolver
print ons_resolver('naval')

from opendig import dns_resolver
print dns_resolver('startupboy.com')
```

Configuration
=======

OpenDig comes with pre-configured default servers 8.8.8.8 (public DNS server by Google) and 162.243.253.65 (public ONS server by OneName). We *strongly* recommend using a local config file, and using servers of your own choice:

```
$ touch ~/.opendig
$ vi ~/.opendig
```
A sample config looks like this:

```
[dns]
servers = 8.8.8.8, 8.8.4.4

[ons]
#all these servers are queried and a check is performed that they return the same data
#to reduce trust on any single party, use your own servers or multiple public servers
servers = 162.243.253.65, 107.170.167.141

[namecoind]
port = 8332
user = opennamesystem
passwd = opennamesystem
use_https = True
```
