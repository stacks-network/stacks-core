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
server1 = 8.8.8.8
server2 = 8.8.4.4

[ons]
server1 = 162.243.253.65
server2 = 107.170.167.141

[namecoind]
port = 8332
user = opennamesystem
passwd = opennamesystem
use_https = True
```
