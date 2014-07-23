opendig
=======

### Table of Contents
[Overview](#overview)  
[Installation](#installation)  
[Command Line Usage](#cli)  
[Python Package Usage](#pythonpackage)  
[Configuration](#configuration)  

<a name="overview"/>
## Overview

opendig is the equivalent of dig for the Open Name System, which extends DNS by supporting the registration and resolution of:

1. user handles on the blockchain (deployed)
1. domains on the blockchain (design phase)

#### ONS = ICANN DNS + blockchain handles + blockchain domains

ONS is 100% backwards compatible with ICANN DNS and simply extends the functionality.

Likewise, opendig has 100% of the functionality of dig.

<a name="installation"/>
## Installation

```
$ sudo pip install opendig
```

<a name="cli"/>
## Command-line Usage

```
$ opendig -u naval
$ opendig bitcoin -u naval
$ opendig -d startupboy.com
```

<a name="pythonpackage"/>
## Python Package Usage

```
from opendig import ons_resolver
print ons_resolver('naval')

from opendig import dns_resolver
print dns_resolver('startupboy.com')
```

<a name="configuration"/>
## Configuration

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
