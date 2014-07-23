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

`opendig` is a command-line tool that extends the functionality of `dig` to be compatible with the Open Name System. Specifically, it adds support for the resolution of blockchain user handles.

ONS extends DNS in a backwards-compatible way by supporting the registration and resolution of:

+ user handles on the blockchain (currently supported by opendig)
+ domains on the blockchain (in the design phase)

#### ONS = ICANN DNS + blockchain handles + blockchain domains

User calls to opendig will return user data in a standard schema.

[Read about the schema](https://github.com/opennamesystem/openspecs)

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

OpenDig comes with pre-configured default servers 8.8.8.8 (public DNS server by Google) and 162.243.253.65, 107.170.167.141 (public ONS server by OneName). We *strongly* recommend using a local config file, and using servers of your own choice:

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
