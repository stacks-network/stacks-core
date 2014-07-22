opendig
=======

Command-line tool for Open Name System (like dig is for DNS)

Installation
=======

> $ sudo pip install opendig

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
print ons_resolver('u/'+'naval')

from opendig import dns_resolver
print dns_resolver('startupboy.com')
```
