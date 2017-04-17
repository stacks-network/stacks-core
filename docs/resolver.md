# Blockstack Resolver

During 2014-2016, Bockstack resolver was a separate service (like DNS resolvers). 
It was merged into the Blockstack API in early 2017.

The following (legacy) API call is still being supported by the Blockstack API:

```
http://localhost:5000/v2/users/fredwilson
```

And you can see a legacy resolver in action at http://resolver.onename.com/v2/users/fredwilson

## Cron Job for Namespaces

**Note: the instructions below need updating.**

Currently, the resolver indexes all valid names in a local file which can be
populated by running
> $ ./refresh_names.sh

On a production deployment, you should add a crond job to periodically run this
script. You can edit your crontab file by:
> $ crontab -e

Here is a sample crontab file that runs the refresh script every two hours: 
```
SHELL=/bin/bash
HOME=/home/ubuntu

#This is a comment
0 */2 * * * /home/ubuntu/resolver/resolver/refresh_names.sh
```
