# Blockstack API

You can read the API documentation and try out API calls at: https://core.blockstack.org

In general, all documentation is in the [docs/](https://github.com/blockstack/blockstack-core/tree/master/docs) directory.

Instructions for deploying your own (public) node are [here](https://github.com/blockstack/blockstack-core/tree/master/docs/install-api.md).

## Docker Instructions

These are instructions on how to run a core api node using docker! This is a production setup.

To start the Blockstack API from this folder, first initialize the `blockstack-core` database and the `blockstack api` with the init command:

```bash
# Install Dependancies
$ ./ops install-docker
$ ./ops install-nginx
$ ./ops install-certbot

# Enable sudo-less docker commands
# Replace `ubuntu` with your username
$ sudo usermod -aG docker ubuntu

# WARNING: This takes ~20 minutes to run
# Set up the dummy wallet for the core api
$ ./ops init-api
# Fast sync the core node
$ ./ops init-core
# Pull down the current version of the index
$ ./ops init-index

# Configure core server and nginx to point to proper domain
$ ./ops config-nginx {{ domain_name }}

# double check your /etc/nginx/sites-available/default file to make sure its right
$ sudo nginx -t
# double check your config.py file to make sure its right, the following should return 2 lines
$ cat config.py | grep my.domain.tld

# Now you are ready to deploy!
$ sudo docker-compose up -d
```
