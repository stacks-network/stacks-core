# Blockstack API

You can read the API documentation and try out API calls at: https://core.blockstack.org

In general, all documentation is in the [docs/](https://github.com/blockstack/blockstack-core/tree/master/docs) directory.

Instructions for deploying your own (public) node are [here](https://github.com/blockstack/blockstack-core/tree/master/docs/install-api.md).

## Docker Instructions

These are instructions on how to run a core api node using docker! This is a production setup.

To start the Blockstack API from this folder, first initialize the `blockstack-core` database and the `blockstack api` with the init command:

```bash
# Install Dependancies
$ sudo ./ops install-docker
$ sudo ./ops install-nginx
$ sudo ./ops install-certbot

# Enable sudo-less docker commands
$ usermod -aG docker ${USER}
$ exec bash

# WARNING: This takes ~20 minutes to run
# Set up the dummy wallet for the core api
# Fast sync the core node
# Pull down the current version of the index
# Configure core server and nginx to point to proper domain
$ sudo ./ops init


# Now you are ready to deploy!
$ docker-compose up
```
