# Stacks Testnet

This folder contains the code for the Stacks testnet website.

## Prerequisites

You must install Blockstack Core and its integration tests.  Please see [this
document](../README.md) to install Blockstack Core, and see [this
document](../integration-tests/README.md) to install the integration tests.

## Deploying

To build the website, run `make`.  The site assets will be written to `./www/`.

To deploy the website, you should do the following:

* Copy the contents of `./www/` to `/var/www/html` (or wherever your Web server serves from).
* Edit `./blockstack-public-testnet.sh` to set `BLOCKSTACK_TESTNET_PUBLIC_HOST`
  to your server's hostname.
* Start the testnet back-end by running `./blockstack-public-testnet.sh`.  Note
  that you may need to open some ports for the various testnet services.  You
can get the URLs and ports that need to be exposed with `curl
http://your-testnet-site/config`.

You can test the website locally by running `make mocktest`.  This will generate
the website and serve it on `http://localhost:8000` using mocked data.


