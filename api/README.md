# Blockstack API

You can read the API documentation and try out API calls at: https://core.blockstack.org

In general, all documentation is in the [docs/](https://github.com/blockstack/blockstack-core/tree/master/docs) directory.

Instructions for deploying your own (public) node are [here](https://github.com/blockstack/blockstack-core/tree/master/docs/install-api.md).

## Docker Instructions

To start the Blockstack API from this folder, first initialize the `blockstack-core` database:

```bash

# Create Directory for blockstack-core config and blockstack api config
$ mkdir -p data/blockstack-core/server/ data/blockstack-api/

# Copy over the blockstack-core config
$ cp deployment/blockstack-server.ini data/blockstack-core/server/blockstack-server.ini
# $ cp deployment/client.ini data/blockstack-api/client.ini

# Download the Atlas network
$ docker run -d --rm\
    -v $(pwd)/data/blockstack-core/server/:/root/.blockstack-server/ \
    -v $(pwd)/data/blockstack-core/api/:/root/.blockstack \
    quay.io/blockstack/blockstack-core:develop-configure-mongo \
    blockstack-core --debug fast_sync http://fast-sync.blockstack.org/snapshot.bsk

$ docker run -it --rm \
    -v $(pwd)/data/blockstack-api/:/root/.blockstack \
    quay.io/blockstack/blockstack-core:develop-configure-mongo \
    blockstack setup -y --password dummywalletpassword

$ sed -i 's/api_endpoint_bind = localhost/api_endpoint_bind = 0.0.0.0/'
$ sed -i 's/api_endpoint_host = localhost/api_endpoint_host = 0.0.0.0/'
```
