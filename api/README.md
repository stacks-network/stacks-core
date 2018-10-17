# Blockstack API

You can read the API documentation and try out API calls at: https://core.blockstack.org

In general, all documentation is in the [docs/](https://github.com/blockstack/blockstack-core/tree/master/docs) directory.

Instructions for deploying your own (public) node are [here](https://github.com/blockstack/blockstack-core/tree/master/docs/install-api.md).

### Running in docker

This directory contains the necessary components for running this API in docker for development purposes. To do so run the following commands:

```bash
# Build the docker images and run them
# NOTE: this build step takes quite a bit of time
$ docker-compose up --build -d 
```

### Environment Variables for Deployment

The following is a list of environmental variables that help configure the API, and their defaults:

```bash
# MAX_PROFILE_LIMIT determines the max profile size that the node will index
MAX_PROFILE_LIMIT=8142       # (8 * 1024) - 50 or roughly 8kb limit

# DEFAULT_CACHE_TIMEOUT determines the
DEFAULT_CACHE_TIMEOUT=43200  # 12 hours in seconds

# DEBUG increases logging verbosity
DEBUG=False

# DEFAULT_PORT sets the port that the process will run on
DEFAULT_PORT=5000

# DEFAULT_HOST sets the host for the flask app
DEFAULT_HOST=localhost

# PUBLIC_NODE disables posts to the API to prevent malicous use
PUBLIC_NODE=False

# MONGODB_URI contains the connection string to use for connecting to mongo
MONGODB_URI=mongodb://localhost

# BASE_API_URL sets the blockstack api connection string
BASE_API_URL=http://localhost:6270

# PUBLIC_NODE_URL controls the what hostname is returned to clients
PUBLIC_NODE_URL=https://core.example.org

# SEARCH_NODE_URL sets the search API connection string
SEARCH_NODE_URL=https://search.example.org

# SEARCH_DEFAULT_LIMIT sets the number of results per call
SEARCH_DEFAULT_LIMIT=50

# BSK_API_TMPLTDIR sets the path to the generated documentation for serving
BSK_API_TMPLTDIR=/src/blockstack/api/templates
```
