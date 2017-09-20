# Using docker

You can setup our integration test with docker.

First, pull the integration test container from quay.

```
docker pull quay.io/blockstack/integrationtests:develop
```

Then, start the docker container:

```
docker run -dt -p 6270:6270 -v /tmp:/tmp -e BLOCKSTACK_TEST_CLIENT_RPC_PORT=6270 -e BLOCKSTACK_TEST_CLIENT_BIND=0.0.0.0 quay.io/blockstack/integrationtests:develop blockstack-test-scenario --interactive 2 blockstack_integration_tests.scenarios.portal_test_env
```

You can see the running container:

```
$ docker ps
```

And the setup has completed:

```
$ IMAGE=$(docker ps | grep "quay.io/blockstack/blockstack-core-with-regtest:develop" | awk '{ print $1 }')
$ docker logs -f $IMAGE | grep inished

```


Documentation for setting up the regtest mode for Blockstack Browser
using core's integration tests in macOS and Linux has
moved [here](../integration_tests).
