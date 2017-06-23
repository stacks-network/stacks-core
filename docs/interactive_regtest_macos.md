
# Install bitcoind

You'll need the `bitcoind` console app, which apparently doesn't
come included with `Bitcoin-QT` on macOS, so we'll need to build
it from source, using this [guide](https://github.com/bitcoin/bitcoin/blob/master/doc/build-osx.md)

Summary:
```
$ brew install automake berkeley-db4 libtool boost --c++11 miniupnpc openssl pkg-config protobuf qt libevent
$ git clone https://github.com/bitcoin/bitcoin
$ cd bitcoin
$ ./autogen.sh
$ ./configure
$ make
```

# Run the integration test

To set up the regtest bitcoind/blockstack-core, use the integration
test framework in the interactive mode.

You need to add the `src/` directory from your bitcoind build to your
path:

```
$ export PATH=/Users/Whomever/Wherever/bitcoin/src:$PATH
```

The virtualenv that gets packed up with portal doesn't have the
integration test binary installed. However, circleCI is currently
building a virtualenv tarball that will work! 
(check builds on branch osx-single-file-build)

To run the integration test, you want to run the
blockstack-test-scenario from the virtualenv: (Note: The first time
this runs, it may fail (you can watch the output from
/tmp/blockstack_regtest_setup_out)).

```
$ BLOCKSTACK_TEST_CLIENT_RPC_PORT=6270 blockstack-venv/bin/blockstack-test-scenario --interactive 2 blockstack_integration_tests.scenarios.portal_test_env 2>&1 | tee /tmp/blockstack_regtest_setup_out | grep "go"
```

This will setup the `id` namespace and give you a wallet with ~50 BTC
(it also runs its own core API service, so don't try to start a new
one.) The api_password is `blockstack_integration_test_api_password`
Bitcoin blocks occur every two seconds.

Now, when you start portal (remember: don't try to start a new core
API service), give it this api_password, and everything should be
interacting with the regtest blockstack.

# Killing the integration test

The integration test can sometimes escape responsiveness to Ctrl-C
interrupts. Just `kill -9` the three processes -- there should be two
Python processes `blockstack-test-scenario` and then one `bitcoind`
process.

