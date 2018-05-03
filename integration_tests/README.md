# Blockstack Integration Tests

This is the end-to-end Blockstack test framework. New Blockstack
developers should familiarize themselves with this first, since the
integration tests offer a straightforward way to set up and run all
the components in a sandboxed environment.

Once installed, developers can easily interact with a fully-featured
Blockstack core node running on a private Bitcoin blockchain.

# Getting Started with Docker

**NOTE**: This is only supported for the `develop` and `master` branches of
Blockstack Core.  For testing `feature` branches, including the upcoming Stacks
token implementation, you must install from source.
See [this section](#install-from-source) for details.

The easiest way to get started with our integration tests on the `develop`
branch is to use our integration test docker images.

You can pull the integration test image from quay.

```bash
docker pull quay.io/blockstack/integrationtests:develop
```

To see a full list of tags check out our [Quay repo](https://quay.io/organization/blockstack)!

The `test-launcher` tool can also be used to build an integration test
image from your local repository.

Once you have the docker image, you can run individual test
scenarios. Test scenarios are organized as Python modules, which can
be imported from `blockstack_integration_tests.scenarios`. For
example, the following command runs the test that will create a
`.id` namespace, preorder and register the name `foo.id`, set its
zonefile hash, and create an empty profile for it:

```bash
IMAGE=$(docker run -dt -v /tmp:/tmp quay.io/blockstack/integrationtests:develop blockstack-test-scenario blockstack_integration_tests.scenarios.browser_env)
```

You can check the status of the test:

```bash
docker logs -f $IMAGE
```

And stop the test with:
```bash
docker stop $IMAGE
```

## Running interactive tests with Docker

You can setup an interactive regtest environment for connecting to a
Blockstack Browser (or interaction via the CLI).

In interactive mode, a test idles after its checks finish (i.e. after
`check()` returns).  This leaves you with a running Bitcoin node and a
running Blockstack Core node that you can interact with via the
Blockstack CLI, as if it were a production system.

To start a test in interactive mode, pass the `--interactive` switch.

For example, with the docker file already pulled, you can execute:

```bash
IMAGE=$(docker run -dt -p 16268:16268 -p 16269:16269 -p 18332:18332 -e BLOCKSTACK_TEST_CLIENT_RPC_PORT=16268 -e BLOCKSTACK_TEST_CLIENT_BIND=0.0.0.0 -e BLOCKSTACK_TEST_BITCOIND_ALLOWIP=172.17.0.0/16 quay.io/blockstack/integrationtests:develop blockstack-test-scenario --interactive 2 blockstack_integration_tests.scenarios.browser_env)
```

You know the setup has finished when it has displayed in the log:

```bash
$ docker logs -f $IMAGE | grep inished
```

Note: To obtain regtest bitcoins in the browser's wallet during testing-mode,
use the hidden browser page (http://localhost:8888/wallet/send-core) or
(http://localhost:3000/wallet/send-core) to send bitcoins to the address.

# Getting Started with Python virtualenv and local bitcoind
(#install-from-source)

You can run the integration test framework without using our docker containers, however, this
requires a bit more setup.

To install the test framework, first install `blockstack-core` and all of its
dependencies (done above).

```bash
    $ virtualenv --python=python2 blockstack-testing
    $ cd blockstack-testing
    $ source bin/activate
    (blockstack-testing) $ git clone https://github.com/blockstack/blockstack-core blockstack-core
    (blockstack-testing) $ cd blockstack-core/ && ./setup.py build && ./setup.py install
```

Next, you will need to install the Blockstack Gaia hub, the Blockstack subdomain
registrar, and the Blockstack transaction broadcaster.  Instructions:

* [Installing the Blockstack Subdomain Registrar](https://github.com/blockstack/subdomain-registrar)
* [Installing the Blockstack Transaction Broadcaster](https://github.com/blockstack/transaction-broadcaster)
* [Installing the Gaia Hub](https://github.com/blockstack/gaia/tree/master/hub)

You will need to install them somewhere in your `PATH`:

```bash
$ which blockstack-subdomain-registrar
/usr/bin/blockstack-subdomain-registrar
$ which blockstack-transaction-broadcaster
/usr/bin/blockstack-transaction-broadcaster
$ which blockstack-gaia-hub
/usr/bin/blockstack-gaia-hub
```

**macOS Note**: Installing the python `scrypt` library on macOS
requires OpenSSL headers. Those can be obtained via HomeBrew (and
setup using environment variables `LDFLAGS` and
`CPPFLAGS`). Alternatively, you can use the virtualenv tarball that
ships with our macOS releases of Blockstack Browser. Generally, on
macOS, it is much easier to setup our test environment with Docker.

Then, do the following to install the integration tests:

```
    $ cd integration_tests/
    $ ./setup.py build && sudo ./setup.py install
```

## Installing bitcoind in macOS

You'll need the `bitcoind` console app, which apparently doesn't
come included with `Bitcoin-QT` on macOS, so we'll need to build
it from source, using this [guide](https://github.com/bitcoin/bitcoin/blob/master/doc/build-osx.md)

Summary:
```bash
$ brew install automake berkeley-db4 libtool boost --c++11 miniupnpc openssl pkg-config protobuf qt libevent
$ git clone https://github.com/bitcoin/bitcoin
$ cd bitcoin
$ ./autogen.sh
$ ./configure
$ make
```

You need to add the `src/` directory from your bitcoind build to your
path:

```
$ export PATH=/Users/Whomever/Wherever/bitcoin/src:$PATH
```


## Running tests

Run a test with the `blockstack-test-scenario` command

```
     $ blockstack-test-scenario blockstack_integration_tests.scenarios.portal_test_env
```

If all is well, the test will run for a few minutes and print:

```
     SUCCESS blockstack_integration_tests.scenarios.portal_test_env
```

## Interactive Testing

There are two ways to set up interactive testing:

* Generate blocks automatically every *n* seconds.
* Present a Web-facing control panel for generating blocks and funding
  addresses.

To do the former, pass `--interactive <blocktime>` to
`blockstack-test-scenario`, where `<blocktime>` is the amount of seconds between
blocks.

To do the latter, pass `--interactive-web <portnum>` to
`blockstack-test-scenario`, where `<portnum>` is the port number on which the
test framework will serve a control Web page.

### Interactive Web Testing

If you start the test with `--interactive-web 3001` and let it run to
completion, you will be able to load `http://localhost:3001` in your Web browser
and see a screen like this:

![Blockstack integration test control
panel](https://github.com/blockstack/blockstack-core/blob/master/docs/figures/test-screen.png)

* The **`Blockchain height`** field indicates how many blocks have been
  generated.  This is 693 in this figure.

* The **`Number of blocks`** form field is the number of blocks to generate.
  Simply type in a number and click "Generate blocks" to generate that many
blocks on the test framework's blockchain.

* The **`Fund address`** and **`value (satoshis)`** form field lets you fund an
  arbitrary address with the given number of satoshis.

* The **`Done testing`** button ends the test.

When you register a name with the Browser, and you are using interactive
Web testing, you should do the following to make sure the transaction confirms:

1. Generate 12 blocks via the Web panel
2. Check the test output and make sure your `NAME_PREORDER` transaction went
   through.  You should see a line that looks like `ACCEPT NAME_PREORDER`.
3. Generate 12 more blocks via the Web panel
4. Check that test output and make sure your `NAME_REGISTRATION` transaction
   went through.  You should see a line that looks like `ACCEPT
NAME_REGISTRATION`.

When you fund an address, you should generate 6 blocks via the Web panel in
order to "confirm" it.

### Testing the Blockstack Browser

This example will set up an interactive regtest node that you can connect to via Blockstack Browser

```bash
 $ BLOCKSTACK_TEST_CLIENT_RPC_PORT=6270 blockstack-test-scenario --interactive 2 blockstack_integration_tests.scenarios.browser_env
```

In this example, a block will be generated once every 2 seconds.

You can also do this:

```bash
 $ BLOCKSTACK_TEST_CLIENT_RPC_PORT=6270 blockstack-test-scenario --interactive-web 3001 blockstack_integration_tests.scenarios.browser_env
```

In this example, you will need to manually generate blocks in order to confirm
name registrations.  However, you can
also fund arbitrary addresses in this mode, which makes it easier to do more
advanced things (like test a subdomain registrar, create a namespace, or test
the Blockstack wallet).

# Information on the testing Framework

Internally, the test-runner (`blockstack-test-scenario`) starts up a
Bitcoin node locally in `-regtest` mode, giving the test its own
private testnet blockchain.  It mines some blocks with Bitcoin, fills
some test-specified addresses with an initial balance (those specified
in the test module's `wallets` global variable), and sets up a
temporary configuration directory tree in
`/tmp/blockstack-run-scenario.blockstack_integration_tests.scenarios.<foo>/`.

Once Bitcoin is ready, the test-runner starts up Blockstack Core and
has it crawl the local Bitcoin blockchain.  It then runs the test's
`scenario()` method, which feeds it a string of Blockstack CLI
commands at the desired block heights.  Once the `scenario()` method
finishes, the test runner calls the `check()` method to verify that
the test generated the right state.  If this passes, the test-runner
verifies the Blockstack node's database integrity, performs automated
SNV tests, and checks that the Atlas network crawled the right
zonefiles.


Relevant Files, Ports, Tips, and Tricks
---------------------------------------

* Bitcoin in regtest mode runs its JSON-RPC server on port 18332, and its peer-to-peer endpoint on port 18444.

* The Blockstack Core indexer and Atlas peer runs on port 16264.  **This is a private API; do not talk to it directly.**

* The Blockstack RESTful HTTP endpoint runs on port 16268.  **This is what you want to use to programmatically interact with Blockstack.**

* All state for a given test is located under `/tmp/blockstack-run-scenario.blockstack_integration_tests.scenarios.${SCENARIO_NAME}/`, where `${SCENARIO_NAME}` is the name of the test (e.g. `portal_test_env`).

* The Core node's log file is located at `/tmp/blockstack-run-scenario.blockstack_integration_tests.scenarios.${SCENARIO_NAME}/blockstack-server.log`.

* The Atlas and indexer node's config file is located at `/tmp/blockstack-run-scenario.blockstack_integration_tests.scenarios.${SCENARIO_NAME}/blockstack-server.ini`.

* The Sqlite3 name database is located at `/tmp/blockstack-run-scenario.blockstack_integration_tests.scenarios.${SCENARIO_NAME}/blockstack-server.db`.

* The history of accepted transactions and consensus hashes for the Core node is located in the Sqlite3 database at `/tmp/blockstack-run-scenario.blockstack_integration_tests.scenarios.${SCENARIO_NAME}/blockstack-server.snapshots`.

Troubleshooting
---------------

* Before starting your test, make sure that there are no `bitcoind -regtest`
  processses running.  Also, make sure that there are no lingering integration
  tests processes running.  This can happen if your test encounters a fatal
  error and does not get a chance to clean itself up properly.

* If your Core node fails to start, you should check the `blockstack-server.log` file in order to verify that the Core node didn't crash or misbehave.

* You can verify that your Core node is running with `curl http://localhost:16268`.  You should get back a simple HTML page.

* Test output can be lengthy.  If you want to preserve it, we recommend `tee(1)`-ing it to a log file.

### ImportError: No module named \_scrypt

The integration test suite depends on [scrypt](https://pypi.python.org/pypi/scrypt/) at this time.  However,
some Linux distributions have a hard time installing it.

Running this command usually fixes this issue:

```
$ pip uninstall scrypt; pip install scrypt
```

CLI Examples
--------

**TODO**:  These use the deprecated Blockstack CLI.  Need to update them.

You can register names like normal when running the test in interactive mode:

```
     $ blockstack register bar.test
     Registering bar.test will cost 0.06481015 BTC.
     The entire process takes 30 confirmations, or about 5 hours.
     You need to have Internet access during this time period, so
     this program can send the right transactions at the right
     times.

     Continue? (Y/n): y
     {
         "message": "The name has been queued up for registration and will take a few hours to go through. You can check on the status at any time by running 'blockstack info'.", 
         "success": true,
         "transaction_hash": "4fa9cd94f195b1aa391727c8949d88dbae25eddf1097bc8930fdb44c6a27b3d7"
     }
```

You can check the status of the name as it gets registered on the regtest blockchain, just as you would on the mainnet blockchain.
Because blocktimes are only 10 seconds in this example, names get registered quickly.

```
     $ blockstack info             
     {
         "advanced_mode": true, 
         "cli_version": "0.14.2", 
         "consensus_hash": "bf168a3b5437c11c744891d38dffb8f2", 
         "last_block_processed": 305, 
         "last_block_seen": 305, 
         "queue": {
             "preorder": [
                 {
                     "confirmations": 7, 
                     "name": "bar.test", 
                     "tx_hash": "4fa9cd94f195b1aa391727c8949d88dbae25eddf1097bc8930fdb44c6a27b3d7"
                 }
             ]
         }, 
         "server_alive": true, 
         "server_host": "localhost", 
         "server_port": 16264, 
         "server_version": "0.14.2"
     }
```

As far as Blockstack is concerned, it thinks its running on the Bitcoin testnet.  As such, you'll see that your names are
owned by testnet-formatted addresses:

```
     $ blockstack names
     {
         "addresses": [
             {
                 "address": "n44rMyQ9rhTf7KjFdRwDNMWUSJ3MWLsDQ4", 
                 "names_owned": [
                     "foo.test", 
                     "bar.test"
                 ]
             }
         ], 
         "names_owned": [
             "foo.test", 
             "bar.test"
         ]
     }
```
     
Once the name registers, you'll see that its profile and zonefile are automatically generated and stored,
and will be loaded from the pre-configured `disk` driver (the defualt driver used by the test framework):

```
    $ BLOCKSTACK_DEBUG=1 blockstack lookup bar.test
    [2016-10-03 17:41:00,892] [DEBUG] [spv:110] (15317.139910730368768) Using testnet/regtest
    [2016-10-03 17:41:01,038] [WARNING] [config:104] (15317.139910730368768) TX_MIN_CONFIRMATIONS = 0
    [2016-10-03 17:41:01,038] [WARNING] [config:276] (15317.139910730368768) CONFIG_PATH = /tmp/blockstack-run-scenario.blockstack_integration_tests.scenarios.rpc_register/client/client.ini
    [2016-10-03 17:41:01,085] [DEBUG] [cli:210] (15317.139910730368768) Enabling advanced methods
    [2016-10-03 17:41:01,125] [DEBUG] [client:134] (15317.139910730368768) Loaded storage driver 'disk'
    [2016-10-03 17:41:01,140] [DEBUG] [storage:285] (15317.139910730368768) get_immutable b4d1edb5ea706310b4599540a8d76ead4c7afd96
    [2016-10-03 17:41:01,141] [DEBUG] [storage:311] (15317.139910730368768) Try disk (b4d1edb5ea706310b4599540a8d76ead4c7afd96)
    [2016-10-03 17:41:01,141] [DEBUG] [storage:345] (15317.139910730368768) loaded b4d1edb5ea706310b4599540a8d76ead4c7afd96 with disk
    [2016-10-03 17:41:01,206] [DEBUG] [storage:422] (15317.139910730368768) get_mutable bar.test
    [2016-10-03 17:41:01,206] [DEBUG] [storage:462] (15317.139910730368768) Try disk (file:///tmp/blockstack-disk/mutable/bar.test)
    [2016-10-03 17:41:01,268] [DEBUG] [storage:492] (15317.139910730368768) loaded 'file:///tmp/blockstack-disk/mutable/bar.test' with disk
    {
        "profile": {
            "@type": "Person", 
            "accounts": []
        }, 
        "zonefile": '$ORIGIN bar.test\n$TTL 3600\npubkey TXT "pubkey:data:039408bc142ffe926a5865cb35447bb6142c9170e74ec194186f96129a37eb9033"\n_file URI 10 1 "file:///tmp/blockstack-disk/mutable/bar.test"\n'
    }
```

Namespace Creation Example
--------------------------

You can test out the namespace creation functions once you've got a shell
set up to connect to your regtest environment:

First, get the private keys you'll use for the namespace:
```bash
$ blockstack wallet
{
    "data_privkey": "bb68eda988e768132bc6c7ca73a87fb9b0918e9a38d3618b74099be25f7cab7d01",
    "data_pubkey": "04ea5d8c2a3ba84eb17625162320bb53440557c71f7977a57d61405e86be7bdcdab63a7f1eda1e6c1670c64a9f532b9f55458019d9b80fdf41748d06cd7f60d451", 
    "owner_address": "myaPViveUWiiZQQTb51KXCDde4iLC3Rf3K",
    "owner_privkey": "8f87d1ea26d03259371675ea3bd31231b67c5df0012c205c154764a124f5b8fe01",
    "payment_address": "mvF2KY1UbdopoomiB371epM99GTnzjSUfj",
    "payment_privkey": "f4c3907cb5769c28ff603c145db7fc39d7d26f69f726f8a7f995a40d3897bb5201"
}
```

For testing, I use the `payment_privkey` above to fund the namespace creation and `owner_privkey`
as the namespace reveal key.

```bash
$ PAYMENTKEY="f4c3907cb5769c28ff603c145db7fc39d7d26f69f726f8a7f995a40d3897bb5201"
$ REVEALKEY="8f87d1ea26d03259371675ea3bd31231b67c5df0012c205c154764a124f5b8fe01"
```

Now, you can perform the preorder.
```bash
$ blockstack namespace_preorder blankstein $PAYMENTKEY $REVEALKEY
```

Wait for the transaction to confirm, and then issue a "reveal". During
the reveal you configure the price function, expiration time of names,
and whether or not you receive funds.
```bash
$ blockstack namespace_reveal blankstein $PAYMENTKEY $REVEALKEY
```

Once your reveal your namespace, you can issue a "ready", and then

```bash
$ blockstack namespace_ready blankstein $REVEALKEY
```
