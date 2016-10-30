Blockstack Integration Tests
----------------------------

This is the end-to-end Blockstack test framework.  New Blockstack developers should familiarize themselves with this repository first, 
since the integration tests offer a straightforward way to set up and run all the components in a sandboxed environment.  Once installed,
developers can easily interact with a fully-featured Blockstack core node running on a private Bitcoin blockchain.

Dependencies
------------

The tests cover the following repositories, and must be installed prior to running integration tests:

* [virtualchain](https://github.com/blockstack/virtualchain)
* [blockstack-core](https://github.com/blockstack/blockstack-core)
* [blockstack-cli](https://github.com/blockstack/blockstack-cli)
* [blockstack-file](https://github.com/blockstack/blockstack-files)
* [blockstack-gpg](https://github.com/blockstack/blockstack-gpg)
* [blockstack-zones](https://github.com/blockstack/dns-zone-file-py)
* [blockstack-profiles](https://github.com/blockstack/blockstack-profiles-py)

The `get_started.sh` script in the root directory will fetch and install the latest branches of all the required Blockstack packages.
**If you want to install the latest branches alongside the stable Blockstack packages, you should use a virtual environment.**

In addition, you must install the Bitcoin daemon and CLI tool.

Getting Started
---------------

Once all of the required packages are installed (see `get_started.sh`), you can run individual test scenarios.  Test scenarios
are organized as Python modules, which can be imported from `blockstack_integration_tests.scenarios`.  For example, the following
command runs the test that will create a `.test` namespace, preorder and register the name `foo.test`, set its zonefile hash, 
and create an empty profile for it:

```
     $ blockstack-test-scenario blockstack_integration_tests.scenarios.rpc_register
```

If all is well, the test will run for a few minutes and print:

```
     SUCCESS blockstack_integration_tests.scenarios.rpc_register
```

Internally, the test-runner (`blockstack-test-scenario`) starts up a Bitcoin node locally in `-regtest` mode, giving the test its own private testnet
blockchain.  It mines some blocks with Bitcoin, fills some test-specified addresses with an initial balance (those specified in the 
test module's `wallets` global variable), and sets up a temporary configuration
directory tree in `/tmp/blockstack-run-scenario.blockstack_integration_tests.scenarios.rpc_register/`.

Once Bitcoin is ready, the
test-runner starts up Blockstack Core and has it crawl the local Bitcoin blockchain.  It then runs the test's `scenario()` method, which 
feeds it a string of Blockstack CLI commands at the desired block heights.  Once the `scenario()` method finishes, the test runner
calls the `check()` method to verify that the test generated the right state.  If this passes, the test-runner verifies the 
Blockstack node's database integrity, performs automated SNV tests, and checks that the Atlas network crawled the right zonefiles.

Interactive Testing
-------------------

By default, tests run in an automated fashion.  However, you can make the test idle after its checks finish (i.e. after `check()`
returns).  This leaves you with a running Bitcoin node and a running Blockstack Core node that you can interact with via the Blockstack CLI, as if it 
were a production system.  The idea here is to use the test to pre-populate the blockchain and Blockstack Core node with
the state you want (i.e. particular names and namespaces, particular addresses with the balances you want, etc.), and then experiment
manually from there.

To start a test in interactive mode, pass the `--interactive` switch with your desired block time (in seconds).  For example, this
command will run the test, and make both Bitcoin and Blockstack Core advance by one block every 10 seconds once the test logic
finishes:

```
     $ blockstack-test-scenario --interactive 10 blockstack_integration_tests.scenarios.rpc_register
```

Hitting `^C` (or sending `SIGINT`) to the `blockstack-test-scenario` process will cause the test to stop idling, finish its built-in
tests, and clean up after itself.

While the test is idling, you can interact with the Blockstack Core node with the Blockstack CLI.  To do so, you'll need to set
the following environment variables:

```
     $ export BLOCKSTACK_TEST=1    # tells Blockstack CLI that it's running with the test environment
     $ export BLOCKSTACK_TESTNET=1 # tells Blockstack CLI to use testnet addresses
     $ export BLOCKSTACK_DEBUG=1   # print debug-level output in the CLI; great for troubleshooting
     $ 
     $ # this tells the CLI where to find the test-generated config file
     $ export BLOCKSTACK_CLIENT_CONFIG=/tmp/blockstack-run-scenario.blockstack_integration_tests.scenarios.name_preorder_register/client/client.ini
```

Once set, you can use the Blockstack CLI as normal, and it will interact with the test case's Blockstack Core node:

```
     $ blockstack lookup foo.test
     {
         "profile": {
             "@type": "Person", 
             "accounts": []
         }, 
         "zonefile": {
             "$origin": "foo.test", 
             "$ttl": 3600, 
             "txt": [
                 {
                     "class": "IN", 
                     "name": "pubkey", 
                     "txt": "pubkey:data:03762f2da226d9c531e8ed371c9e133bfbf42d8475778b7a2be92ab0b376539ae7"
                 }
             ], 
             "uri": [
                 {
                     "class": "IN", 
                     "name": "_file", 
                     "priority": 10, 
                     "target": "file:///tmp/blockstack-disk/mutable/foo.test", 
                     "weight": 1
                 }
             ]
         }
     }
```

Examples
--------

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
         "cli_version": "0.14.0", 
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
         "server_version": "0.14.0"
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
        "zonefile": {
            "$origin": "bar.test", 
            "$ttl": 3600, 
            "txt": [
                {
                    "class": "IN", 
                    "name": "pubkey", 
                    "txt": "pubkey:data:039408bc142ffe926a5865cb35447bb6142c9170e74ec194186f96129a37eb9033"
                }
            ], 
            "uri": [
                {
                    "class": "IN", 
                    "name": "_file", 
                    "priority": 10, 
                    "target": "file:///tmp/blockstack-disk/mutable/bar.test", 
                    "weight": 1
                }
            ]
        }
    }
````


