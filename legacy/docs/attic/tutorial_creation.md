---
layout: core
permalink: /:collection/:path.html
---
# Create and Launch a Namespace
{:.no_toc}

This tutorial teaches you how to create your namespace, it contains the
following sections:

* TOC
{:toc}


Creating namespaces is expensive.
Be sure to test your namespace in our [integration test
framework](https://github.com/blockstack/blockstack-core/tree/master/integration_tests)
first!  It will let you simulate any valid namespace configuration
you want at no risk to you.


>**WARNING**:  If you intend to create a namespace, you must read this document
_in its entirety_.  You should also _install the test framework_ and experiment
with your namespace's parameters.  _FAILURE TO DO SO MAY RESULT IN IRRECOVERABLE
LOSS OF FUNDS._

## Before you begin

Some basic familiarity with how Bitcoin works is required to
understand this tutorial.  This includes:

* knowing the difference between mainnet, testnet, and regtest
* knowing about compressed and uncompressed ECDSA public keys
* knowing about base58-check encoding
* knowing how Bitcoin transactions are structured
* knowing how UTXOs work

Creating a namespace is a three-step process.  The first step is to `preorder`
the namespace, which broadcasts a salted hash of the namespace ID.  The second
step is to `reveal` the namespace, which exposes the namespace ID and price
function to the blockchain.  The final step is to `ready` the namespace, which
allows anyone to register names within it.

In between the `reveal` and `ready` steps, the namespace creator will have a
"lock" on the namespace that lasts for about 1 year.  During this time period,
the namespace creator can `import` names.  The `import` transaction lets the
namespace creator assign the name a zone file and an owner in one step.

## Before Trying This in Production...



### Setting up the Test Environment

In this example, we will use the test framework to create a private Bitcoin
blockchain on your computer, and then create a Blockstack namespace on it.
This will let you experiment with different namespace parameters
without spending actual BTC.  The test framework uses `bitcoind -regtest`,
so all of the commands you'll run here will work identically on
mainnet.

To install the test framework, please follow these
[instructions](https://github.com/blockstack/blockstack-core/tree/master/integration_tests).
Once you have the test framework installed, you should run the `namespace_check` test in `--interactive-web` mode.
This will create an empty `.test` namespace and leave the test scenario running
once it finishes.  You will be able to fund addresses and create new blocks via
your Web browser or via `curl`, as will be explained below.  Also, you'll be able to use the
`blockstack` utility to interact with your private blockchain and namespaces.

The test setup command is as follows.  This will launch the `namespace_check`
test scenario, and open a web server on port 3001.
```bash
    $ blockstack-test-scenario --interactive-web 3001 blockstack_integration_tests.scenarios.namespace_check
```

When the test is ready for us to experiment, you should see the following:

```bash
    An empty namespace called 'test' has been created
    Feel free to experiment with other namespaces

    Available keys with a balance:
    *  6e50431b955fe73f079469b24f06480aee44e4519282686433195b3c4b5336ef01
    *  c244642ce0b4eb68da8e098facfcad889e3063c36a68b7951fb4c085de49df1b01
    *  f4c3907cb5769c28ff603c145db7fc39d7d26f69f726f8a7f995a40d3897bb5201
    *  8f87d1ea26d03259371675ea3bd31231b67c5df0012c205c154764a124f5b8fe01
    *  bb68eda988e768132bc6c7ca73a87fb9b0918e9a38d3618b74099be25f7cab7d01
    *  2,3,6f432642c087c2d12749284d841b02421259c4e8178f25b91542c026ae6ced6d01,65268e6267b14eb52dc1ccc500dc2624a6e37d0a98280f3275413eacb1d2915d01,cdabc10f1ff3410082448b708c0f860a948197d55fb612cb328d7a5cc07a6c8a01
    *  2,3,4c3ab2a0704dfd9fdc319cff2c3629b72ebda1580316c7fddf9fad1baa323e9601,75c9f091aa4f0b1544a59e0fce274fb1ac29d7f7e1cd020b66f941e5d260617b01,d62af1329e541871b244c4a3c69459e8666c40b683ffdcb504aa4adc6a559a7701
    *  2,3,4b396393ca030b21bc44a5eba1bb557d04be1bfe974cbebc7a2c82b4bdfba14101,d81d4ef8123852403123d416b0b4fb25bcf9fa80e12aadbc08ffde8c8084a88001,d0482fbe39abd9d9d5c7b21bb5baadb4d50188b684218429f3171da9de206bb201
    *  2,3,836dc3ac46fbe2bcd379d36b977969e5b6ef4127e111f2d3e2e7fb6f0ff1612e01,1528cb864588a6a5d77eda548fe81efc44180982e180ecf4c812c6be9788c76a01,9955cfdac199b8451ccd63ec5377a93df852dc97ea01afc47db7f870a402ff0501
```

You can determine that the test framework is live by going to
`http://localhost:3001` in your Web browser.  From there, you can generate
blocks in the test framework's `bitcoind` node and you can fund any address in
the test framework.

Finally, you can use the `blockstack-test-env` command to set up your shell
environment variables so `blockstack` will interact with this test (instead of
mainnet).  To do so, run the following in your shell:

```bash
    $ . $(which blockstack-test-env) namespace_check
    |blockstack-test namespace_check| $
```

You can verify that the environment variables by verifying that your `$PS1`
variable includes the name of your test (as shown above), and that some other
`BLOCKSTACK_`-prefixed variables are set:

```bash
    |blockstack-test namespace_check| $ env | grep BLOCKSTACK
    BLOCKSTACK_OLD_PS1=\u@\h:\w$
    BLOCKSTACK_TESTNET=1
    BLOCKSTACK_EPOCH_1_END_BLOCK=1
    BLOCKSTACK_EPOCH_2_END_BLOCK=2
    BLOCKSTACK_TEST=1
    BLOCKSTACK_DEBUG=1
    BLOCKSTACK_CLIENT_CONFIG=/tmp/blockstack-run-scenario.blockstack_integration_tests.scenarios.namespace_check/client/client.ini
```

## Registering a Namespace

Suppose we're going to create the `hello` namespace.  The key
`6e50431b955fe73f079469b24f06480aee44e4519282686433195b3c4b5336ef01` will be the key that
*pays* for the namespace.  The key
`c244642ce0b4eb68da8e098facfcad889e3063c36a68b7951fb4c085de49df1b01` will be the key that
*creates* the namespace.  The creator key will be used to `import` names and
declare the namespace `ready`.  The payment key will be used to both pay for the
namespace and receive name registration and renewal fees for the first year of
the namespace's lifetime.

In this example, we will set these keys as environment variables:

```bash
    |blockstack-test namespace_check| $ export PAYMENT_PKEY="6e50431b955fe73f079469b24f06480aee44e4519282686433195b3c4b5336ef01"
    |blockstack-test namespace_check| $ export CREATOR_PKEY="c244642ce0b4eb68da8e098facfcad889e3063c36a68b7951fb4c085de49df1b01"
```

#### Multisig Namespace Payment

If you want to use a multisig address to pay for your namespace (and collect
name registration fees), then instead of using
`6e50431b955fe73f079469b24f06480aee44e4519282686433195b3c4b5336ef01`, you should
use a string formatted as `m,n,pk1,pk2,...,pk_n`.  `m` is the number of
signatures required, `n` is the number of private keys, and `pk1,pk2,...,pk_n`
are the private keys.

For example, you can use the following as your `PAYMENT_PKEY` to have a 2-of-3
multisig script pay for your namespace and collect name registration fees:

```bash
    |blockstack-test namespace_check| $ export PAYMENT_PKEY="2,3,6f432642c087c2d12749284d841b02421259c4e8178f25b91542c026ae6ced6d01,65268e6267b14eb52dc1ccc500dc2624a6e37d0a98280f3275413eacb1d2915d01,cdabc10f1ff3410082448b708c0f860a948197d55fb612cb328d7a5cc07a6c8a01"
```

### Namespace preorder

The command to preorder the namespace would be:

```bash
    |blockstack-test namespace_check| $ blockstack namespace_preorder hello "$PAYMENT_PKEY" "$CREATOR_PKEY"
```

You will be given a set of instructions on how to proceed to reveal and
launch the namespace.  _READ THEM CAREFULLY_.  You will be prompted to
explicitly acknowledge that you understand the main points of the instructions,
and that you understand the risks.

The command outputs some necessary information at the very end of its execution.
In particular, you will need to remember the transaction ID of the namespace
preorder.  The command will help you do so.

Here is a sample output:

```bash
    |blockstack-test namespace_check| $ blockstack namespace_preorder hello "$PAYMENT_PKEY" "$CREATOR_PKEY"

    <...snip...>

    Remember this transaction ID: b40dd1375ef63e5a40ee60d790ec6dccd06efcbac99d0cd5f3b07502a4ab05ac
    You will need it for `blockstack namespace_reveal`

    Wait until b40dd1375ef63e5a40ee60d790ec6dccd06efcbac99d0cd5f3b07502a4ab05ac has six (6) confirmations.  Then, you can reveal `hello` with:

        $ blockstack namespace_reveal "hello" "6e50431b955fe73f079469b24f06480aee44e4519282686433195b3c4b5336ef01" "c244642ce0b4eb68da8e098facfcad889e3063c36a68b7951fb4c085de49df1b01" "b40dd1375ef63e5a40ee60d790ec6dccd06efcbac99d0cd5f3b07502a4ab05ac"

    {
        "status": true,
        "success": true,
        "transaction_hash": "b40dd1375ef63e5a40ee60d790ec6dccd06efcbac99d0cd5f3b07502a4ab05ac"
    }
```

If all goes well, you will get back a transaction hash (in this case, `b40dd1375ef63e5a40ee60d790ec6dccd06efcbac99d0cd5f3b07502a4ab05ac`).
To get Blockstack to process it, you will need to mine some blocks in the test framework (by default,
Blockstack will only accept a transaction that has 6 confirmations).  To do
this, simply go to `http://localhost:3001` and generate at least 6 blocks.  If you
observe the test log, you will see the Blockstack node process and accept it.

Note that when you do this live, you should wait for
at least 10 confirmations before sending the `reveal` transaction, just to be
safe.

### Namespace reveal

The command to reveal a preordered namespace is more complicated, since it
describes the price curve.

This command is **interactive**.  The command to invoke it is as follows:

```bash
    |blockstack-test namespace_check| $ blockstack namespace_reveal hello "$PAYMENT_PKEY" "$CREATOR_PKEY" "b40dd1375ef63e5a40ee60d790ec6dccd06efcbac99d0cd5f3b07502a4ab05ac"
```

When running the command, you will see the namespace creation wizard prompt you
with the price curve and the current values:

```
Name lifetimes (blocks): infinite
Price coefficient:       4
Price base:              4
Price bucket exponents:  [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
Non-alpha discount:      2
No-vowel discount:       5
Burn or receive fees?    Receive to mr6nrMvvh44sR5MiX929mMXP5hqgaTr6fx

Name price formula:
(UNIT_COST = 10.0 satoshi):
                                     buckets[min(len(name)-1, 15)]
             UNIT_COST * coeff * base
cost(name) = -----------------------------------------------------
                   max(nonalpha_discount, no_vowel_discount)


Name price table:
| length | price       | price, nonalpha | price, no vowel | price, both |
--------------------------------------------------------------------------
|      1 | 42949672960 |      8589934592 |      8589934592 |  8589934592 |
|      2 | 10737418240 |      5368709120 |      2147483648 |  2147483648 |
|      3 |  2684354560 |      1342177280 |       536870912 |   536870912 |
|      4 |   671088640 |       335544320 |       134217728 |   134217728 |
|      5 |   167772160 |        83886080 |        33554432 |    33554432 |
|      6 |    41943040 |        20971520 |         8388608 |     8388608 |
|      7 |    10485760 |         5242880 |         2097152 |     2097152 |
|      8 |     2621440 |         1310720 |          524288 |      524288 |
|      9 |      655360 |          327680 |          131072 |      131072 |
|     10 |      163840 |           81920 |           32768 |       32768 |
|     11 |       40960 |           20480 |            8192 |        8192 |
|     12 |       10240 |            5120 |            2048 |        2048 |
|     13 |        2560 |            1280 |             512 |         512 |
|     14 |         640 |             320 |             128 |         128 |
|     15 |         160 |              80 |              32 |          32 |
|    16+ |          40 |              20 |              10 |          10 |


What would you like to do?
(0) Set name lifetime in blocks             (positive integer between 1 and 4294967295, or "infinite")
(1) Set price coefficient                   (positive integer between 1 and 255)
(2) Set base price                          (positive integer between 1 and 255)
(3) Set price bucket exponents              (16 comma-separated integers, each between 1 and 15)
(4) Set non-alphanumeric character discount (positive integer between 1 and 15)
(5) Set no-vowel discount                   (positive integer between 1 and 15)
(6) Toggle collecting name fees             (True: receive fees; False: burn fees)
(7) Show name price formula
(8) Show price table
(9) Done

(1-9)
```

All prices are in the "fundamental unit" of the underlying blockchain (i.e.
satoshis).

As the formula describes, the name's price is a function of:

* a fixed unit cost (`UNIT_COST`)
* a multiplicative constant coefficient (`coeff`)
* a fixed exponential base (`base`)
* a 16-element list of price buckets, indexed by the length of the name (`buckets`)
* a discount for having non-alphnumeric letters (`nonalpha_discount`)
* a discount for having no vowels in the name (`no_vowel_discount`)

You can use options 1 through 8 to play with the pricing function and examine
the name costs in the price table.  Enter 9 to send the transaction itself.

Once you're happy, you can issue the namespace-reveal transaction.  As with the
namespace-preorder transaction, you will get back a transaction hash, and your transaction will be
unconfirmed.  Simply go to `http://localhost:3001` to generate some more blocks
to confirm your namespace-reveal.

Once you have confirmed your namespace-reveal transaction, you can
begin to populate your namespace with some initial names.

**Collecting Name Fees**

Blockstack 0.17 introduced the ability to create a namespace such that for the
first year of its existence (54595 blocks), all name registration and renewal
fees will be sent to the address of the _payment key_.  In this example,
this is the address `mr6nrMvvh44sR5MiX929mMXP5hqgaTr6fx`.

The alternative is to
have all namespace fees sent to an unspendable burn address
(`1111111111111111111114oLvT2`).  This is the case for the `.id` namespace,
for example.

After the year has passed, all future name registrations and renewal fees
will be sent to the unspendable burn address.  This is to disincentivize
namespace squatters.

**Warnings**

* You must issue this command **within 144 blocks** of the namespace-preorder transaction.  Otherwise, the preorder will expire and you will need to start over from scratch.

### Importing names

After sending the `reveal` transaction, you can populate your namespace with
some initial names.  You can do so with the `name_import` command.

Suppose we want to import the name `example.hello` and assign it to an owner
whose public key address is `ms6Y32bcL5zhA57e8tf7awgVZuPxV8Xg8N`.  Suppose also
that you wanted to give `example.hello` an initial zone file stored at
`/var/blockstack/zone_files/example.hello`.  To do so, you would issue the
following command:

```bash
    |blockstack-test namespace_check| $ blockstack name_import example.hello ms6Y32bcL5zhA57e8tf7awgVZuPxV8Xg8N /var/blockstack/zone_files/example.hello "$CREATOR_PKEY"
```

By default, you **must** use the private key you used to reveal the namespace
to import names (this is `$CREATOR_PKEY` in this example).

As with namespace-preorder and namespace-reveal, the transaction this command
generates will be unconfirmed.  Simply go to `http://localhost:3001` to generate
some blocks to confirm it.

You can check the progress of the transaction with `blockstack info`, as follows:

```bash
    |blockstack-test namespace_check| $ blockstack info
    {
        "cli_version": "0.17.0.8",
        "consensus_hash": "b10fdd38a20a7e46555ce3a7f68cf95c",
        "last_block_processed": 694,
        "last_block_seen": 694,
        "queues": {
            "name_import": [
                {
                    "confirmations": 1,
                    "name": "example.hello",
                    "tx_hash": "10f7dcd9d6963ef5d20d010f731d5d2ddb76163a083b9d7a2b9fd4515c7fe58c"
                }
            ]
        },
        "server_alive": true,
        "server_host": "localhost",
        "server_port": 16264,
        "server_version": "0.17.0.8"
    }
```

The `confirmation` field indicates how deep in the blockchain the transaction is
at the time.  Generating more blocks will increase its number of confirmations.

When you do this live,
**YOU SHOULD LEAVE YOUR COMPUTER RUNNING UNTIL THE `name_import` QUEUE IS EMPTY**.
Blockstack's background API daemon will monitor the transactions and upload the
name's zone file to the Blockstack Atlas network once it is confirmed.
But to do so, your computer must remain online.  If you do not do this, then
the name will not have a zone file and will be unusable in the higher layers of
Blockstack-powered software (including Blockstack applications).  However,
if your computer does go offline or reboots, you can recover by
restarting the Blockstack API daemon (with
`blockstack api start`).  The daemon itself will pick up where it left off, and
replicate all zone files that have confirmed transactions.

After the zone file is uploaded, the name will be public and resolvable.  You can re-import the
same name over and over, and give it a different address and/or zone file.  Like
all other names, the Blockstack Atlas network will accept and propagate zone
files for imported names.

The owner of the address `ms6Y32bcL5zhA57e8tf7awgVZuPxV8Xg8N` will **not** be
able to issue any transactions for the name `example.hello` until the namespace
creator has sent the `ready` transaction.

#### Using multiple private keys for NAME_IMPORT

Bitcoin itself imposes limits on how fast you can send transactions from the
same key (limited by a maximum UTXO-chain length).  To work around this,
Blockstack lets you import names by using up to 300 private keys.  The private
keys you can use are BIP32 unhardened children of the namespace reveal key (i.e.
`$CREATOR_PKEY` in this example).

The first name you import **must** use the namespace reveal private key
(`$CREATOR_PKEY` in this example).  However, all future names you import in this
namespace can use one of the 300 BIP32 keys.

To get the list of keys you can use, you can use the `make_import_keys` command:

```bash
    |blockstack-test namespace_check| $ blockstack make_import_keys example hello "$CREATOR_PKEY"
    aeda50305ada40aaf53f2d8921aa717f1ec71a0a3b9b4c6397b3877f6d45c46501 (n4DVTuLLv5J1Yc17AoRYY1GtxDAuLGAESr)
    92ff179901819a1ec7d32997ce3bb0d9a913895d5850cc05146722847128549201 (mib2KNBGR4az8GiUmusBZexVBqb9YB2gm5)
    cc5b6a454e2b614bfa18f4deb9a8e179ab985634d63b7fedfaa59573472d209b01 (mxE2iqV4jdpn4K349Gy424TvZp6MPqSXve)
    9b0265e0ac8c3c24fe1d79a734b3661ec2b5c0c2619bb6342356572b8235910101 (n4rGz8hkXTscUGWCwZvahrkEh6LHZVQUoa)
    e2585af250404b7918cf6c91c6fa67f3401c0d1ae66df2fafa8fa132f4b9350f01 (moGNpEpighqc6FnkqyNVJA9xtfTiStr5YU)
    {
        "status": true
    }
```

(NOTE: in the test environment, you get only 5 keys in order to save time).

You can use any of these keys to import names.

#### Trying it out

Here's an example walkthrough of how to try this out in the test framework:

1. Import the first name, creating a zone file in the process:

```bash
    |blockstack-test namespace_check| $ cat > /var/blockstack/zone_files/example.hello <<EOF
    > $ORIGIN example.hello
    > $TTL 3600
    > _file URI 10 1 "file:///home/blockstack-test/example.hello"
    > EOF
    |blockstack-test namespace_check| $ blockstack name_import example.hello ms6Y32bcL5zhA57e8tf7awgVZuPxV8Xg8N /var/blockstack/zone_files/example.hello "$CREATOR_PKEY"
    Import cost breakdown:
    {
        "name_import_tx_fee": {
            "btc": 0.0003342,
            "satoshis": 33420
        },
        "total_estimated_cost": {
            "btc": 0.0003342,
            "satoshis": 33420
        },
        "total_tx_fees": 33420
    }
    Importing name 'example.hello' to be owned by 'ms6Y32bcL5zhA57e8tf7awgVZuPxV8Xg8N' with zone file hash '05c302430f4ed0a24470abf9df7e264d517fd389'
    Proceed? (y/N) y
    {
        "status": true,
        "success": true,
        "transaction_hash": "bd875f00f63bcb718bb22782c88c3edcbed79663f2f9152deab328c48746f103",
        "value_hash": "05c302430f4ed0a24470abf9df7e264d517fd389"
    }
```

2. Advance the test framework blockchain, so the indexer knows which import keys to expect:

```bash
    # NOTE: you can also do this by going to http://localhost:3001 in your Web browser
    |blockstack-test namespace_check| $ curl -X POST http://localhost:3001/nextblock
```

3. Make import keys:

```bash
    |blockstack-test namespace_check| $ blocksatck make_import_keys hello "$CREATOR_PKEY"
    aeda50305ada40aaf53f2d8921aa717f1ec71a0a3b9b4c6397b3877f6d45c46501 (n4DVTuLLv5J1Yc17AoRYY1GtxDAuLGAESr)
    92ff179901819a1ec7d32997ce3bb0d9a913895d5850cc05146722847128549201 (mib2KNBGR4az8GiUmusBZexVBqb9YB2gm5)
    cc5b6a454e2b614bfa18f4deb9a8e179ab985634d63b7fedfaa59573472d209b01 (mxE2iqV4jdpn4K349Gy424TvZp6MPqSXve)
    9b0265e0ac8c3c24fe1d79a734b3661ec2b5c0c2619bb6342356572b8235910101 (n4rGz8hkXTscUGWCwZvahrkEh6LHZVQUoa)
    e2585af250404b7918cf6c91c6fa67f3401c0d1ae66df2fafa8fa132f4b9350f01 (moGNpEpighqc6FnkqyNVJA9xtfTiStr5YU)
    {
        "status": true
    }
```

4. Fill up one of the addresses in the test framework, so we can fund `NAME_IMPORT` transactions with it:

```bash
    # NOTE: you can also do this by going to http://localhost:3001 in your Web browser
    |blockstack-test namespace_check| $ curl -X POST -F 'addr=n4DVTuLLv5J1Yc17AoRYY1GtxDAuLGAESr' -F 'value=100000000' 'http://localhost:3001/sendfunds'
```

5. Import another name, with the child private key we just funded:

```bash
    |blockstack-test namespace_check| $ cat > /tmp/example.hello.zonefile <<EOF
    > $ORIGIN example2.hello
    > $TTL 3600
    > _file URI 10 1 "file:///home/blockstack-test/example2.hello"
    > EOF
    |blockstack-test namespace_check| $ blockstack name_import example2.hello n3sFkNfBQPWS25G12DqDEqHRPiqHotAkEb /tmp/example.hello.zonefile aeda50305ada40aaf53f2d8921aa717f1ec71a0a3b9b4c6397b3877f6d45c46501
    Import cost breakdown:
    {
        "name_import_tx_fee": {
            "btc": 0.0003342,
            "satoshis": 33420
        },
        "total_estimated_cost": {
            "btc": 0.0003342,
            "satoshis": 33420
        },
        "total_tx_fees": 33420
    }
    Importing name 'example2.hello' to be owned by 'n3sFkNfBQPWS25G12DqDEqHRPiqHotAkEb' with zone file hash '0649bc0b457f54c564d054ce20dc3745a0c4f0c0'
    Proceed? (y/N) y
    {
        "status": true,
        "success": true,
        "transaction_hash": "496a6c2aaccedd98a8403c2e61ff3bdeff221a58bf0e9c362fcae981353f459f",
        "value_hash": "0649bc0b457f54c564d054ce20dc3745a0c4f0c0"
    }
```

6. Advance the blockchain again:

```bash
    # NOTE: you can also do this by going to http://localhost:3001 in your Web browser
    |blockstack-test namespace_check| $ curl -X POST http://localhost:3001/nextblock
```

7. See that the names are processing:

```bash
    |blockstack-test namespace_check| $ blockstack info
    {
        "cli_version": "0.17.0.8",
        "consensus_hash": "2a055beeaedcaa1365ab2671a0254a03",
        "last_block_processed": 711,
        "last_block_seen": 711,
        "queues": {
            "name_import": [
                {
                    "confirmations": 2,
                    "name": "example.hello",
                    "tx_hash": "bd875f00f63bcb718bb22782c88c3edcbed79663f2f9152deab328c48746f103",
                },
                {
                    "confirmations": 1,
                    "name": "example2.hello",
                    "tx_hash": "496a6c2aaccedd98a8403c2e61ff3bdeff221a58bf0e9c362fcae981353f459f"
                }
            ]
        },
        "server_alive": true,
        "server_host": "localhost",
        "server_port": 16264,
        "server_version": "0.17.0.8"
    }
```

8. Confirm all the transactions:

```bash
    # NOTE: you can also do this by going to http://localhost:3001 in your Web browser
    |blockstack-test namespace_check| $ for i in $(seq 1 10); do curl -X POST http://localhost:3001/nextblock
```

9. Look up name zone files to confirm they were replicated to the test framework's Atlas network:

```bash
    |blockstack-test namespace_check| $ blockstack info
    {
        "cli_version": "0.17.0.8",
        "consensus_hash": "ad247c1d5ff239a65db0736951078f17",
        "last_block_processed": 721,
        "last_block_seen": 721,
        "queues": {},
        "server_alive": true,
        "server_host": "localhost",
        "server_port": 16264,
        "server_version": "0.17.0.8"
    }
    |blockstack-test namespace_check| $ blockstack get_name_zonefile example.hello
    $ORIGIN example.hello
    $TTL 3600
    _file URI 10 1 "file:///home/blockstack-test/example.hello"

    |blockstack-test namespace_check| $ blockstack get_name_zonefile example2.hello
    $ORIGIN example2.hello
    $TTL 3600
    _file URI 10 1 "file:///home/blockstack-test/example2.hello"
```

Now, these names are imported and once the `NAMESPACE_READY` transaction is
sent, the name owners can proceed to issue name operations.

**Warnings**

* The first private key you use must be the same one you used to *create* the namespace (`$CREATOR_KEY`).
* You may only use the 300 private keys described above to import names.
* You must complete all `NAME_IMPORT` transactions within 52595 blocks of the `NAMESPACE_REVEAL` transaction (about 1 year).

### Launching a Namespace

Once you have pre-populated your namespace with all of the initial names, you
have to make it `ready` so anyone can register a name.  If you do not do this
within 1 year of the `reveal` transaction, then your namespace and all of the
names will disappear, and someone else will be able to register it.

To make a namespace `ready`, you use the creator private key as follows:

```bash
     |blockstack-test namespace_check| $ blockstack namespace_ready hello "$CREATOR_PKEY"
```

**Warnings**

* You must send the `NAMESPACE_READY` transaction within 52595 blocks (about 1 year) of the `NAMESPACE_REVEAL` transaction.
