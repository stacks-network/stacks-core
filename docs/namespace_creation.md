# Creating a Namespace

**WARNING**:  If you intend to create a namespace, you must read this document
_in its entirety_.  You should also _install the test framework_ and experiment
with your namespace's parameters.  _FAILURE TO DO SO MAY RESULT IN IRRECOVERABLE
LOSS OF FUNDS._

Creating a namespace is a three-step process.  The first
step is to `preorder` the namespace, which broadcasts a salted hash of the
namespace ID.  The second step is to `reveal` the namespace, which exposes the
namespace ID and price function to the blockchain.  The final step is to `ready`
the namespace, which allows anyone to register names within it.

In between the `reveal` and `ready` steps, the namespace creator will have a
"lock" on the namespace that lasts for about 1 year.  During this time period,
the namespace creator can `import` names.  The `import` transaction lets the
namespace creator assign the name a zone file and an owner in one step.

## Before Trying This...

Creating namespaces is expensive (hundreds to millions of USD)
Be sure to test your namespace in our [integration test
framework](https://github.com/blockstack/blockstack-core/tree/master/integration_tests)
first!  It will let you simulate any valid namespace configuration
you want at no risk to you.

## Registering a Namespace

Suppose we're going to create the `hello` namespace.  The key
`L1EujLf4S4YXPhDUXwguMDiEjBVME2Tphs9H7qXz6DkwUpD1wf2P` will be the key that
*pays* for the namespace.  The key
`KxspG5n8JPqCHWuNdpvsfRayzc1X7FM675zsdmyhWAwpEtpj29cX` will be the key that
*creates* the namespace.  The creator's key will be used to `import` names and
declare the namespace `ready`.

In this example, we will set these keys as environment variables:

```
    $ export PAYMENT_PKEY="77f76847dfb75cb3b32fa515b2d51bcf548aa0d2761ff3b2ca4d379aec2ea53e01"
    $ export CREATOR_PKEY="31709f43493c6c750e3ea969624aad1983907ea0a038aad9e1aff60acd0676b301"
```

### Namespace preorder

The command to preorder the namespace would be:

```
    $ blockstack namespace_preorder hello "$PAYMENT_PKEY" "$CREATOR_PKEY"
```

You will be given a set of instructions on how to proceed to reveal and
launch the namespace.  _READ THEM CAREFULLY_.  You will be prompted to
explicitly acknowledge that you understand the main points of the instructions,
and that you understand the risks.

If all goes well, you will get back a transaction hash.  You should wait for the
transaction to be confirmed (~10 confirmations) before sending the `reveal`
transaction.

The command outputs some necessary information at the very end of its execution.
In particular, you will need to remember the transaction ID of the namespace
preorder.  The command will help you do so.

Here is a sample output:

```
    $ blockstack namespace_preorder hello "$PAYMENT_PKEY" "$CREATOR_PKEY"

    <...snip...>

    Remember this transaction ID: b40dd1375ef63e5a40ee60d790ec6dccd06efcbac99d0cd5f3b07502a4ab05ac
    You will need it for `blockstack namespace_reveal`

    Wait until b40dd1375ef63e5a40ee60d790ec6dccd06efcbac99d0cd5f3b07502a4ab05ac has six (6) confirmations.  Then, you can reveal `hello` with:

        $ blockstack namespace_reveal "hello" "77f76847dfb75cb3b32fa515b2d51bcf548aa0d2761ff3b2ca4d379aec2ea53e01" "31709f43493c6c750e3ea969624aad1983907ea0a038aad9e1aff60acd0676b301" "b40dd1375ef63e5a40ee60d790ec6dccd06efcbac99d0cd5f3b07502a4ab05ac"

    {
        "status": true,
        "success": true,
        "transaction_hash": "b40dd1375ef63e5a40ee60d790ec6dccd06efcbac99d0cd5f3b07502a4ab05ac"
    }
    $
```

### Namespace reveal

The command to reveal a preordered namespace is more complicated, since it
describes the price curve.

This command is **interactive**.  The command to invoke it is as follows:

```
    $ blockstack namespace_reveal hello "$PAYMENT_PKEY" "$CREATOR_PKEY" "b40dd1375ef63e5a40ee60d790ec6dccd06efcbac99d0cd5f3b07502a4ab05ac"
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
Burn or receive fees?    Receive to 1PJg2vkxRBJSJDugkcidDmdavs1eXZ6vTv

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

Once you're happy, you can begin to populate your namespace with some initial names.

**Collecting Name Fees**

Blockstack 0.17 introduced the ability to create a namespace such that for the
first year of its existence (54595 blocks), all name registration and renewal
fees will be sent to the address of the _payment key_.  In this example,
this is the address `1PJg2vkxRBJSJDugkcidDmdavs1eXZ6vTv`.

The alternative is to
have all namespace fees sent to an unspendable burn address
(`1111111111111111111114oLvT2`).  This is the case for the `.id` namespace,
for example.

After the year has passed, all future name registrations and renewal fees
will be sent to the unspendable burn address.  This is to disincentivize
namespace squatters.

### Importing names

After sending the `reveal` transaction, you can populate your namespace with
some initial names.  You can do so with the `name_import` command.

Suppose we want to import the name `example.hello` and assign it to an owner
whose public key address is `1CaajyWdX4ZSNxe2RKgjm2UAhuoFaMSTxg`.  Suppose also
that you wanted to give `example.hello` an initial zone file stored at
`/var/blockstack/zone_files/example.hello`.  To do so, you would issue the
following command:

```
    $ blockstack name_import example.hello 1CaajyWdX4ZSNxe2RKgjm2UAhuoFaMSTxg /var/blockstack/zone_files/example.hello "$CREATOR_PKEY"
```

Once a name is imported, it is public and resolvable.  You can re-import the
same name over and over, and give it a different address and/or zone file.  Like
all other names, the Blockstack Atlas network will accept and propagate zone
files for imported names.

The owner of the address `1CaajyWdX4ZSNxe2RKgjm2UAhuoFaMSTxg` will **not** be
able to issue any transactions for the name `example.hello` until the namespace
creator has sent the `ready` transaction.

#### Scaling Imports

The namespace creator is able to import many names in parallel by using BIP32
unhardened children.  The keys `$CREATOR_PKEY / 0` through
`$CREATOR_PKEY / 299` can be used to import names.  However, the **first**
`name_import` **must** use the `$CREATOR_PKEY`, since its associated public key
will be used by the other Blockstack nodes to generate the list of valid public keys from which a valid
`name_import` may originate.

### Launching a Namespace

Once you have pre-populated your namespace with all of the initial names, you
have to make it `ready` so anyone can register a name.  If you do not do this
within 1 year of the `reveal` transaction, then your namespace and all of the
names will disappear, and someone else will be able to register it.

To make a namespace `ready`, you use the creator private key as follows:

```
     $ blockstack namespace_ready hello "$CREATOR_PKEY"
```

