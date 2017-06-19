# Creating a Namespace

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

Creating namespaces is expensive (thousands to millions of USD at the time of
this writing).  Be sure to test your namespace in our [integration test
framework](https://github.com/blockstack/blockstack-core/tree/master/integration_tests)
first!

## Registering a Namespace

Suppose we're going to create the `hello` namespace.  The key
`L1EujLf4S4YXPhDUXwguMDiEjBVME2Tphs9H7qXz6DkwUpD1wf2P` will be the key that
*pays* for the namespace.  The key
`KxspG5n8JPqCHWuNdpvsfRayzc1X7FM675zsdmyhWAwpEtpj29cX` will be the key that
*creates* the namespace.  The creator's key will be used to `import` names and
declare the namespace `ready`.

In this example, we will set these keys as environment variables:

```
    $ export PAYMENT_PKEY="L1EujLf4S4YXPhDUXwguMDiEjBVME2Tphs9H7qXz6DkwUpD1wf2P"
    $ export CREATOR_PKEY="KxspG5n8JPqCHWuNdpvsfRayzc1X7FM675zsdmyhWAwpEtpj29cX"
```

### Namespace preorder

The command to preorder the namespace would be:

```
    $ blockstack namespace_preorder hello "$PAYMENT_PKEY" "$CREATOR_PKEY"
```

If all goes well, you will get back a transaction hash.  You should wait for the
transaction to be confirmed (~10 confirmations) before sending the `reveal`
transaction.

### Namespace reveal

The command to reveal a preordered namespace is more complicated, since it
describes the price curve.

This command is **interactive**.  The command to invoke it is as follows:

```
    $ blockstack namespace_reveal hello "$PAYMENT_PKEY" "$CREATOR_PKEY"
```

When running the command, you will see the namespace creation wizard prompt you
with the price curve and the current values:

```
Namespace ID:           hello
Name lifetimes:         infinite
Price coefficient:      4
Price base:             4
Price bucket exponents: [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
Non-alpha discount:     2
No-vowel discount:      5

Name price formula:
(UNIT_COST = 100):
                                     buckets[min(len(name)-1, 15)]
             UNIT_COST * coeff * base                             
cost(name) = -----------------------------------------------------
                   max(nonalpha_discount, no_vowel_discount)      


Name price table:
| length | price        | price, nonalpha | price, no vowel | price, both |
---------------------------------------------------------------------------
|      1 | 429496729600 |     85899345920 |     85899345920 | 85899345920 |
|      2 | 107374182400 |     53687091200 |     21474836480 | 21474836480 |
|      3 |  26843545600 |     13421772800 |      5368709120 |  5368709120 |
|      4 |   6710886400 |      3355443200 |      1342177280 |  1342177280 |
|      5 |   1677721600 |       838860800 |       335544320 |   335544320 |
|      6 |    419430400 |       209715200 |        83886080 |    83886080 |
|      7 |    104857600 |        52428800 |        20971520 |    20971520 |
|      8 |     26214400 |        13107200 |         5242880 |     5242880 |
|      9 |      6553600 |         3276800 |         1310720 |     1310720 |
|     10 |      1638400 |          819200 |          327680 |      327680 |
|     11 |       409600 |          204800 |           81920 |       81920 |
|     12 |       102400 |           51200 |           20480 |       20480 |
|     13 |        25600 |           12800 |            5120 |        5120 |
|     14 |         6400 |            3200 |            1280 |        1280 |
|     15 |         1600 |             800 |             320 |         320 |
|    16+ |          400 |             200 |             100 |         100 |


What would you like to do?
(1) Set name lifetime in blocks             (positive integer between 1 and 4294967295, or "infinite")
(2) Set price coefficient                   (positive integer between 1 and 255)
(3) Set base price                          (positive integer between 1 and 255)
(4) Set price bucket exponents              (16 comma-separated integers, each between 1 and 15)
(5) Set non-alphanumeric character discount (positive integer between 1 and 15)
(6) Set no-vowel discount                   (positive integer between 1 and 15)
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
* a 16-element list of price buckets, indexed by the length of the name
  (`buckets`)
* a discount for having non-alphnumeric letters (`nonalpha_discount`)
* a discount for having no vowels in the name (`no_vowel_discount`)

You can use options 1 through 8 to play with the pricing function and examine
the name costs in the price table.  Enter 9 to send the transaction itself.

Once you're happy, you can begin to populate your namespace with some initial names.

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

