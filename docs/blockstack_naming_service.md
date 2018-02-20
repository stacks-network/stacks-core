# Blockstack Naming Service

This document is written for Blockstack developers and technically-inclined
users.  Its purpose is twofold: to give a brief overview of how the 
Blockstack Naming Service works, and describe how developers can use it
to build decentralized Web applications.

If you read this document in its entirety, you will
understand the following concepts:

* Why a secure decentralized naming service is an important building
  block in decentralized systems
* How Blockstack applications can leverage BNS to solve real-world problems
* How the Blockstack Naming Service is different from other offerings in this
  space.

# Introduction

The Blockstack Naming Service (BNS) is a network system that binds names
to a (small) amount of state without relying on any central points of control.
It does so by embedding a log of its control-plane messages within a public blockchain, like Bitcoin.


Each BNS peer determines the state of each name by indexing these specially-crafted
transactions.  In doing so, each peer independently calculates the same global
name state.

Names in BNS have three properties:

* **Names are globally unique.**  The protocol does not allow name collisions, and all
  well-behaved nodes resolve a given name to the same state.
* **Names are human-meaningful.**  Each name is chosen by its creator.
* **Names are strongly-owned.**  Only the name's owner can change the state it
  resolves to.

[Blockstack Core](https://github.com/blockstack/blockstack-core) is the reference
implementation of the Blockstack Naming Service.

# Motivation

We rely on naming systems in everyday life, and they play a critical
role in many different applications.  For example, when you look up a
friend on social media, you are using the platform's naming service to resolve
their name to their profile.  When you look up a website, you are using the
Domain Name Service to
resolve the hostname to its host's IP address.  When you check out a Git branch, you
are using your Git client to resolve the branch name to a commit hash.
When you look up someone's PGP key on a keyserver, you are resolving
their key ID to their public key.

What kinds of things do we want to be true about names?  In BNS, names are
globally unique, names are human-meaningful, and names are strongly-owned.
However, if you look at these examples, you'll see that each of them only
guarantees *two* of these properties.  This limits how useful they can be.

* In DNS and social media, names are globally unique and human-readable, but not
strongly-owned.  The system operator has the
final say as to what each names resolves to.
   * **Problem**:  Clients must trust the system to make the right
     choice in what a given name resolves to.  This includes trusting that
     no one but the system administrators can make these changes.

* In Git, branch names are human-meaningful
and strongly-owned, but not globally unique.  Two different Git nodes may resolve the same
branch name to different unrelated repository states.
   * **Problem**:  Since names can refer to conflicting state, developers
     have to figure out some other mechanism to resolve ambiguities.  In Git's
     case, the user has to manually intervene.

* In PGP, names are key IDs.  They are
are globally unique and cryptographically owned, but not human-readable.  PGP
key IDs are derived from the keys they reference.
   * **Problem**:  These names are difficult for most users to
     remember since they do not carry semantic information relating to their use in the system.

BNS names have all three properties, and none of these problems.  This makes it a
powerful tool for building all kinds of network applications.  With BNS, we
can do the following and more:

* Build domain name services where hostnames can't be hijacked.
* Build social media platforms where user names can't be stolen by phishers.
* Build version control systems where repository branches do not conflict.
* Build public-key infrastructure where it's easy for users to discover and
  remember each other's keys.

# How to Use BNS

A BNS node implements a replicated name database.  Each BNS node keeps itself
synchronized to all of the other ones in the world, so queries on one BNS node
will be the same on other nodes.

BNS nodes extract name information from an underlying blockchain (Blockstack
Core currently uses Bitcoin, and had used Namecoin in the past).
BNS uses the blockchain to establish a shared "ground truth" for the system:  as long as
two nodes have the same view of the blockchain, then they will build up the same
database.

The biggest consequence for developers is that in BNS, reading name state is
fast and cheap but writing name state is slow and expensive.  This is because
registering and updating names requires one or more transactions to be sent to
the underlying blockchain, and BNS nodes will not process them until they are
sufficiently confirmed.  Users and developers need to acquire and spend
the requisite cryptocurrency (i.e. Bitcoin) to send BNS transactions.

## BNS Clients

Developers interact with BNS by resolving names, registering names, and managing
names.  Resolving names is done with a RESTful API call, and can be done with 
vanilla `curl` or `wget`.  Registering and
managing names require generating and sending blockchain transactions, which
requires specialized software.

To register and manage names, you will need a BNS client.  We provide two
options:

* The [Blockstack Browser](https://github.com/blockstack/blockstack-browser) gives users
and developers a graphical UI to resolve, register and manage names.  This is the recommended
way to interact with BNS.
* The [Blockstack CLI](https://blockstack.org/docs/#lookups) gives developers low-level
control over resolving, registering, and managing names.
A new CLI that uses [blockstack.js](https://github.com/blockstack/blockstack.js)
is under development, and will replace the existing CLI program.

We recommend that new developers use the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser).

Developers who want to make their own client programs that do not use 
the reference client library code should read the
[BNS transaction wire format](wire-format.md) document for generating and
sending their own transactions.

The examples in this document focus on resolving names using `curl`.  We refer
the reader to client-specific documentation for registering and managing names.

## BNS Node Architecture

There are two parts to a BNS node that developers should be aware of.  They are:

* **The BNS indexer**.  This module crawls the blockchain and builds
  up its name database.  BNS indexers do not contain any private or sensitive
state, and can be deployed publicly.  We maintain a fleet of them at
`https://node.blockstack.org:6263` for developers to use to get started.

* **The BNS API**  This module gives
  developers a *stable RESTful API* for interacting with the BNS network.
We provide one for developers to experiment with at `https://core.blockstack.org`.

An architectural schematic appears below.

```
                        +----------------+             +--------------------+
+--------+  RESTful API |                | private API |                    |
| client |<------------>| BNS API module |<----------->| BNS indexer module |
+--------+              |                |             |                    |
                        +----------------+             | +----------------+ |
                                                       | | name database  | |
                                                       | +----------------+ |
                                                       +--------------------+
                                                                 ^
 Figure 1: BNS node architecture overview.                       |
 Clients talk to the BNS API module.  The                        |
 API module talks to the indexer module.                         v
 The indexer module reads the blochchain via           +--------------------+
 a blockchain peer, over the blockchain's              |   blockchain peer  |
 peer network.                                         +--------------------+
```

BNS clients and applications should use the BNS API module.  They should not attempt
to talk to a BNS indexer directly, because its API is not stable and is not meant
for consumption by any other process except for the API daemon.

Blockstack Core currently implements the API module and indexer module as separate daemons
(`blockstack api` and `blockstack-core`, respectively).  However, this is an
implementation detail, and may change in the future.

## BNS Namespaces

BNS names are organized hierarchically.  Names are grouped
in **namespaces**, which function like top-level domains in DNS.  All BNS names
belong to exactly one namespace.

Namespaces control a few properties about the names within them:
* How expensive they are to register
* How long they last before they have to be renewed
* Who (if anyone) receives the name registration fees
* Who is allowed to seed the namespace with its initial names.

At the time of this writing, by far the largest BNS namespace is the `.id`
namespace.  Names in the `.id` namespace are meant for resolving user
identities.  Short names in `.id` are more expensive than long names, and have
to be renewed by their owners every two years.  Name registration fees are not
paid to anyone in particular---they are instead sent to a "black hole" where they are
rendered unspendable (the intention is to discourage ID sqautters).

Unlike DNS, *anyone* can create a namespace and set its properties.
Namespaces are created on a first-come first-serve basis, and once created, they
last forever.

The intention is that each application can create its own BNS
namespace for its own purposes.  Applications can use namespaces for things like:

* Giving users a SSO system, where each user registers their public key under a
  username.  Blockstack applications do this with names in the `.id` namespace,
for example.
* Providing a subscription service, where each name is a 3rd party that provides
a service for users to subscribe to.  For example, names in
`.podcast` point to podcasts that users of the 
[DotPodcast](https://dotpodcast.co) app can subscribe to.
* Implementing software licenses, where each name corresponds to an access key.
  Unlike conventional access keys, access keys implemented as names
can be sold and traded independently.  The licensing fee (paid as a name
registration) would be set by the developer and sent to a developer-controlled
blockchain address.

Developers wanting to create their own namespaces should read the [namespace
creation](namespace-creation.md) document.

Developers can query individual namespaces and look up names within them using
the BNS API.  The API offers routes to do the following: 

#### List all namespaces in existence ([reference](https://core.blockstack.org/#namespace-operations-get-all-namespaces)).

```bash
$ curl https://core.blockstack.org/v1/namespaces
[                                                                                                                                                                                                                                                                                                                             
  "id", 
  "helloworld", 
  "podcast"
]
```
     
#### List all names within a namespace ([reference](https://core.blockstack.org/#namespace-operations-get-all-namespaces))

```bash
$ curl https://core.blockstack.org/v1/namespaces/id/names?page=0
[
  "0.id",
  "0000.id",
  "000000.id",
  "000001.id",
  "00000111111.id",
  "000002.id",
  "000007.id",
  "0011sro.id",
  "007_007.id",
  "00n3w5.id",
  "00r4zr.id",
  "00w1k1.id",
  "0101010.id",
  "01jack.id",
  "06nenglish.id",
  "08.id",
  "0cool_f.id",
  "0dadj1an.id",
  "0nelove.id",
  "0nename.id"
...
]
```

Each page returns a batch of 100 names.

## Resolving BNS Names

Each BNS node maintains a name database table with three columns:
all the names that have been registered, each name's public key hash,
and each name's small amount of state.  In addition, each BNS node maintains the *transaction
history* for each name.  A developer can not only resolve a name to its
*current* state, but also to *any previous state at a given point in time.*

Below is an example name table pulled from a live BNS node:

| Name | Public key hash | Name State |
|------|-----------------|--------------|
| `ryan.id` | `15BcxePn59Y6mYD2fRLCLCaaHScefqW2No` | `a455954b3e38685e487efa41480beeb315f4ec65` |
| `muneeb.id` | `1J3PUxY5uDShUnHRrMyU6yKtoHEUPhKULs` | `37aecf837c6ae9bdc9dbd98a268f263dacd00361` |
| `jude.id` | `16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg` | `b6e99200125e70d634b17fe61ce55b09881bfafd` |
| `verified.podcast` | `1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH` | `6701ce856620d4f2f57cd23b166089759ef6eabd` |
| `cicero.res_publica.id` | `1EtE77Aa5AA8etzF2irk56vvkS4v7rZ7PE` | `7e4ac75f9d79ba9d5d284fac19617497433b832d` |
| `podsaveamerica.verified.podcast` | `1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH` | `0d6f090db8945aa0e60759f9c866b17645893a95` |

The value of the `Name State` column is written to the blockchain, and its
contents can be arbitrary.  However, the exact amount of state that can be written
is constrained by the underlying blockchain.  For example, the reference implementation
limits it to 20 bytes.

Since the `Name State` field size is so constrained, in practice it gets used to
store the cryptographic hash of some off-chain data.
This allows the off-chain data can be hosted anywhere, since its authenticity
and integrity are determined using the hash in the (trusted) BNS node.

This use-case is so common that the reference implementation explicitly
uses  the `Name State` field to store the hash of a
[DNS zone file](https://en.wikipedia.org/wiki/Zone_file), which contains
URLs that point to the name owner's Blockstack application data.
BNS nodes eagerly replicate zone files they discover to one another via the
[Atlas Network](atlas-network.md), so BNS name lookups will often resolve both
to their on-chain state and their off-chain zone file data.

Developers can query this table via the BNS API.  The API offers routes
to do the following:

#### Look up a name's public key and name state ([reference](https://core.blockstack.org/#name-querying-get-name-info))

```bash
$ curl https://core.blockstack.org/v1/names/muneeb.id
{
  "address": "1J3PUxY5uDShUnHRrMyU6yKtoHEUPhKULs",
  "blockchain": "bitcoin", 
  "expire_block": 599266, 
  "last_txid": "7e16e8688ca0413a398bbaf16ad4b10d3c9439555fc140f58e5ab4e50793c476", 
  "status": "registered", 
  "zonefile": "$ORIGIN muneeb.id\n$TTL 3600\n_http._tcp URI 10 1 \"https://gaia.blockstack.org/hub/1J3PUxY5uDShUnHRrMyU6yKtoHEUPhKULs/0/profile.json\"\n", 
  "zonefile_hash": "37aecf837c6ae9bdc9dbd98a268f263dacd00361"
}
```

Note that the API uses the `zonefile_hash` field to serve the `Name State` data.
Also note that the `zonefile` field is given with the off-chain data that hashes
to the `zonefile_hash` field.

#### List all names the node knows about ([reference](https://core.blockstack.org/#name-querying-get-all-names))

```bash
$ curl https://core.blockstack.org/v1/names?page=0
[
  "judecn.id",
  "3.id",
  "4.id",
  "8.id",
  "e.id",
  "h.id",
  "5.id",
  "9.id",
  "i.id",
  "l.id",
  "p.id",
  "w.id",
  "ba.id",
  "df.id",
...
]
```

Each page returns 100 names.

#### Look up the history of states a name was in ([reference](https://core.blockstack.org/#name-querying-name-history))

```bash
$ curl https://core.blockstack.org/v1/names/patrickstanley.id/history
{
  "445838": [
    {
      "address": "1occgbip7tFDXX9MvzQhcnTUUjcVX2dYK",
      "block_number": 445838,
      "burn_address": "1111111111111111111114oLvT2",
      "consensus_hash": "7b696b6f4060b792d41912068944d73b",
      "op": "?",
      "op_fee": 25000,
      "opcode": "NAME_PREORDER",
      "preorder_hash": "26bf7874706ac761afdd403ed6b3b9578fb01a34",
      "sender": "76a91408d0dd44c1f0a3a4f0957ae95901929d7d66d55788ac",
      "sender_pubkey": "039a8948d339ecbff44cf426cb85d90fce876f1658d385cdc47f007f279be626ea",
      "txid": "6730ae09574d5935ffabe3dd63a9341ea54fafae62fde36c27738e9ee9c4e889",
      "vtxindex": 40
    }
  ],
  "445851": [
    {
      "address": "17CbHgTgBG3kLedXNneEKBkCTgW2fyrnUD",
      "block_number": 445838,
      "consensus_hash": null,
      "first_registered": 445851,
      "importer": null,
      "importer_address": null,
      "last_creation_op": "?",
      "last_renewed": 445851,
      "name": "patrickstanley.id",
      "name_hash128": "683a3e1ee5f0296833c56e481cf41b77",
      "namespace_block_number": 373601,
      "namespace_id": "id",
      "op": ":",
      "op_fee": 25000,
      "opcode": "NAME_REGISTRATION",
      "preorder_block_number": 445838,
      "preorder_hash": "26bf7874706ac761afdd403ed6b3b9578fb01a34",
      "revoked": false,
      "sender": "76a9144401f3be5311585ea519c1cb471a8dc7b02fd6ee88ac",
      "sender_pubkey": "039a8948d339ecbff44cf426cb85d90fce876f1658d385cdc47f007f279be626ea",
      "transfer_send_block_id": null,
      "txid": "55b8b42fc3e3d23cbc0f07d38edae6a451dfc512b770fd7903725f9e465b2925",
      "value_hash": null,
      "vtxindex": 54
    }
  ],
  "445873": [
    {
      "address": "17CbHgTgBG3kLedXNneEKBkCTgW2fyrnUD",
      "block_number": 445838,
      "consensus_hash": "18b8d69f0182b89ccb1aa536f83be18a",
      "first_registered": 445851,
      "importer": null,
      "importer_address": null,
      "last_creation_op": "?",
      "last_renewed": 445851,
      "name": "patrickstanley.id",
      "name_hash128": "683a3e1ee5f0296833c56e481cf41b77",
      "namespace_block_number": 373601,
      "namespace_id": "id",
      "op": "+",
      "op_fee": 25000,
      "opcode": "NAME_UPDATE",
      "preorder_block_number": 445838,
      "preorder_hash": "26bf7874706ac761afdd403ed6b3b9578fb01a34",
      "revoked": false,
      "sender": "76a9144401f3be5311585ea519c1cb471a8dc7b02fd6ee88ac",
      "sender_pubkey": "039a8948d339ecbff44cf426cb85d90fce876f1658d385cdc47f007f279be626ea",
      "transfer_send_block_id": null,
      "txid": "dc478659fc684a1a6e1e09901971e82de11f4dfe2b32a656700bf9a3b6030719",
      "value_hash": "02af0ef21161ad06b0923106f40b994b9e4c1614",
      "vtxindex": 95
    }
  ],
  "445884": [
    {
      "address": "1GZqrVbamkaE6YNveJFWK6cDrCy6bXyS6b",
      "block_number": 445838,
      "consensus_hash": "18b8d69f0182b89ccb1aa536f83be18a",
      "first_registered": 445851,
      "importer": null,
      "importer_address": null,
      "last_creation_op": "?",
      "last_renewed": 445851,
      "name": "patrickstanley.id",
      "name_hash128": "683a3e1ee5f0296833c56e481cf41b77",
      "namespace_block_number": 373601,
      "namespace_id": "id",
      "op": ">>",
      "op_fee": 25000,
      "opcode": "NAME_TRANSFER",
      "preorder_block_number": 445838,
      "preorder_hash": "26bf7874706ac761afdd403ed6b3b9578fb01a34",
      "revoked": false,
      "sender": "76a914aabffa6dd90d731d3a349f009323bb312483c15088ac",
      "sender_pubkey": null,
      "transfer_send_block_id": 445875,
      "txid": "7a0a3bb7d39b89c3638abc369c85b5c028d0a55d7804ba1953ff19b0125f3c24",
      "value_hash": "02af0ef21161ad06b0923106f40b994b9e4c1614",
      "vtxindex": 16
    }
  ]
}
```

All of the above information is extracted from the blockchain.  Each top-level
field encodes the states the name transitioned to at the given block height (e.g.
445838, 445851, 445873, adn 445884).  At each block height, the name's states
are returned in the order they were discovered in the blockchain.

Each name state contains a lot of ancillary data that is used internally by
other API calls and client libraries.  The relevant fields for this document's
scope are:

* `address`: This is the base58check-encoded public key hash.
* `name`:  This is the name queried.
* `value_hash`:  This is the `Name State` value.  The term `value_hash` is used
  as an allusion to the overwhelmingly-common use-case of using this field to
store the hash of some off-chain data.
* `opcode`:  This is the type of transaction that was processed.
* `txid`:  This is the transaction ID in the underlying blockchain.

#### Look up the list of names owned by a given public key hash ([reference](https://core.blockstack.org/#name-querying-get-names-owned-by-address))

```bash
$ curl https://core.blockstack.org/v1/addresses/bitcoin/16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg
{
  "names": [
    "judecn.id",
    "patrickstanley1.id",
    "abcdefgh123456.id",
    "duckduckgo_tor.id",
    "jude.id",
    "blockstacknewyear2017.id",
    "jude.statism.id"
  ]
}
```

Note that this API endpoint includes names and [subdomains](subdomains).

## Registering BNS Names

Anyone can register a name in BNS, but only the name's owner can change its
public key hash or its name state.  Internally, BNS does this by encoding
these operations as transactions in its underlying blockchain.

Because BNS is implemented on top of a blockchain, registering names costs money
in the form of transaction fees and registration fees.  All blockchains require
a transaction fee in order to process and store a transaction, so no matter
what we do, name registration cannot be free of charge.  However, this is a good
thing, since it prevents spammers from both filling up the blockchain with
garbage data and in turn prevents spammers from filling up BNS name databases with junk.

In addition to the transaction fee, BNS imposes a *registration fee*.  Not all
names are created equal---some names are more desirable than others.  BNS
uses the registration fee to ensure that more desirable names cost more, so they
are less likely to be squatted.  In addition, the registration fee is an
incentive mechanism for developers to create and curate namespaces
for their apps.

The act of registering a name will insert a new row into each BNS node's name
table.  This ensures that every BNS node in the world will discover and add
the new name to their databases when they processes the name's
transactions.  However, this also means that registering a name can take
minutes or hours, depending on how fast the underlying blockchain is able to
confirm transactions.

Names are registered on a first-come first-serve basis, thereby ensuring that they are
globally unique.  Any unclaimed, well-formed name can be registered.  See the
[Implementation Notes](implementation-notes) for specific rules about what characters and lengths
are permitted.

Registration happens through a BNS client, such as the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser). 

## Managing BNS Names

Only a name's owner can update a name's public key hash and name state.
This is enforced by ensuring that each name operation is signed by the name's
private key.

BNS supports several operations for managing names:

* **Updating a name.**  A name owner can change the name state's value to any
  20-byte string they want.
* **Transferring a name.**  A name owner can change the name's public key hash,
  thereby giving it a new owner.  The current owner has the option of atomically
clearing its name state value in the act of transferring it.
* **Renewing a name.**  Not all names last forever, depending on which
  namespace it lives in.  If a name does not last for ever, it
must be periodically renewed.  When renewing a name, the owner has the option to
atomically update and transfer it as well.
* **Revoking a name.**  A name owner can kill a name, such that it will no
  longer resolve and can no longer be updated, transferred, or renewed.  If the
name can expire, it will eventually be available again to be registered.

Each of these operations can be thought of as executing `UPDATE/SET/WHERE`
SQL commands on the BNS node's name table.
Each name operation is implemented as a single blockchain transaction.

Performing a name operation happens through a BNS client, such as the
[Blockstack Browser](https://github.com/blockstack/blockstack-browser).

## BNS Subdomains

BNS names are strongly-owned because the owner of its private key can generate
valid transactions that update its state and owner.  However, this comes at the
cost of requiring a name owner to pay for the underlying transaction in the
blockchain.  Moreover, this approach limits the rate of BNS name registrations
and operations to the underlying blockchain's transaction bandwidth.

BNS overcomes this with subdomains.  A **BNS subdomain** is a type of BNS name whose state
and owner are stored outside of the blockchain, but whose existence and
operation history are anchored to the
blockchain.  In the example table in the [Resolving BNS
Names](resolving-bns-names) section, the names `cicero.res_publica.id` and
`podsaveamerica.verified.podcast` are subdomains.

Like their on-chain counterparts, subdomains are globally
unique, strongly-owned, and human-readable.  BNS gives them their own name state
and public keys.

Unlike on-chain names, subdomains can be created and managed
cheaply, because they are broadcast to the
BNS network in batches.  A single blockchain transaction can send up to 120
subdomain operations.

This is achieved by storing subdomain records in the [Atlas Network](atlas-network.md).
An on-chain name owner broadcasts subdomain operations by encoding them as
`TXT` records within a DNS zone file.
To broadcast the zone file, the owner sets the name's state value to be 
the hash of a zone file.  It then uses Atlas to replicate the zone file,
and thus all of the subdomain operations.  This anchors the set of operations to
an on-chain transaction, so other nodes who receive and process the zone file
and its subdomain operations can prove that the zone file is legitimate.

For example, the name `verified.podcast` once wrote the name state value `247121450ca0e9af45e85a82e61cd525cd7ba023`,
which is the hash of the following zone file:

```bash
$ curl -sL https://core.blockstack.org/v1/names/verified.podcast/zonefile/247121450ca0e9af45e85a82e61cd525cd7ba023 | jq -r '.zonefile'
$ORIGIN verified.podcast
$TTL 3600
1yeardaily TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAxeWVhcmRhaWx5CiRUVEwgMzYwMApfaHR0cC5fdGNwIFVSSSAxMCAxICJodHRwczovL3BoLmRvdHBvZGNhc3QuY28vMXllYXJkYWlseS9oZWFkLmpzb24iCg=="
2dopequeens TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAyZG9wZXF1ZWVucwokVFRMIDM2MDAKX2h0dHAuX3RjcCBVUkkgMTAgMSAiaHR0cHM6Ly9waC5kb3Rwb2RjYXN0LmNvLzJkb3BlcXVlZW5zL2hlYWQuanNvbiIK"
10happier TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAxMGhhcHBpZXIKJFRUTCAzNjAwCl9odHRwLl90Y3AgVVJJIDEwIDEgImh0dHBzOi8vcGguZG90cG9kY2FzdC5jby8xMGhhcHBpZXIvaGVhZC5qc29uIgo="
31thoughts TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAzMXRob3VnaHRzCiRUVEwgMzYwMApfaHR0cC5fdGNwIFVSSSAxMCAxICJodHRwczovL3BoLmRvdHBvZGNhc3QuY28vMzF0aG91Z2h0cy9oZWFkLmpzb24iCg=="
359 TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAzNTkKJFRUTCAzNjAwCl9odHRwLl90Y3AgVVJJIDEwIDEgImh0dHBzOi8vcGguZG90cG9kY2FzdC5jby8zNTkvaGVhZC5qc29uIgo="
30for30 TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAzMGZvcjMwCiRUVEwgMzYwMApfaHR0cC5fdGNwIFVSSSAxMCAxICJodHRwczovL3BoLmRvdHBvZGNhc3QuY28vMzBmb3IzMC9oZWFkLmpzb24iCg=="
onea TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiBvbmVhCiRUVEwgMzYwMApfaHR0cC5fdGNwIFVSSSAxMCAxICJodHRwczovL3BoLmRvdHBvZGNhc3QuY28vb25lYS9oZWFkLmpzb24iCg=="
10minuteteacher TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAxMG1pbnV0ZXRlYWNoZXIKJFRUTCAzNjAwCl9odHRwLl90Y3AgVVJJIDEwIDEgImh0dHBzOi8vcGguZG90cG9kY2FzdC5jby8xMG1pbnV0ZXRlYWNoZXIvaGVhZC5qc29uIgo="
36questionsthepodcastmusical TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAzNnF1ZXN0aW9uc3RoZXBvZGNhc3RtdXNpY2FsCiRUVEwgMzYwMApfaHR0cC5fdGNwIFVSSSAxMCAxICJodHRwczovL3BoLmRvdHBvZGNhc3QuY28vMzZxdWVzdGlvbnN0aGVwb2RjYXN0bXVzaWNhbC9oZWFkLmpzb24iCg=="
_http._tcp URI 10 1 "https://dotpodcast.co/"
```

Each `TXT` record in this zone file encodes a subdomain-creation.
For example, `1yeardaily.verified.podcast` resolves to:

```bash
$ curl https://core.blockstack.org/v1/names/1yeardaily.verified.podcast
{
  "address": "1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH",
  "blockchain": "bitcoin",
  "last_txid": "d87a22ebab3455b7399bfef8a41791935f94bc97aee55967edd5a87f22cce339",
  "status": "registered_subdomain",
  "zonefile_hash": "e7acc97fd42c48ed94fd4d41f674eddbee5557e3",
  "zonefile_txt": "$ORIGIN 1yeardaily\n$TTL 3600\n_http._tcp URI 10 1 \"https://ph.dotpodcast.co/1yeardaily/head.json\"\n"
}
```

This information was extracted from the `1yeardaily` `TXT` resource record in the zone
file for `verified.podcast`.

### Subdomain Lifecycle

Note that `1yeardaily.verified.podcast` has a different public key
hash (address) than `verified.podcast`.  A BNS node will only process a
subsequent subdomain operation on `1yeardaily.verified.podcast` if it includes a
signature from this address's private key.  `verified.podcast` cannot generate
updates; only the owner of `1yeardaily.verified.podcast can do so`.

The lifecycle of a subdomain and its operations is shown in Figure 2.

```
   subdomain                  subdomain                  subdomain
   creation                   update                     transfer
+----------------+         +----------------+         +----------------+
| cicero         |         | cicero         |         | cicero         |
| addr="1Et..."  | signed  | addr="1Et..."  | signed  | addr="1cJ..."  |
| state="7e4..." |<--------| state="111..." |<--------| state="111..." |<---- ...
| sequence=0     |         | sequence=1     |         | sequence=2     |
|                |         | sig="xxxx"     |         | sig="xxxx"     |
+----------------+         +----------------+         +----------------+
        |                          |                          |
        |        off-chain         |                          |
~ ~ ~ ~ | ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~|~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ | ~ ~ ~ ~ ~ ~ ~ ...
        |         on-chain         |                          |
        V                          V                          V
+----------------+         +----------------+         +----------------+
| res_publica.id |         |    jude.id     |         | res_publica.id |
|  NAME_UPDATE   |<--------|  NAME_UPDATE   |<--------|  NAME_UPDATE   |<---- ...
+----------------+         +----------------+         +----------------+
   blockchain                 blockchain                 blockchain
   block                      block                      block


Figure 2:  Subdomain lifetime with respect to on-chain name operations.  A new
subdomain operation will only be accepted if it has a later "sequence=" number,
and a valid signature in "sig=" over the transaction body.  The "sig=" field 
includes both the public key and signature, and the public key must hash to
the previous subdomain operation's "addr=" field.

Thesubdomain-creation and subdomain-transfer transactions for
"cicero.res_publica.id" are broadcast by the owner of "res_publica.id".
However, any on-chain name ("jude.id" in this case) can broadcast a subdomain
update for "cicero.res_publica.id".
```

Subdomain operations are ordered by sequence number, starting at 0.  Each new
subdomain operation must include:

* The next sequence number
* The public key that hashes to the previous subdomain transaction's address
* A signature from the corresponding private key over the entire subdomain
  operation.

If two correctly-signed but conflicting subdomain operations are discovered
(i.e. they have the same sequence number), the one that occurs earlier in the
blockchain's history is accepted.  Invalid subdomain operations are ignored.

Combined, this ensures that a BNS node with all of the zone files with a given
subdomain's operations will be able to determine the valid sequence of
state-transitions it has undergone, and determine the current state and public
key hash for the subdomain.

### Resolving Subdomains

Developers interact with subdomains the same way they interact with names.
Using the BNS API, a developer can:

#### Look up a subdomain's public key and name state ([reference](https://core.blockstack.org/#name-querying-get-name-info))

```bash
$ curl https://core.blockstack.org/v1/names/aaron.personal.id
{
  "address": "1PwztPFd1s2STMv4Ntq6UPBdYgHSBr5pdF",
  "blockchain": "bitcoin",
  "last_txid": "85e8273b0a38d3e9f0af7b4b72faf0907de9f4616afc101caac13e7bbc832394",
  "status": "registered_subdomain",
  "zonefile_hash": "a6dda6b74ffecf85f4a162627d8df59577243813",
  "zonefile_txt": "$ORIGIN aaron.personal.id\n$TTL 3600\n_https._tcp URI 10 1 \"https://gaia.blockstack.org/hub/1PwztPFd1s2STMv4Ntq6UPBdYgHSBr5pdF/profile.json\"\n"
}
```

Note that `zonefile_hash` refers to the 20-byte name state that each name in BNS
gets.  The API endpoint helpfully returns an associated zone file, if one exists
that hashes to the value of `zonefile_hash`.

#### Look up a subdomain's transaction history ([reference](https://core.blockstack.org/#name-querying-name-history))

```bash
$ curl https://core.blockstack.org/v1/names/aaron.personal.id/history
{
  "509981": [
    {
      "address": "1PwztPFd1s2STMv4Ntq6UPBdYgHSBr5pdF",
      "block_number": 509981,
      "domain": "personal.id",
      "name": "aaron.personal.id",
      "sequence": 0,
      "txid": "85e8273b0a38d3e9f0af7b4b72faf0907de9f4616afc101caac13e7bbc832394",
      "value_hash": "a6dda6b74ffecf85f4a162627d8df59577243813",
      "zonefile": "JE9SSUdJTiBhYXJvbi5wZXJzb25hbC5pZAokVFRMIDM2MDAKX2h0dHBzLl90Y3AgVVJJIDEwIDEgImh0dHBzOi8vZ2FpYS5ibG9ja3N0YWNrLm9yZy9odWIvMVB3enRQRmQxczJTVE12NE50cTZVUEJkWWdIU0JyNXBkRi9wcm9maWxlLmpzb24iCg=="
    }
  ]
}
```

#### Look up the list of names and subdomains owned by a given public key hash ([reference](https://core.blockstack.org/#name-querying-get-names-owned-by-address))

```bash
$ curl https://core.blockstack.org/v1/addresses/bitcoin/1PwztPFd1s2STMv4Ntq6UPBdYgHSBr5pdF
{
  "names": [
    "aaron.personal.id"
  ]
}
```

### Subdomain Creation and Management

Unlike an on-chain name, a subdomain owner needs an on-chain name owner's help
to broadcast their subdomain operations.  In particular:
* A subdomain-creation transaction can only be processed by the owner of the on-chain
name that shares its suffix.  For example, only the owner of `res_publica.id`
can broadcast subdomain-creation transactions for subdomain names ending in
`.res_publica.id`.
* A subdomain-transfer transaction can only be broadcast by the owner of the
on-chain name that created it.  For example, the owner of
`cicero.res_publica.id` needs the owner of `res_publica.id` to broadcast a
subdomain-transfer transaction to change `cicero.res_publica.id`'s public key.
* In order to send a subdomain-creation or subdomain-transfer, all
  of an on-chain name owner's name state values must be zone file hashes,
  and all zone files must be available in the Atlas network.  This lets the BNS
node prove the *absence* of any conflicting subdomain-creation and
subdomain-transfer operations when processing new zone files.
* A subdomain update transaction can be broadcast by *any* on-chain name owner,
  but the subdomain owner needs to find one who will cooperate.  For example,
the owner of `verified.podcast` can broadcast a subdomain-update transaction
created by the owner of `cicero.res_publica.id`.

That said, to create a subdomain, the subdomain owner generates a
subdomain-creation operation for their desired name
and gives it to the on-chain name owner.
The on-chain name owner then uses Atlas to
broadcast it to all other BNS nodes.

Once created, a subdomain owner can use any on-chain name owner to broadcast a
subdomain-update operation.  To do so, they generate and sign the requisite
subdomain operation and give it to an on-chain name owner, who then packages it
with other subdomain operations into a DNS zone file
and sends them all out on the Atlas network.

If the subdomain owner wants to change the address of their subdomain, they need
to sign a subdomain-transfer operation and give it to the on-chain name owner
who created the subdomain.  They then package it into a zone file and broadcast
it.

### Subdomain Registrars

Because subdomain names are cheap, developers may be inclined to run
subdomain registrars on behalf of their applications.  For example, 
the name `personal.id` is used to register Blockstack application users without
requiring them to spend any Bitcoin.

We supply a reference
implementation of a [BNS Subdomain Registrar](https://github.com/blockstack/subdomain-registrar)
to help developers register and manage subdomains.

## Decentralized Identifiers (DIDs)

BNS nodes are compliant with the emerging
[Decentralized Identity Foundation](https://identity.foundation) protocol
specification for decentralized identifiers (DIDs).

Each name in BNS has an associated DID.  The DID format for BNS is:

```
    did:stack:v0:{address}-{index}
```

Where:
* `{address}` is an on-chain public key hash (e.g. a Bitcoin address).
* `{index}` refers to the `nth` name this address created.

For example, the DID for `personal.id` is
`did:stack:v0:1dARRtzHPAFRNE7Yup2Md9w18XEQAtLiV-0`, because the name
`personal.id` was the first-ever name created by
`1dARRtzHPAFRNE7Yup2Md9w18XEQAtLiV`.

As another example, the DID for `jude.id` is `did:stack:v0:16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg-1`.
Here, the address `16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg` had created one earlier
name in history prior to this one (which happens to be `abcdefgh123456.id`).

The purpose of a DID is to provide an eternal identifier for a public key.
The public key may change, but the DID will not.

Blockstack Core implements a DID method of its own
in order to be compatible with other systems that use DIDs for public key resolution.
In order for a DID to be resolvable, all of the following must be true for a
name:

* The name must exist
* The name's state value must be the hash of a DNS zone file
* The DNS zone file must be present in the BNS [Atlas Network](atlas-network.md)
* The DNS zone file must contain a `URI` resource record that points to a signed
  JSON Web Token
* The public key that signed the JSON Web Token (and is included with it) must
  hash to the address that owns the name

Not all names will have DIDs.  However, names created by the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser) will all have DIDs.

Developers can programmatically resolve DIDs via the Python API:

```Python
>>> import blockstack
>>> blockstack.lib.client.resolve_DID('did:stack:v0:16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg-1', hostport='https://node.blockstack.org:6263')
{'public_key': '020fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc8'}
```

A RESTful API is under development.

## Summary

BNS is a decentralized naming system that produces names that are
globally-unique, human-readable, and strongly-owned.  It does so by embedding a
database log within a public blockchain like Bitcoin, and replaying it locally
to calculate the state and owner of each name.  In doing so, a BNS node provides
a full replica of all of the network's state, which gives it the ability to
service queries like prior name states and name historys.

BNS groups names by namespaces in order to provide different ways to register
and use names, and furthermore implements subdomains to provide a cheap,
scalable way to register many names for the cost of a single blockchain
transaction.

[Blockstack Core](https://github.com/blockstack/blockstack-core) is the
reference implementation of BNS, and provides a public BNS node with online
documentation at https://core.blockstack.org.

## Appendix 1: Feature Comparison

BNS is not the only naming system in wide-spread use, nor is it the only
decentralized naming system that implements human-readable,
globally-unique, and strongly-owned names.  The following feature table
describes how BNS differs from other naming systems

| Feature                    | BNS | [ENS](https://ens.domains/) | DNS | [Namecoin](https://namecoin.org/) |
|----------------------------|-----|-----|-----|----------|
| Globally unique names      |  X  |  X  |  X  |    X     |
| Human-readable names       |  X  |  X  |  X  |    X     |
| Strongly-owned names       |  X  |  X  |     |    X     |
| Names are enumerable       |  X  |     |     |    X     |
| Registration times         | 1-2 hours | ~1 week | ~1 day | ~1 hour |
| Subdomain registration times | 1 hour (instant with [#750](https://github.com/blockstack/blockstack-core/issues/750)) | varies | instant | ~1 hour |
| Anyone can make a TLD/namespace | X  |     |     |      |
| TLD/Namespace owners get registration fees | X |   |   X  |   |
| Portable across blockchains | X  |     | N/A |   N/A    |
| Off-chain names            | X   |     | N/A  |         |
| Name provenance            | X   | X   |      |   X     |
| [DID](https://identity.foundation) support | X   |     |     |          |
| Turing-complete namespace rules |  | X  | X  |          |
| Miners are rewarded for participating  | [1] |    | N/A  |  X |

[1] Blockstack Core destroys the underlying blockchain token to pay for
registration fees when there is no pay-to-namespace-creator address set in the
name's namespace.  This has the effect of making the blockchain miners' holdings
slightly more valuable.

