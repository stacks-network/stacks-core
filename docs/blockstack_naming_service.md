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

This project repository ([Blockstack Core](https://github.com/blockstack/blockstack-core))
is the reference implementation of the Blockstack Naming Service.

# Introduction

The Blockstack Naming Service (BNS) is a network system that binds names
to off-chain state without relying on any central points of control.
It does so by embedding a log of its control-plane messages within a public blockchain, like Bitcoin.

Each BNS peer determines the state of each name by indexing these specially-crafted
transactions.  In doing so, each peer independently calculates the same global
name state.

Names in BNS have three properties:

* **Names are globally unique.**  The protocol does not allow name collisions, and all
  well-behaved nodes resolve a given name to the same state.
* **Names are human-meaningful.**  Each name is chosen by its creator.
* **Names are strongly-owned.**  Only the name's owner can change the state it
  resolves to.  Specifically, a name is owned by one or more ECDSA private keys.

Internally, a BNS node implements a replicated name database.  Each BNS node keeps itself
synchronized to all of the other ones in the world, so queries on one BNS node
will be the same on other nodes.  BNS nodes allow a name's owner to bind 
up to 40Kb of off-chain state to their name, which will be replicated to all 
BNS nodes via the [Atlas network](atlas_network.md).

BNS nodes extract the name database log from an underlying blockchain (Blockstack
Core currently uses Bitcoin, and had used Namecoin in the past).
BNS uses the blockchain to establish a shared "ground truth" for the system:  as long as
two nodes have the same view of the blockchain, then they will build up the same
database.

The biggest consequence for developers is that in BNS, reading name state is
fast and cheap but writing name state is slow and expensive.  This is because
registering and modifying names requires one or more transactions to be sent to
the underlying blockchain, and BNS nodes will not process them until they are
sufficiently confirmed.  Users and developers need to acquire and spend
the requisite cryptocurrency (i.e. Bitcoin) to send BNS transactions.

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

# BNS Architecture

The BNS node is the heart of the system.  It is responsible for building up 
and replicating global name state.

There are three parts to BNS that developers should be aware of.  They are:

* **The BNS indexer**.  This module crawls the blockchain and builds
  up its name database.  BNS indexers do not contain any private or sensitive
state, and can be deployed publicly.  We maintain a fleet of them at
`https://node.blockstack.org:6263` for developers to use to get started.

* **The BNS API**.  This module gives
  developers a *stable RESTful API* for interacting with the BNS network.
We provide one for developers to experiment with at `https://core.blockstack.org`.

* **BNS clients**.  These communicate with the BNS API module in order to
  resolve names.  Internally, they generate and send transactions to register
and modify names.

The BNS indexer and BNS API comprise the **BNS node**.  An architectural schematic appears below.

```
                      +-------------------------------------------------------+
            RESTful   | +----------------+             +--------------------+ |
+--------+   API      | |                | private API |                    | |
| client |<------------>| BNS API module |<----------->| BNS indexer module | |
+--------+            | |                |             |                    | |
    |                 | +----------------+             | +----------------+ | |
    |                 |                                | | name database  | | |
    |                 |                                | +----------------+ | |
    |                 |                                +--------------------+ |
    |                 | BNS node                                 ^            |
    |                 +------------------------------------------|------------+
    |                                                            |
    |                                                            v
    |       blockchain transactions                    +--------------------+
    +------------------------------------------------->|   blockchain peer  |
                                                       +--------------------+

Figure 1: BNS architecture overview.  Clients talk to the BNS API module to
resolve names, and generate and send blockchain transactions to register and
modify names.   The API module talks to the indexer module and gives clients
a stable, Web-accessible interface for resolving names.  The indexer module reads
the blochchain via a blockchain peer, over the blockchain's peer network. 

Blockstack Core currently implements the API module and indexer module as separate
daemons (`blockstack api` and `blockstack-core`, respectively).  However, this
is an implementation detail, and may change in the future.
```

The BNS indexer implements the blockchain consensus rules and network protocols.
Its main responsibility is to build up and replicate all of the name state.  It does 
not have any public APIs of its own.

The BNS API modules allows users and developers to resolve names via a RESTful
interface.  Resolution can be done with vanilla `curl` or `wget`.
BNS applications should use the BNS API module for name resolution.
They should not attempt to talk to a BNS indexer directly, because its API is not stable and is not meant
for consumption by any other process except for the API module.

Registering and managing names require generating and sending blockchain
transactions, which requires running a BNS client.  We provide two reference
BNS clients:

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

# How to Use BNS

BNS names are organized into a global name hierarchy.  There are three different
layers in this hierarchy related to naming:

* **Namespaces**.  These are the top-level names in the hierarchy.  An analogy
  to BNS namespaces are DNS top-level domains.  Existing BNS namespaces include
`.id`, `.podcast`, and `.helloworld`.  All other names belong to exactly one
namespace.  Anyone can create a namespace, but in order for the namespace
to be persisted, it must be *launched* so that anyone can register names in it.
Namespaces are not owned by their creators.

* **BNS names**.  These are names whose records are stored directly on the
  blockchain.  The ownership and state of these names are controlled by sending
blockchain transactions.  Example names include `verified.podcast` and
`muneeb.id`.  Anyone can create a BNS name, as long as the namespace that
contains it exists already.  The state for BNS names is usually stored in the [Atlas
network](atlas_network.md).

* **BNS subdomains**.  These are names whose records are stored off-chain, 
but are collectively anchored to the blockchain.  The ownership and state for
these names lives within the [Atlas network](atlas_network.md).  While BNS
subdomains are owned by separate private keys, a BNS name owner must
broadcast their subdomain state.  Example subdomains include `jude.personal.id`
and `podsaveamerica.verified.podcast`.  Unlike BNS namespaces and names, the
state of BNS subdomains is *not* part of the blockchain consensus rules.

A feature comparison matrix summarizing the similarities and differences
between these name objects is presented below:

| Feature | **Namespaces** | **BNS names** | **BNS Subdomains** |
|---------|----------------|---------------|--------------------|
| Globally unique | X | X | X |
| Human-meaningful | X | X | X |
| Owned by a private key |  | X | X |
| Anyone can create | X | X | [1] |
| Owner can update |   | X  | [1] |
| State hosted on-chain | X | X |  |
| State hosted off-chain |  | X | X |
| Behavior controlled by consensus rules | X | X |  |
| May have an expiration date |  | X  |  |

[1] Requires the cooperation of a BNS name owner to broadcast its transactions

## BNS Namespaces

Namespaces are the top-level naming objects in BNS.
They control a few properties about the names within them:
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

However, creating a namespace is not free.  The namespace creator must *burn*
cryptocurrency to do so.  The shorter the namespace, the more cryptocurrency
must be burned (i.e. short namespaces are more valuable than long namespaces).
For example, it cost Blockstack PBC 40 BTC to create the `.id` namespace in
2015 (in transaction `5f00b8e609821edd6f3369ee4ee86e03ea34b890e242236cdb66ef6c9c6a1b281`).

Namespaces can be between 1 and 19 characters long, and are composed of the
characters `a-z`, `0-9`, `-`, and `_`.

### Creating a Namespace

There are four steps to creating a namespace:

1. **Send a `NAMESPACE_PREORDER` transaction** ([live example](https://www.blocktrail.com/BTC/tx/5f00b8e609821edd6f3369ee4ee86e03ea34b890e242236cdb66ef6c9c6a1b28)).
This is the first step.  This registers the *salted hash* of the namespace with BNS nodes, and burns the
requisite amount of cryptocurrency.  In addition, it proves to the
BNS nodes that user has honored the BNS consensus rules by including
a recent *consensus hash* in the transaction
(see the section on [BNS forks](#bns-forks) for details).

2. **Send a `NAMESPACE_REVEAL` transaction** ([live example](https://www.blocktrail.com/BTC/tx/ab54b1c1dd5332dc86b24ca2f88b8ca0068485edf0c322416d104c5b84133a32)).
This is the second step.  This reveals the salt and the namespace ID (pairing it with its
`NAMESPACE_PREORDER`), it reveals how long names last in this namespace before
they expire or must be renewed, and it sets a *price function* for the namespace
that determines how cheap or expensive names its will be.  The price function takes
a name in this namespace as input, and outputs the amount of cryptocurrency the
name will cost (i.e. by examining how long the name is, and whether or not it
has any vowels or non-alphabet characters).  The namespace creator 
has the option to collect name registration fees for the first year of the
namespace's existence by setting a *namespace creator address*.

3. **Seed the namespace with `NAME_IMPORT` transactions** ([live example](https://www.blocktrail.com/BTC/tx/c698ac4b4a61c90b2c93dababde867dea359f971e2efcf415c37c9a4d9c4f312)).
Once the namespace has been revealed, the user has the option to populate it with a set of
names.  Each imported name is given both an owner and some off-chain state.
This step is optional---namespace creators are not required to import names.

4. **Send a `NAMESPACE_READY` transaction** ([live example](https://www.blocktrail.com/BTC/tx/2bf9a97e3081886f96c4def36d99a677059fafdbd6bdb6d626c0608a1e286032)).
This is the final step of the process.  It *launches* the namespace, which makes it available to the
public.  Once a namespace is ready, anyone can register a name in it if they 
pay the appropriate amount of cryptocurrency (according to the price funtion
revealed in step 2).

The reason for the `NAMESPACE_PREORDER/NAMESPACE_REVEAL` pairing is to prevent
frontrunning.  The BNS consensus rules require a `NAMESPACE_REVEAL` to be
paired with a previous `NAMESPACE_PREORDER` sent within the past 24 hours.
If it did not do this, then a malicious actor could watch the blockchain network
and race a victim to claim a namespace.

Namespaces are created on a first-come first-serve basis.  If two people try to
create the same namespace, the one that successfully confirms both the
`NAMESPACE_PREORDER` and `NAMESPACE_REVEAL` wins.  The fee burned in the
`NAMESPACE_PREORDER` is spent either way.

Once the user issues the `NAMESPACE_PREORDER` and `NAMESPACE_REVEAL`, they have
1 year before they must send the `NAMESPACE_READY` transaction.  If they do not
do this, then the namespace they created disappears (along with all the names
they imported).

Developers wanting to create their own namespaces should read the [namespace
creation](namespace_creation.md) document.  It is highly recommended that
developers follow this tutorial closely, given the large amount of
cryptocurrency at stake.

### Using Namespaces

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

Names within a namespace can serve any purpose the developer wants.  The ability
to collect registration fees for 1 year after creating the namespace not only
gives developers the incentive to get users to participate in the app, but also
gives them a way to measure economic activity.

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

#### Get the Cost to Register a Namespace ([reference](https://core.blockstack.org/#price-checks-get-namespace-price))

```bash
$ curl https://core.blockstack.org/v1/prices/namespaces/test
{
  "satoshis": 40000000
}
```

If you want to register a namespace, please see the [namespace creation tutorial](namespace_creation.md).

#### Getting the Current Consensus Hash ([reference](https://core.blockstack.org/#blockchain-operations-get-consensus-hash))

```bash
$ curl -sL https://core.blockstack.org/v1/blockchains/bitcoin/consensus
{
  "consensus_hash": "98adf31989bd937576aa190cc9f5fa3a"
}
```

A recent consensus hash is required to create a `NAMESPACE_PREORDER` transaction.  The reference
BNS clients do this automatically.  See the [transaction format](wire-format.md)
document for details on how the consensus hash is used to construct the
transaction.

## Resolving BNS Names

BNS names are bound to both public keys and to about 40Kb of off-chain state.
The off-chain state is encoded as a [DNS zone file](https://en.wikipedia.org/wiki/Zone_file),
which contains routing information for discovering the user's Blockstack data
(such as their profile and app data, which are hosted in the [Gaia storage
system](https://github.com/blockstack/gaia)).

The blockchain is not used to store this information directly.  Instead, the
blockchain stores the *public key hash* and the *zone file hash*.  When
indexing the blockchain, each BNS node builds a database with
three columns:  all the on-chain BNS names that have been registered, each
name's public key hash, and each name's zone file's hash.
In addition, each BNS node maintains the *transaction history* of each name.
A developer can resolve a name to any configuration it was in at any prior
point in time.

Below is an example name table pulled from a live BNS node:

| Name | Public key hash | Zone File Hash |
|------|-----------------|--------------|
| `ryan.id` | `15BcxePn59Y6mYD2fRLCLCaaHScefqW2No` | `a455954b3e38685e487efa41480beeb315f4ec65` |
| `muneeb.id` | `1J3PUxY5uDShUnHRrMyU6yKtoHEUPhKULs` | `37aecf837c6ae9bdc9dbd98a268f263dacd00361` |
| `jude.id` | `16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg` | `b6e99200125e70d634b17fe61ce55b09881bfafd` |
| `verified.podcast` | `1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH` | `6701ce856620d4f2f57cd23b166089759ef6eabd` |
| `cicero.res_publica.id` | `1EtE77Aa5AA8etzF2irk56vvkS4v7rZ7PE` | `7e4ac75f9d79ba9d5d284fac19617497433b832d` |
| `podsaveamerica.verified.podcast` | `1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH` | `0d6f090db8945aa0e60759f9c866b17645893a95` |

In practice, the zone file hash is the `RIPEMD160` hash of the `SHA256` hash of
the zone file, and the public key is the `base58check`-encoded `RIPEMD160` hash
of the double-`SHA256` hash of the ECDSA public key (i.e. a Bitcoin address).

The BNS consensus rules ensure that
a BNS name can only be registered if it is not already taken, and that only the 
user who owns the name's private key can change its public key hash or zone file
hash.  This means that a name's public key and zone file can be stored anywhere,
since they can be authenticated using the hashes discovered by indexing the
blockchain under the BNS consensus rules.

BNS nodes implement a decentralized storage system for zone files called the
[Atlas network](atlas_network.md).  In this system, BNS nodes eagerly replicate
all the zone files they know about to one another, so that eventually every BNS
node has a full replica of all zone files.

The public keys for names are stored off-chain in [Gaia](https://github.com/blockstack/gaia).
The user controls where their public keys are hosted using the zone file
contents (if they are hosted online anywhere at all).

Developers can query this table via the BNS API.  The API offers routes
to do the following:

#### Look up a name's public key and zone file ([reference](https://core.blockstack.org/#name-querying-get-name-info))

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

Note that the `zonefile` field is given with the off-chain data that hashes
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

Each page returns 100 names.  While no specific ordering is mandated by the
protocol, the reference implementation orders names by their order of creation
in the blockchain.

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
445838, 445851, 445873, adn 445884).  At each block height, the name's zone file
hashes are returned in the order they were discovered in the blockchain.

Each name state contains a lot of ancillary data that is used internally by
other API calls and client libraries.  The relevant fields for this document's
scope are:

* `address`: This is the base58check-encoded public key hash.
* `name`:  This is the name queried.
* `value_hash`:  This is the zone file hash.
* `opcode`:  This is the type of transaction that was processed.
* `txid`:  This is the transaction ID in the underlying blockchain.

The name's *entire* history is returned.  This includes the history of the name
under its previous owner, if the name expired and was reregistered.

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

Note that this API endpoint includes names and
[subdomains](#bns-subdomains).

## Registering BNS Names

Registering a BNS name costs cryptocurrency.  This cost comes from two sources:

* **Transaction fees:** These are the fees imposed by the cost of storing the
  transaction data to the blockchain itself.  They are independent of BNS, since
all of the blockchain's users are competing to have their transactions included
in the next block.  The blockchain's miners receive the transaction fee.

* **Registration fees:** Each BNS namespace imposes an *additional* fee on how
  much a name costs.  The registration fee is sent to the namespace creator
during the first year that a namespace exists, and is sent to a burn address
afterwards.  The registration fee is different for each name and is
determined by the namespace itself, but can be queried in advance by the user.

Registering a name takes two transactions.  They are:

* **`NAME_PREORDER` transaction**:  This is the first transaction to be sent.
  It tells all BNS nodes the *salted hash* of the BNS name, and it pays the
registration fee to the namespace owner's designated address (or the burn
address).  In addition, it proves to the BNS nodes that the client knows about
the current state of the system by including a recent *consensus hash*
in the transaction (see the section on [BNS forks](#bns-forks) for details).

* **`NAME_REGISTRATION` transaction**:  This is the second transaction to be
  sent.  It reveals the salt and the name to all BNS nodes, and assigns the name
an initial public key hash and zone file hash

The reason this process takes two transactions is to prevent front-running.
The BNS consensus rules stipulate that a name can only be registered if its
matching preorder transaction was sent in the last 24 hours.  Because a name
must be preordered before it is registered, someone watching the blockchain's
peer network cannot race a victim to claim the name they were trying to
register (i.e. the attacker would have needed to send a `NAME_PREORDER`
transaction first, and would have had to have sent it no more than 24 hours
ago).

Registering a name on top of the Bitcoin blockchain takes 1-2 hours.  This is
because you need to wait for the `NAME_PREORDER` transaction to be sufficiently
confirmed before sending the `NAME_REGISTRATION` transaction.  The BNS nodes
only register the name once both transactions have at least 6 confirmations
(which itself usually takes about an hour).

Names are registered on a first-come first-serve basis.
If two different people try to register the same name at the same time, the
person who completes the two-step process *earliest* will receive the name.  The
other person's `NAME_REGISTRATION` transaction will be ignored, since it will
not be considered valid at this point.  The registration fee paid by the
`NAME_PREORDER` will be lost.  However, this situation is rare in practice---
as of early 2018, we only know of one confirmed instance in the system's 3+ years
of operation.

Fully-qualified names can be between 3 and 37 characters long, and consist of
the characters `a-z`, `0-9`, `+`, `-`, `_`, and `.`.  This is to prevent
[homograph attacks](https://en.wikipedia.org/wiki/IDN_homograph_attack).
`NAME_REGISTRATION` transactions that do not conform to this requirement will be
ignored.

#### Getting a Name's Registration Fee ([reference](https://core.blockstack.org/#price-checks-get-name-price))

```bash
$ curl -sL https://core.blockstack.org/v1/prices/names/helloworld.id | jq -r ".name_price"
{
  "btc": 2.5e-05,
  "satoshis": 2500
}
```

Note the use of `jq -r` to select the `"name_price"` field.  This API
endpoint may return other ancilliary data regarding transaction fee estimation,
but this is the only field guaranteed by this specification to be present.

#### Getting the Current Consensus Hash ([reference](https://core.blockstack.org/#blockchain-operations-get-consensus-hash))

```bash
$ curl -sL https://core.blockstack.org/v1/blockchains/bitcoin/consensus
{
  "consensus_hash": "98adf31989bd937576aa190cc9f5fa3a"
}
```

The consensus hash must be included in the `NAME_PREORDER` transaction.  The BNS
clients do this automatically.  See the [transaction format
document](wire-format.md) for details as to how to include this in the
transaction.

#### Registering a Name

Registration happens through a BNS client, such as the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser) or
[blockstack.js](https://github.com/blockstack/blockstack.js).
The reference BNS clients manage a local Bitcoin wallet, calculate transaction fees
dynamically and automatically, and broadcast both the `NAME_PREORDER` and
`NAME_REGISTRATION` transactions at the right times.

If you want to make your own registration client, you should see the
[transaction format](wire-format.md) document.

## Managing BNS Names

Once you register a BNS name, you have the power to change its zone file hash,
change its public key hash, destroy it (i.e. render it unresolvable),
or renew it.  The BNS consensus rules ensure that *only* you, as the owner of
the name's private key, have the ability to carry out these operations.

Each of these operations are executed by sending a specially-formatted
blockchain transaction to the blockchain, which BNS nodes read and process.
The operations are listed below:

| Transaction Type | Description |
|------------------|-------------|
| `NAME_UPDATE`    | This changes the name's zone file hash.  Any 20-byte string is allowed. |
| `NAME_TRANSFER`  | This changes the name's public key hash.  In addition, the current owner has the option to atomically clear the name's zone file hash (so the new owner won't "receive" the zone file). |
| `NAME_REVOKE`    | This renders a name unresolvable.  You should do this if your private key is compromised. |
| `NAME_RENEWAL`   | This pushes back the name's expiration date (if it has one), and optionally both sets a new zone file hash and a new public key hash. |

The reference BNS clients---
[blockstack.js](https://github.com/blockstack/blockstack.js) and the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser)---can handle creating
and sending all of these transactions for you.

### NAME_UPDATE ([live example](https://www.blocktrail.com/BTC/tx/e2029990fa75e9fc642f149dad196ac6b64b9c4a6db254f23a580b7508fc34d7))

A `NAME_UPDATE` transaction changes the name's zone file hash.  You would send
one of these transactions if you wanted to change the name's zone file contents.
For example, you would do this if you want to deploy your own [Gaia
hub](https://github.com/blockstack/gaia) and want other people to read from it.

A `NAME_UPDATE` transaction is generated from the name, a recent [consensus
hash](#bns-forks), and the new zone file hash.  The reference clients gather
this information automatically.  See the [transaction format](wire-format.md)
document for details on how to construct this transaction.

### NAME_TRANSFER ([live example](https://www.blocktrail.com/BTC/tx/7a0a3bb7d39b89c3638abc369c85b5c028d0a55d7804ba1953ff19b0125f3c24))

A `NAME_TRANSFER` transaction changes the name's public key hash.  You would
send one of these transactions if you wanted to:

* Change your private key
* Send the name to someone else

When transferring a name, you have the option to also clear the name's zone
file hash (i.e. set it to `null`).
This is useful for when you send the name to someone else, so the
recipient's name does not resolve to your zone file.

The `NAME_TRANSFER` transaction is generated from the name, a recent [consensus
hash](#bns-forks), and the new public key hash.  The reference clients gather
this information automatically.  See the [transaction format](wire-format.md)
document for details on how to construct this transaction.

### NAME_REVOKE ([live example](https://www.blocktrail.com/BTC/tx/eb2e84a45cf411e528185a98cd5fb45ed349843a83d39fd4dff2de47adad8c8f))

A `NAME_REVOKE` transaction makes a name unresolvable.  The BNS consensus rules
stipulate that once a name is revoked, no one can change its public key hash or
its zone file hash.  The name's zone file hash is set to `null` to prevent it
from resolving.

You should only do this if your private key is compromised, or if you want to
render your name unusable for whatever reason.  It is rarely used in practice.

The `NAME_REVOKE` operation is generated using only the name.  See the
[transaction format](wire-format.md) document for details on how to construct
it.

### NAME_RENEWAL ([live example](https://www.blocktrail.com/BTC/tx/e543211b18e5d29fd3de7c0242cb017115f6a22ad5c6d51cf39e2b87447b7e65))

Depending in the namespace rules, a name can expire.  For example, names in the
`.id` namespace expire after 2 years.  You need to send a `NAME_RENEWAL` every
so often to keep your name.

A `NAME_RENEWAL` costs both transaction fees and registration fees.  You will
pay the registration cost of your name to the namespace's designated burn address when you
renew it.  You can find this fee using the `/v1/prices/names/{name}` endpoint.

When a name expires, it enters a month-long "grace period" (5000 blocks).  It
will stop resolving in the grace period, and all of the above operations will
cease to be honored by the BNS consensus rules.  You may, however, send a
`NAME_RENEWAL` during this grace period to preserve your name.

If your name is in a namespace where names do not expire, then you never need to
use this transaction.

When you send a `NAME_RENEWAL`, you have the option of also setting a new public
key hash and a new zone file hash.  See the [transaction format](wire-format.md)
document for details on how to construct this transaction.

## BNS Subdomains

BNS names are strongly-owned because the owner of its private key can generate
valid transactions that update its zone file hash and owner.  However, this comes at the
cost of requiring a name owner to pay for the underlying transaction in the
blockchain.  Moreover, this approach limits the rate of BNS name registrations
and operations to the underlying blockchain's transaction bandwidth.

BNS overcomes this with subdomains.  A **BNS subdomain** is a type of BNS name whose state
and owner are stored outside of the blockchain, but whose existence and
operation history are anchored to the
blockchain.  In the example table in the [Resolving BNS
Names](#resolving-bns-names) section, the names `cicero.res_publica.id` and
`podsaveamerica.verified.podcast` are subdomains.

Like their on-chain counterparts, subdomains are globally
unique, strongly-owned, and human-readable.  BNS gives them their own name state
and public keys.

Unlike on-chain names, subdomains can be created and managed
cheaply, because they are broadcast to the
BNS network in batches.  A single blockchain transaction can send up to 120
subdomain operations.

This is achieved by storing subdomain records in the [Atlas Network](atlas_network.md).
An on-chain name owner broadcasts subdomain operations by encoding them as
`TXT` records within a DNS zone file.  To broadcast the zone file,
the name owner sets the new zone file hash with a `NAME_UPDATE` transaction and
replicates the zone file via Atlas.  This, in turn, replicates all subdomain
operations it contains, and anchors the set of subdomain operations to
an on-chain transaction.  The BNS node's consensus rules ensure that only
valid subdomain operations from *valid* `NAME_UPDATE` transactions will ever be
stored.

For example, the name `verified.podcast` once wrote the zone file hash `247121450ca0e9af45e85a82e61cd525cd7ba023`,
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
| owner="1Et..." | signed  | owner="1Et..." | signed  | owner="1cJ..." |
| zf0="7e4..."   |<--------| zf0="111..."   |<--------| zf0="111..."   |<---- ...
| seqn=0         |         | seqn=1         |         | seqn=2         |
|                |         | sig="xxxx"     |         | sig="xxxx"     |
+----------------+         +----------------+         +----------------+
        |                          |                          |
        |        off-chain         |                          |
~ ~ ~ ~ | ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~|~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ | ~ ~ ~ ~ ~ ~ ~ ...
        |         on-chain         |                          |
        V                          V (zone file hash    )     V
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
state-transitions it has undergone, and determine the current zone file and public
key hash for the subdomain.

### Resolving Subdomains

Developers interact with subdomains the same way they interact with names.
Using the BNS API, a developer can:

#### Look up a subdomain's public key and zone file ([reference](https://core.blockstack.org/#name-querying-get-name-info))

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
  of an on-chain name owner's zone files must be present in the Atlas network.
  This lets the BNS node prove the *absence* of any conflicting subdomain-creation and
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
to help developers broadcast subdomain operations.  Users would still own their
subdomain names; the registrar simply gives developers a convenient way for them
to register and manage them in the context of a particular application.
Please see the [tutorial on running a subdomain registrar](subdomains.md) for
details on how to use it.

## BNS Forks

BNS effectively uses a public blockchain to store a database log.  A BNS peer
bootstraps itself by downloading and replaying the database log from the
blockchain, and in doing so, will calculate the same name database state as
every other (honest) BNS peer that has the same view of the blockchain.

Crucially, BNS is built on top of a public blockchain that is *unaware* of BNS's existence.
This means that the blockchain peers do not validate BNS transactions.  Instead,
the BNS peer needs to do so, and must know how to *reject* both invalid transactions
as well as well-formed transactions from dishonest peers (i.e. peers that do not
follow the same consensus rules).

BNS nodes do not directly communicate with one another---by design, the set of
BNS peers is not enumerable.  The only shared communication medium between BNS
peers is the blockchain.

To identify and reject invalid and malicious transactions without the blockchain's help,
the log of name operations embedded in the blockchain is constructed as a
[fork\*-consistent](http://www.scs.stanford.edu/~jinyuan/bft2f.pdf) database
log.  Fork\*-consistency is a [consistency
model](https://en.wikipedia.org/wiki/Consistency_model) whereby the state
replicas in all of the nodes exhibit the following properties:

* Each correct peer maintains a history of well-formed, valid state operations.  In this
  case, each correct BNS node maintains a copy of the history blockchain transactions
that encoded well-formed, valid name operations.

* Each honest peer's history contains the sequence of all operations that it
  sent.  That is, a user's BNS peer's transaction log will contain the sequence of all valid
transactions that the user's client wrote to the blockchain.

* If two peers accept operations *op* and *op'* from the same correct client,
  then both of their logs will have the both operations in the same order.  If
*op'* was accepted before *op*, then both peers' logs are identical up to *op'*.
In BNS, this means that if two peers both accept a given transaction, then it
means that they have accepted the same sequence of prior transactions.

This means that unlike with blockchains,
there can be *multiple long-lived conflicting forks* of the BNS database log.
However, due to fork\*-consistency, a correct BNS peer will only process *one*
of these forks, and will *ignore* transactions from peers in other forks.  In other words,
fork\*-consistency partitions the set of BNS peers into different **fork-sets**,
where all peers in a fork-set process each other's transactions, but the
completely ignore peers in other fork-sets.

BNS nodes identify which fork set they belong to using a **consensus hash**.  The
consensus hash is a cryptographic digest of a node's operation
history.  Each BNS peer calculates a new consensus hash each time it processes a
new block, and stores the history of consensus hashes for each block it
processed.

Two honest BNS peers can quickly determine if they are in the same fork-set by querying
each other's consensus hashes for a given block.  If they match, then they are
in the same fork-set (assming no hash collisions).

A BNS client executes a name operation on a specific fork-set by including a
recent consensus hash from that fork-set in the blockchain transaction.
At the same time, the BNS consensus rules state that a transaction can only be
accepted if it included a recent valid consensus hash.
This means that all BNS nodes in the client's desired fork-set will accept
the transaction, and all other BNS nodes not in the fork-set will ignore it.
You can see where the consensus hash is included in blockchain transactions by reading
the [transaction wire format](wire-format.md) document.

### Fork-set Selection

The blockchain linearizes the history of transactions, which means that
in general, there exists a fork-set for each distinct set of BNS
consensus rules.  For example, the Blockstack Core [2016 hard fork](release_notes/changelog-0.14.md) 
and [2017 hard fork](release_notes/changelog-0.17.md) both introduced new consensus
rules, which means at the time of this writing there are three possible fork-sets:
the pre-2016 fork-set, the 2016-2017 fork-set, and the post-2017 fork-set.
The [public BNS nodes](https://node.blockstack.org:6263) are always running
in the fork-set with the latest consensus rules.

BNS clients are incentivized to communicate with peers in the fork-set that has
the most use, since this fork-set's name database will encode name/state
bindings that are the most widely-accepted and understood by users.
To identify this fork-set, a BNS client needs to learn one of
its recent consensus hashes.  Once it has a recent consensus hash, it can
query an *untrusted* BNS node for a copy of 
its name database, and use the consensus hash to verify that the name database
was used to generate it.

How does a BNS node determine whether or not a consensus hash corresponds to the
most widely-used fork-set?  There are two strategies:

* Determine whether or not a *characteristic transaction* was accepted by the
widely-used fork-set.  If a client knows that a specific transaction belongs to
the widely-used fork-set and not others, then they can use the consensus hash to
efficiently determine whether or not a given node belongs to this fork-set.

* Determine how much "economic activity" exists in a fork-set by inspecting
the blockchain for burned cryptocurrency tokens.  Namespace and name
registrations are structured in a way that sends cryptocurrency tokens to either
a well-known burn address, or to an easily-queried pay-to-namespace-creator
address.

Both strategies rely on the fact that the consensus hash is calculated as a
[Merkle skip-list](https://github.com/blockstack/blockstack-core/issues/146)
over the BNS node's accepted transactions.  A client can use a consensus hash to
determine whether or not a transaction *T* was accepted by a node with *O(log
n)* time and space complexity.  We call the protocol for resolving a consensus hash to a specific transaction
**Simplified Name Verification** (SNV).  See our [paper on the subject](https://blockstack.org/virtualchain_dccl16.pdf)
for details of how SNV works under the hood.

If the client has a consensus hash and knows of a characteristic transaction in the widely-used fork-set,
it can use SNV to determine whether or not a node belongs to the fork-set that accepted it.

If the client knows about multiple conflicting consensus hashes,
they can still use SNV to determine which one corresponds
to the most-used fork-set.  To do so, the client would use a
[blockchain explorer](https://explorer.blockstack.org) to find the
list of transactions that burned cryptocurrency tokens.  Each of these
transactions will be treated as potential characteristic transactions:
the client would first select the subset of transactions that are well-formed
BNS transactions, and then use SNV to determine which of them correspond to which
consensus hashes.  The client chooses the consensus hash that corresponds
to the fork-set with the highest cumulative burn.

Work is currently underway to automate this process.

## Decentralized Identifiers (DIDs)

BNS nodes are compliant with the emerging
[Decentralized Identity Foundation](http://identity.foundation) protocol
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
* The name's zone file hash must be the hash of a well-formed DNS zone file
* The DNS zone file must be present in the BNS [Atlas Network](atlas_network.md)
* The DNS zone file must contain a `URI` resource record that points to a signed
  JSON Web Token
* The public key that signed the JSON Web Token (and is included with it) must
  hash to the address that owns the name

Not all names will have DIDs that resolve to public keys.  However, names created by the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser) will have DIDs that
do.

Developers can programmatically resolve DIDs via the Python API:

```Python
>>> import blockstack
>>> blockstack.lib.client.resolve_DID('did:stack:v0:16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg-1', hostport='https://node.blockstack.org:6263')
{'public_key': '020fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc8'}
```

A RESTful API is under development.

### DID Encoding for Subdomains

Every name and subdomain in BNS has a DID.  The encoding is slightly different
for subdomains, so the software can determine which code-path to take.

* For on-chain BNS names, the `{address}` is the same as the Bitcoin address
  that owns the name.  Currently, both version byte 0 and version byte 5
addresses are supported (i.e. addresses starting with `1` or `3`, meaning `p2pkh` and
`p2sh` addresses).

* For off-chain BNS subdomains, the `{address}` has version byte 63 for
  subdomains owned by a single private key, and version byte 50 for subdomains
owned by a m-of-n set of private keys.  That is, subdomain DID addresses start
with `S` or `M`, respectively.

The `{index}` field for a subdomain's DID is distinct from the `{index}` field
for a BNS name's DID, even if the same created both names and subdomains.
For example, the name `abcdefgh123456.id` has the DID `did:stack:v0:16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg-0`,
because it was the first name created by `16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg`.
However, `16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg` *also* created `jude.statism.id`
as its first subdomain name.  The DID for `jude.statism.id` is
`did:stack:v0:SSXMcDiCZ7yFSQSUj7mWzmDcdwYhq97p2i-0`.  Note that the address
`SSXMcDiCZ7yFSQSUj7mWzmDcdwYhq97p2i` encodes the same public key hash as the address
`16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg` (the only difference between these two
strings is that the first is base58check-encoded with version byte 0, and the
second is encoded with version byte 63).

You can see this play out in practice with the following code snippit:

```python
>>> import blockstack
>>> blockstack.lib.client.get_name_record('jude.statism.id', hostport='https://node.blockstack.org:6263')['address']
u'16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg'
>>> import virtualchain
>>> virtualchain.address_reencode('16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg', version_byte=63)
'SSXMcDiCZ7yFSQSUj7mWzmDcdwYhq97p2i'
>>> blockstack.lib.client.resolve_DID('did:stack:v0:SSXMcDiCZ7yFSQSUj7mWzmDcdwYhq97p2i-0', hostport='https://node.blockstack.org:6263')
{'public_key': '020fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc8'}
```

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
| Registration times         | 1-2 hours | ~1 week | ~1 day | 1-2 hours |
| Subdomain registration times | 1 hour (instant with [#750](https://github.com/blockstack/blockstack-core/issues/750)) | varies | instant | ~1 hour |
| Anyone can make a TLD/namespace | X  |  [1]   |     |    [1]  |
| TLD/Namespace owners get registration fees | X |   |   X  |   |
| TLD/Namespace can be seeded with initial names | X |  |  X |  |
| Portable across blockchains | X  |     | N/A |    |
| Off-chain names            | X   |     | N/A  |         |
| Off-chain name state       | X   | X   | N/A  |         |
| Name provenance            | X   | X   |      |   X     |
| [DID](http://identity.foundation) support | X   |     |     |          |
| Turing-complete namespace rules |  | X  | X  |          |
| Miners are rewarded for participating  | [1] |    | N/A  |  X |

[1] Requires support in higher-level applications.  These systems are not aware
of the existence of namespaces/TLDs at the protocol level.

[2] Blockstack Core destroys the underlying blockchain token to pay for
registration fees when there is no pay-to-namespace-creator address set in the
name's namespace.  This has the effect of making the blockchain miners' holdings
slightly more valuable.

