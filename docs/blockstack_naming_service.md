# Blockstack Naming Service

This document is written for Blockstack developers and technically-inclined
users.  Its purpose is twofold: to give a brief overview of how the 
Blockstack Naming Service works, and describe how developers can use it
to build decentralized Web applications.  If you read this document in its entirety, you will
understand the following concepts:

* Why a secure decentralized naming service is an important building
  block in decentralized systems
* How Blockstack applications can leverage BNS to solve real-world problems
* How BNS works under the hood

## Introduction

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

## Motivation

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

## How to Use BNS

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

Detailed explanations of how this works can be found in the
section "[How BNS Works](how-bns-works)."

### BNS Node Architecture

There are two parts to a BNS node that developers should be aware of.  They are:

* **The BNS indexer**.  This process crawls the blockchain and builds
  up its name database.  BNS indexers do not contain any private or sensitive
state, and can be deployed publicly.  We maintain a fleet of them at
`https://node.blockstack.org:6263` for developers to use to get started.

* **The BNS API**  This process gives
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
 Figure 1: BNS node architecture.                                |
 Clients talk to the BNS API module.                             |
 The API module talks to the indexer module.                     v
 The indexer module reads the blochchain via           +--------------------+
 a blockchain peer, over the blockchain's peer         |   blockchain peer  |
 network.                                              +--------------------+
```

BNS applications should use the BNS API module.  They should not attempt
to talk to a BNS indexer directly, because its API is not stable and is not meant
for consumption by any other process except for the API daemon.

Blockstack Core implements the API module and indexer module as separate daemons
(`blockstack api` and `blockstack-core`, respectively).  However, this is an
implementation detail, and may change in the future.

### BNS Namespaces

BNS names are organized hierarchically.  Names are grouped
in **namespaces**, which function like top-level domains in DNS.  All BNS names
belong to exactly one namespace.

Namespaces control a few properties about the names within them:
* How expensive they are to register
* How long they last before they have to be renewed
* Who (if anyone) receives the name registration fees
* Who is allowed to seed the namespace with its initial names.

Unlike DNS, *anyone* can create a namespace and set these properties.
Namespaces are created on a first-come first-serve basis, and once created, they
last forever.  The intention is that an application can create its own BNS
namespace  

At the time of this writing, by far the largest BNS namespace is the `.id`
namespace.  Names in the `.id` namespace are meant for resolving user
identities.  Short names in `.id` are more expensive than long names, and have
to be renewed by their owners every two years.  Name registration fees are not
paid to anyone in particular---they are instead sent to a "black hole" where they are
rendered unspendable (the intention is to discourage ID sqautters).

Developers can query individual namespaces and look up names within them using
the BNS API.  The API offers routes to do the following: 

* List all namespaces in existence ([reference](https://core.blockstack.org/#namespace-operations-get-all-namespaces))
* List all names within a namespace
  ([reference](https://core.blockstack.org/#namespace-operations-get-all-namespaces))

### Resolving BNS Names

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

Developers can query this table via the BNS API.  The API offers routes
to do the following:

* Look up a name's public key and name state 
([reference](https://core.blockstack.org/#name-querying-get-name-info))
* List all names the node knows about
  ([reference](https://core.blockstack.org/#name-querying-get-all-names))
* Look up a name's transaction history
  ([reference](https://core.blockstack.org/#name-querying-name-history))
* Look up the list of names owned by a given public key hash
  ([reference](https://core.blockstack.org/#name-querying-get-names-owned-by-address))

### Registering BNS Names

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

Registration happens through a BNS client.  We provide a [Node.js
client library](https://github.com/blockstack/blockstack.js) that implements a
wallet and an API for generating and sending well-formed transactions that will
be processed by BNS indexers.  The act of registering a name returns a
blockchain transaction ID, which programs can use to poll blockchain peers on
the status of a name's registration transactions.

Developers who do not want to use the reference client library should see the
[BNS transaction wire format](docs/wire-format.md) document for generating and
sending their own transactions.

### Managing BNS Names

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

Performing a name operation happens through a BNS client.  Our [Node.js client
library](https://github.com/blockstack/blockstack.js) implements
methods that generate, sign, and broadcast these transactions.  Each operation
generates a transaction ID, which programs can use to determine whether or not
an operation is confirmed and estimate how long it will take.  The low-level
transaction wire formats can be found in [this document](docs/wire-format.md).

### BNS Subdomains

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

Unlike on-chain names, a subdomain owner needs an on-chain name owner's help
in instantiating and transferring subdomains.  Only the subdomain's owner can generate 
subdomain transactions, but they need an on-chain name owner to broadcast them
to the BNS network.  In particular:
* A subdomain-creation transaction can only be processed by the owner of the on-chain
name that shares its suffix.  For example, only the owner of `res_publica.id`
can broadcast subdomain-creation transactions for subdomain names ending in
`.res_publica.id`.
* A subdomain-transfer transaction can only be broadcast by the owner of the
on-chain name that created it.  For example, the owner of
`cicero.res_publica.id` needs the owner of `res_publica.id` to broadcast a
subdomain-transfer transaction to change `cicero.res_publica.id`'s public key.
* A subdomain update transaction can be broadcast by *any* on-chain name owner,
  but the subdomain owner needs to find one who will cooperate.  For example,
the owner of `verified.podcast` can broadcast a subdomain-update transaction
created by the owner of `cicero.res_publica.id`.

The reason for these constraints is that the
state of all subdomains cannot depend on the order in which their
off-chain state is discovered.  See the [How BNS Works](how-bns-works) section
for details.

```
   subdomain                  subdomain                  subdomain
   creation                   update                     transfer
+----------------+         +----------------+         +----------------+
| cicero         |         | cicero         |         | cicero         |
| pubk="1Et..."  |         | pubk="1Et..."  |         | pubk="1cJ..."  |
| state="7e4..." |<--------| state="111..." |<--------| state="111..." |<---- ...
| sequence=0     |         | sequence=1     |         | sequence=2     |
| sig="xxxx"     |         | sig="xxxx"     |         | sig="xxxx"     |
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


Figure 2:  Subdomain lifetime with respect to on-chain name operations.  The
subdomain "cicero.res_publica.id" must be created and transferred by the
owner of "res_publica.id".  However, any on-chain name can process a subdomain
update for "cicero.res_publica.id".
```

To create a subdomain, the subdomain owner generates a
subdomain-creation transaction for their desired name
and gives it to the on-chain name owner.
The on-chain name owner then uses the [Atlas Network](docs/atlas-network.md) to
broadcast it to all other BNS nodes.

Importantly, these
records are stored outside of the blockchain (in the [Atlas Network](docs/atlas-network.md)).
The on-chain name owner anchors them to
the blockchain by setting their on-chain state value to the hash of the
sequence of subdomain-creation transactions they are broadcasting.  In the reference
implementation, the name owner can process up to 
120 subdomain-creation transactions with one on-chain transaction (and this number is
arbitrary).

Once created, a subdomain owner can use any on-chain name owner to broadcast a
subdomain-update transaction.  To do so, they generate and sign the requisite
subdomain operation and give it to an on-chain name owner, who then packages it
with other subdomain operations and sends them all out on the Atlas network.  As
with subdomain creation, the name owner anchors the subdomain operations to the
blockchain by setting the on-chain name's state value to the hash of the set of
subdomain operations they are propagating.  In
the reference implementation, a name owner can propagate up to 120 subdomain
operations with one on-chain transaction (again, this number is arbitrary).

Both the BNS indexer and API are aware of subdomains.  Developers can
query them just like on-chain names.

* Look up a subdomain's public key and name state 
([reference](https://core.blockstack.org/#name-querying-get-name-info))
* Look up a subdomain's transaction history
  ([reference](https://core.blockstack.org/#name-querying-name-history))
* Look up the list of names and subdomains owned by a given public key hash
  ([reference](https://core.blockstack.org/#name-querying-get-names-owned-by-address))

### Running a Registrar

// TODO

### Implementation Notes

Blockstack Core is the reference implementation of BNS.

In Blockstack Core, the following implementation-specific rules apply:
* Names are between 3 and 37 characters long (including their namespace), and consist of a 40-character
alphabet with the characters `a-z`, `0-9`, `.`, `_`, `-`, and `+`.
* Public key hashes are [Bitcoin
  addresses](https://en.bitcoin.it/wiki/Address)--specifically, p2pkh or p2sh
addresses.
* The name state is 20 bytes.

## How BNS Works

// TODO

### Related Work

BNS is not the only system of its kind.
Other systems include:
  * [Namecoin](https://namecoin.org)
  * [ENS](https://ens.domains/)
  * [Emercoin](https://emercoin.com/)
  * [Twister](https://en.wikipedia.org/wiki/Twister_(software))

BNS differs from these systems in the following ways:
// TODO: feature matrix
