---
layout: core
permalink: /:collection/:path.html
---
# Blockstack Naming Service (BNS)
{:.no_toc}

This document gives an overview of how the Blockstack Naming Service work. This
section introduces you to BNS and explains the following concepts:

* TOC
{:toc}

The ([Blockstack Core](https://github.com/blockstack/blockstack-core))
repository is the reference implementation of the Blockstack Naming Service.


## What is BNS

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
BNS nodes via the [Atlas network]({{ site.baseurl }}/core/atlas/overview.html).

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

## Motivation behind naming services

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


# Organization of BNS

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
network]({{ site.baseurl }}/core/atlas/overview.html).

* **BNS subdomains**.  These are names whose records are stored off-chain,
but are collectively anchored to the blockchain.  The ownership and state for
these names lives within the [Atlas network]({{ site.baseurl }}/core/atlas/overview.html).  While BNS
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
