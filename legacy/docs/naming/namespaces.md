---
layout: core
permalink: /:collection/:path.html
---
# Understand Namespaces

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
paid to anyone in particular---they are instead sent to a "black hole" where
they are rendered unspendable (the intention is to discourage ID sqautters).

Unlike DNS, *anyone* can create a namespace and set its properties. Namespaces
are created on a first-come first-serve basis, and once created, they last
forever.

However, creating a namespace is not free.  The namespace creator must *burn*
cryptocurrency to do so.  The shorter the namespace, the more cryptocurrency
must be burned (i.e. short namespaces are more valuable than long namespaces).
For example, it cost Blockstack PBC 40 BTC to create the `.id` namespace in 2015
(in transaction
`5f00b8e609821edd6f3369ee4ee86e03ea34b890e242236cdb66ef6c9c6a1b281`).

Namespaces can be between 1 and 19 characters long, and are composed of the
characters `a-z`, `0-9`, `-`, and `_`.

## Namespace Organization

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
