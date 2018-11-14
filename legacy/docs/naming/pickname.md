---
layout: core
permalink: /:collection/:path.html
---
# Choose a name
{:.no_toc}

This section explains how to choose and create a namespace, it contains the
following sections:

* TOC
{:toc}

## Intended uses for a namespace

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
the BNS API.

## List all namespaces in existence ([reference](https://core.blockstack.org/#namespace-operations-get-all-namespaces)).

```bash
$ curl https://core.blockstack.org/v1/namespaces
[
  "id",
  "helloworld",
  "podcast"
]
```

## List all names within a namespace ([reference](https://core.blockstack.org/#namespace-operations-get-all-namespaces))

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

## Get the Cost to Register a Namespace ([reference](https://core.blockstack.org/#price-checks-get-namespace-price))

```bash
$ curl https://core.blockstack.org/v1/prices/namespaces/test
{
  "satoshis": 40000000
}
```

If you want to register a namespace, please see the [namespace creation section]({{ site.baseurl }}/core/naming/namespace.html).

## Getting the Current Consensus Hash ([reference](https://core.blockstack.org/#blockchain-operations-get-consensus-hash))

```bash
$ curl -sL https://core.blockstack.org/v1/blockchains/bitcoin/consensus
{
  "consensus_hash": "98adf31989bd937576aa190cc9f5fa3a"
}
```

A recent consensus hash is required to create a `NAMESPACE_PREORDER` transaction.  The reference
BNS clients do this automatically.  See the [transaction format]({{ site.baseurl }}/core/wire-format.html)
document for details on how the consensus hash is used to construct the
transaction.

## Create a namespace

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

Developers wanting to create their own namespaces should read the [namespace creation section]({{ site.baseurl }}/core/naming/namespace.html) document.  It is highly recommended that
developers request individual support before creating their own space, given the large amount of
cryptocurrency at stake.
