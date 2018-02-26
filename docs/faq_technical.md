# Blockstack Technical FAQ

This document lists frequently-asked questions and answers to technical
questions about Blockstack.

If you are new to Blockstack, you should read the
[non-technical FAQ](https://blockstack.org/faq) first.

If you have a technical question that gets frequently asked on the
[forum](https://forum.blockstack.org) or [Slack](https://blockstack.slack.com),
feel free to send a pull-request with the question and answer.

# General Questions

## What is Blockstack?

Blockstack is a new Internet for decentralized applications.  Blockstack
applications differ from Web applications in two ways:

* **Users own their identities**.  The user brings their identity to the
  applications; applications do not require the user to create accounts and
passwords.
* **Users own their data**.  Users control who can read it, and where it gets stored.
  The application does not need to worry about hosting any user data.

The Blockstack project provides all of the infrastructure required for building
these kinds of applications.

## Is Blockstack decentralized?

Yes!  The components that make up Blockstack do not have any central points of
control.

* The [Blockstack Naming Service](blockstack_naming_service.md) runs on top of
  the Bitcoin blockchain, which itself is decentralized.  It binds Blockstack
IDs to a small amount of on-chain data (usually a hash of off-chain data).
* The [Atlas Peer Network](atlas_network.md) stores chunks of data referenced by
names in BNS.  It operates under similar design principles to BitTorrent, and
has no single points of failure.  The network is self-healing---if a node
crashes, it quickly recovers all of its state from its peers.
* The [Gaia storage system](https://github.com/blockstack/gaia) lets users
  choose where their application data gets hosted.  Gaia reduces all storage
systems---from cloud storage to peer-to-peer networks---to dumb, interchangeable
hard drives.  Users have maximum flexibility and control over their data in a
way that is transparent to app developers.

## Are Blockstack applications usable today?

Yes!  Blockstack applications are as easy to use as normal Web applications, if
not easier.  Moreover, they are just as performant if not more so.

If you install the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser), or use our
[Web-hosted Blockstack Browser](https://browser.blockstack.org), you can get
started with them right away.

## Where does Blockstack keep my user account?

Your user account is ultimately controlled by a [private
key](https://en.wikipedia.org/wiki/Public-key_cryptography).  You and only you
know what the private key is, and using your private key, you can prove to other
people that you own a particular piece of data (such as your Blockstack ID).

Your private key resides within your locally-running Blockstack Browser.
It never leaves your computer.

Your public keys are stored off-chain, and the *hash* of your public key is
stored on the Bitcoin blockchain.  The [Blockstack Naming
Service](blockstack_naming_service.md) allows anyone to look up your public key
hash, given your Blockstack ID.

## Where does Blockstack keep my app data?

As a Blockstack user, you can choose exactly where your data gets stored.
Blockstack uses a decentralized storage system called
[Gaia](https://github.com/blockstack/gaia) to host your data.  Gaia is different
from other storage systems because it lets you securely host your data wherever you want---in cloud
storage providers, on your personal server, or in another decentralized storage
system like BitTorrent or IPFS.

When you register, you are given a default Gaia hub that replicates your
data to a bucket in Microsoft Azure.  However, you can configure and 
deploy your own Gaia hub and have Blockstack store your data there instead.

The [Blockstack Naming Service](blockstack_naming_service.md) and the [Atlas
network](atlas_network.md) work together to help other users discover your
app-specific public data, given your Blockstack ID.

# Blockstack IDs

## What is a Blockstack ID?

Blockstack IDs are usernames.  Unlike normal Web app usernames, Blockstack IDs
are usable *across every Blockstack app.*  They fill a similar role to
centralized single-signon services like Facebook or Google.  However, you and
only you control your Blockstack ID, and no one can track your logins.

## How do I get a Blockstack ID?

If you install the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser) or use the
[Web-hosted Blockstack Browser](https://browser.blockstack.org), you can
purchase one with Bitcoin.

## Do I need a Blockstack ID to use Blockstack apps?

No, you can use Blockstack applications right away.  However, if you want to
*share data with other users*, then you need a Blockstack ID.

## Why do I need a Blockstack ID?

Blockstack IDs are used to discover where you are keeping your
(publicly-readable) application data.  For example, if `alice.id` wants to share 
a document with `bob.id`, then `bob.id`'s browser uses the Blockstack ID
`alice.id` to look up where `alice.id` stored it.

The technical descriptions of how and why this works are quite long.
Please see the [Blockstack Naming Service](blockstack_naming_service.md)
documentation for a full description.

## What is a Blockstack Subdomain?

This is also a Blockstack ID, and can be used for all the things a Blockstack ID
can be used for.  The only difference is that they have the format `foo.bar.baz`
instead of `bar.baz`.  For example,
[jude.personal.id](https://core.blockstack.org/v1/users/jude.personal.id) is a 
Blockstack ID, and is a subdomain of `personal.id`.

Subdomains are first-class Blockstack IDs---they can be used for all the same
things that an on-chain Blockstack ID can be used for, and they have all of
the same safety properties.  They are globally unique, they are strongly owned
by a private key, and they are human-readable.

Subdomains are considerably cheaper than Blockstack IDs, since hundreds of them
can be registered with a single transaction.  The [BNS
documentation](blockstack_naming_service.md) describes them in detail.

Subdomains provide a fast, inexpensive way to onboard many users at once.

## Can I get a Blockstack ID without spending Bitcoin?

Blockstack subdomains can be obtained without spending Bitcoin
by asking a subdomain registrar to create one for you.

## Is there a Blockstack name explorer?

Yes!  It's at https://explorer.blockstack.org

# Blockstack App Development

## I'm a Web developer.  Can I build on Blockstack?

Yes!  Blockstack is geared primarily towards Web developers.  All of your
existing knowledge is immediately applicable to Blockstack.  Anything you can do
in a Web browser, you can do in a Blockstack app.

## I'm a non-Web developer.  Can I build on Blockstack?

Yes!  Blockstack implements a [RESTful API](https://core.blockstack.org) which
lets you interact with Blockstack from any language and any runtime.  In fact,
the reference client
([blockstack.js](https://github.com/blockstack/blockstack.js)) is mainly a
wrapper around these RESTful API calls, so you won't be missing much by using a
language other than Javascript.

## What's the difference between a Web app and a Blockstack app?

Blockstack apps are built like [single-page Web
apps](https://en.wikipedia.org/wiki/Single-page_application)---they are, in
fact, a type of Web application.

Blockstack apps are a subset of Web applications that use Blockstack's
technology to preserve the user's control over their identities and data.
As such, they tend to be simpler
in design and operation, since in many cases they don't have to host anything
besides the application's assets.

## Do I need to learn any new languages or frameworks?

No.  Blockstack applications are built using existing Web frameworks and programming
The only new thing you need to learn is either [blockstack.js](https://github.com/blockstack/blockstack.js) or
the [Blockstack RESTful API](https://core.blockstack.org).

## How does my Web app interact with Blockstack?

The [blockstack.js](https://github.com/blockstack/blockstack.js) library gives
any Web application the ability to interact with Blockstack's authentication and
storage services.  In addition, we supply a [public RESTful API](https://core.blockstack.org).

## What does `blockstack.js` do?

This is the reference client implementation for Blockstack.  You use it in your
Web app to do the following:

* Authenticate users
* Load and store user data
* Read other users' public data

## How do I use `blockstack.js`?

Please see the API documentation [here](https://github.com/blockstack/blockstack.js).

## How can I look up names and profiles?

You can use `blockstack.js`, or you can use the [public Blockstack Core
endpoint](https://core.blockstack.org).

## How can I read my public app data without `blockstack.js`?

The URLs to a user's public app data are in a canonical location in their
profile.  For example, here's how you would get public data from the
[Publik](https://publik.ykliao.com) app, stored under the Blockstack ID `ryan.id`.

1. Get the bucket URL
```bash
$ BUCKET_URL="$(curl -sL https://core.blockstack.org/v1/users/ryan.id | jq -r '."ryan.id"["profile"]["apps"]["http://publik.ykliao.com"]')"
$ echo "$BUCKET_URL"
https://gaia.blockstack.org/hub/1FrZTGQ8DM9TMPfGXtXMUvt2NNebLiSzad/
```

2. Get the data
```bash
$ curl -sL "${BUCKET_URL%%/}/statuses.json"
[{"id":0,"text":"Hello, Blockstack!","created_at":1515786983492}]
```

## How do I register Blockstack IDs?

You should use the [Blockstack Browser](https://github.com/blockstack/blockstack-browser).

## How do I register Blockstack Subdomains?

You can deploy and use a [Blockstack Subdomain Registrar](subdomains.md), or
use an existing one.

## Can I programmatically register Blockstack IDs?

Blockstack applications do not currently have
have access to the user's wallet.  Users are expected to
register Blockstack IDs themselves.

However, if you feel particularly ambitious, you can do one of the following:

* Set up a `blockstack api` endpoint (see the project [README](../README.md)) and write a
  program to automatically register names.  Also, see the [API
documentation](https://blockstack.github.io/blockstack-core/#managing-names-register-a-name)
for registering names on this endpoint.

* Write a `node.js` program that uses `blockstack.js` to register
  names.  This is currently in development.

## Can I programmatically register Blockstack Subdomains?

Yes!  Once you deploy your own subdomain registrar, you can have your Web app
send it requests to register subdomains on your Blockstack ID.  You can also
create a program that drives subdomain registration on your Blockstack ID.

## Do you have a testnet or sandbox to experiment with Blockstack?

We have an [integration test framework](../integration-tests) that provides a
private Blockstack testnet.  It uses `bitcoin -regtest` to create a private
blockchain that you can interact with, without having to spend any Bitcoin or
having to wait for blocks to confirm.  Please see the
[README](../integration-tests/README.md) for details.

## Does Blockstack have a smart contract system?

No, not yet.  This is because
Blockstack's design philosophy focuses on keeping system complexity at the 
"edges" of the network (e.g. clients), instead of the "core" of the network (e.g. 
the blockchain), in accordance with the [end-to-end
principle](https://en.wikipedia.org/wiki/End-to-end_principle).
Generally speaking, this can be interpreted as "if you can do X without 
a smart contract, you should do X without a smart contract."  This organizing
principle applies to a lot of useful decentralized applications.

## Can Blockstack applications interact with Bitcoin? Ethereum? Smart contracts? Other blockchains?

Yes!  Since Blockstack applications are built like Web applications, all you need to do is include the
relevant Javascript library into your application.

## Do you have a Blockstack app development tutorial?

Yes!  See [here](https://blockstack.org/tutorials).

# Comparisons to Other Systems

## Blockstack vs DNS

Blockstack and DNS both implement naming systems, but in fundamentally
different ways.  Blockstack *can be used* for resolving host names to IP
addresses, but this is not its default use-case.  The [Blockstack Naming
Service](blockstack_naming_service.md) (BNS) instead behaves
more like a decentralized
[LDAP](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol) system for
resolving user names to user data.

While DNS and BNS handle different problems, they share some terminology and
serialization formats.  However, it is important to recognize that this is the
*only* thing they have in common---BNS has fundamentally different semantics
than DNS:

* **Zone files**:  Blockstack stores a DNS zone file for each name.  However,
the semantics of a BNS zone file are nothing like the semantics of a DNS zone
file---the only thing they have in common is their format.
A "standard" Blockstack zone files only have `URI` and `TXT` resource records
that point to the user's application data.  Moreover, a Blockstack ID has a
*history* of zone files, and historic zone files can alter the way in which a
Blockstack ID gets resolved (DNS has no such concept).  It is conceivable that an advanced
user could add `A` and `AAAA` records to their Blockstack ID's zone file,
but these are not honored by any Blockstack software at this time.

* **Subdomains**:  Blockstack has the concept of a subdomain, but it is
  semantically very different from a DNS subdomain.  In Blockstack, a subdomain
is a Blockstack ID whose state and transaction history are anchored to the
blockchain, but stored within an on-chain Blockstack ID's zone file history.
Unlike DNS subdomains, a BNS subdomain has 
its own owner and is a first-class BNS name---all subdomains are resolvable,
and only the subdomain's owner can update the subdomain's records.  The only thing BNS subdomains and DNS
subdomains have in common is the name format (e.g. `foo.bar.baz` is a subdomain
of `bar.baz` in both DNS and BNS).

More details can be found in the [Blockstack vs
DNS](https://blockstack.org/docs/blockstack-vs-dns) document.  A feature
comparison can be found at the end of the [Blockstack Naming
Service](blockstack_naming_service.md) document.

## Blockstack vs Namecoin

Namecoin also implements a decentralized naming service on top of a blockchain,
just like BNS.  In fact, early versions of Blockstack were built on Namecoin.
However, [it was discovered](https://www.usenix.org/node/196209) that Namecoin's
merged mining with Bitcoin regularly placed it under the *de facto* control of a single
miner.  This prompted a re-architecting of the system to be *portable* across
blockchains, so that if Blockstack's underlying blockchain (currently Bitcoin)
ever became insecure, the system could migrate to a more secure blockchain.

A feature comparison can be found at the end of the [Blockstack Naming
Service](blockstack_naming_service.md) document.

## Blockstack vs ENS

ENS also implements a decentralized naming system on top of a blockchain, but as
a smart contract on Ethereum.  Like BNS, ENS is geared towards resolving names
to off-chain state (ENS names resolve to a hash, for example).  Moreover, ENS is
geared towards providing programmatic control over names with Turing-complete
on-chain resolvers.

BNS has a fundamentally different relationship with blockchains than ENS.
WHereas ENS tries to use on-chain logic as much as possible, BNS
tries to use the blockchain as little as possible.  BNS only uses it to store a
database log for name operations (which are interpreted with an off-chain BNS
node like Blockstack Core).  BNS name state and BNS subdomains reside entirely
off-chain in the Atlas network.  This has allowed BNS to migrate from blockchain
to blockchain in order to survive individual blockchain failures, and this has
allowed BNS developers to upgrade its consensus rules without having to get the
blockchain's permission (see the [virtualchain
paper](https://blockstack.org/virtualchain_dccl2016.pdf) for details).

A feature comparison can be found at the end of the [Blockstack Naming
Service](blockstack_naming_service.md) document.

## Blockstack vs Ethereum

Blockstack and Ethereum both strive to provide a decentralized application
platform.  Blockstack's design philosophy differs from Ethereum's design
philosophy in that Blockstack emphasizes treating the blockchain as a "dumb
ledger" with no special functionality or properties beyond a few bare minimum
requirements.  Instead, it strives to do everything off-chain---an application of the [end-to-end principle](https://en.wikipedia.org/wiki/End-to-end_principle).
Most Blockstack applications do *not*
interact with the blockchain, and instead interact with Blockstack
infrastructure through client libraries and RESTful endpoints.
This is evidenced by Blockstack's decision to implement its naming system (BNS), discovery and routing system
(Atlas), and storage system (Gaia) as blockchain-agnostic components that can be
ported from one blockchain to another.

Ethereum takes the opposite approach.  Ethereum dapps are expected to interface
directly with on-chain smart contract logic, and are expected to host a
non-trivial amount of state in the blockchain itself.  This is necessary for
them, because many Ethereum dapps' business logic is centered around the
mechanics of an ERC20 token.

Blockstack does not implement a smart contract system (yet), but it will soon
implement a [native token](https://blockstack.com/distribution.pdf) that will be
accessible to Blockstack applications.
