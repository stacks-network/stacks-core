---
layout: core
permalink: /:collection/:path.html
---
# Blockstack Technical FAQ
{:.no_toc}
* TOC
{:toc}



This document lists frequently-asked questions and answers to technical
questions about Blockstack.

If you are new to Blockstack, you should read the
[non-technical FAQ](https://blockstack.org/faq) first.

If you have a technical question that gets frequently asked on the
[forum](https://forum.blockstack.org) or [Slack](https://blockstack.slack.com),
feel free to send a pull-request with the question and answer.

## Who should build on Blockstack?

Everyone! But more seriously, if you are building an application in JavaScript
that requires sign-in and storage you should look at using Blockstack. The APIs
we provide are not only decentralized (No dependency on Google, Facebook, or
other OAuth provider) but easier to use than traditional OAuth. Also you no
longer have to maintain and secure databases with all your user information.
That data is stored securely with the people who created it.

## What is a "serverless" app?

The application itself should not run application-specific functionality on a server. All of its functionality should run on end-points. However, the application may use non-app-specific servers with the caveat that they must not be part of the trusted computing base. This is the case with storage systems like Amazon S3 and Dropbox, for example, because Blockstack's data is signed and verified end-to-end (so the storage systems are not trusted to serve data). Serverless can also mean applications where some amount of server-side logic is still written by the application developer but unlike traditional architectures is run in stateless compute containers that are event-triggered, ephemeral (may only last for one invocation)


## How are Blockstack domains different from normal DNS domains?

Blockstack domains are not registered on the traditional DNS run by an organized called ICANN. Instead they're registered on a blockchain in a fully decentralized way. This means that Blockstack domains are truly owned by their owners and cannot be taken away. All Blockstack domains have public keys by default (public keys are required to own the domains), unlike the traditional DNS where a small fraction of domains get the (optional) public key certificates.

## What is a virtual chain?

Blockstack is designed around a "virtual chain" concept, where nodes only need to reach consensus on the shared "virtual chain" they're interested in. Virtual chains do not interact with one another, and a single blockchain can host many virtual chains. These virtual chains can live in any blockchain for which there exists a driver, and virtual chain clients only need to execute their virtual chain transactions (i.e. Blockstack only processes Blockstack virtual chain transactions).

## What is Blockstack Core and who is working on it?

Blockstack Core is the reference implementation of the Blockstack protocol described in our white paper. It consists of a couple of parts:

- Virtualchain implementation: This is a python library that parses the underlying blockchain (Bitcoin) and builds the state of the Blockstack DNS.
- Blockstack Core: Uses the Virtualchain to build the DNS state and comes to a consensus on that state in a peer network (Atlas).
- Blockstack API: Indexes the data stored by Blockstack Core and makes it available in a performant way to applications.

The project is open-source and anyone can contribute! The major contributors are mostly employees of Blockstack PBC. You can see the full list of contributors here: https://github.com/blockstack/blockstack-core/graphs/contributors


## How is Blockstack different from Ethereum for building decentralized apps?

You can think of Ethereum as a "heavy" blockchain that does everything for you. All the complexity is handled on-chain, computations are run there, and all scalability and security concerns need to be handled at the blockchain level. It amounts to a "mainframe" that runs all the applications in the ecosystem.

Blockstack puts minimal logic into a blockchain and handles scalability outside of the blockchain by re-using existing internet infrastructure. Our architectural design mirrors how computing has developed; moving from mainframes to smaller networked entities.

Read more about the differences between Blockstack and Ethereum dapps in the following forum post: https://forum.blockstack.org/t/what-is-the-difference-between-blockstack-and-ethereum/781/2

## Can Blockstack only run on Bitcoin?

The model we're currently exploring is where Blockstack can process multiple blockchains to construct the global state where each namespace is tied to a single blockchain. Meaning that say the .id namespace is defined to run on Bitcoin and a .eth namespace is defined to run on Ethereum. Blockstack can process transactions from both blockchains and update the state of namespaces, but the consistency of any given namespace depends only on the underlying blockchain it was defined on.

## Does Blockstack use a DHT (Distributed Hash Table)?

It does not, as of November 2016. It uses a much more reliable system called the Atlas Network. Details here: https://blog.blockstack.org/blockstack-core-v0-14-0-release-aad748f46d#.30gzlthdw

## Can the Blockstack network fork?

Yes, the Blockstack network can fork if the underlying blockchain encounters a deep fork. In this case, blockstack nodes on either side of the fork will diverge from one another.

We have yet to encounter a deep fork. If this does happen, then Blockstack will use the virtualchain state on the majority fork once the fork resolves.

We also hard fork the network once a year to make protocol breaking changes and upgrade the network. The last one of these happened on block `488500` on the bitcoin blockchain. There are more details about the fork in this forum post: https://forum.blockstack.org/t/blockstack-annual-hard-fork-2017/1618

## How is the Blockstack network upgraded over time? What parties need to agree on an upgrade?

We're working on an on-chain voting strategy similar to how mining works, where anyone can cast a vote proportional to the amount of Bitcoin burned. Similar to how Bitcoin upgrades, a new feature will activate if a certain threshold (e.g. 80%) of votes consistently request its adoption over a given time interval (e.g. a couple weeks).

Until then, we will publicly announce the availability of new software, with the promise that each release will bring highly-desired features to make upgrading worth the users' whiles.

## Who gets the registration fees for name registrations?

With the current design, names are purchased by paying tribute with Bitcoin mining fees.


## Where are the current core developers based? What are the requirements for being a core developer?

Most of the core developers work in NYC and Hong Kong. Developers who've contributed to the [core open-source software](https://github.com/blockstack/blockstack-core) over a long enough time period, by default, get included in the list of core developers. There is no formal process for being part of this informal list. Core developers, generally, have the ability to write high-quality code, understand distributed systems and applied crypto, and share a vision of building a truly decentralized internet and are dedicated to that cause.

## I heard some companies working on Blockstack have raised venture capital, how does that impact the project?

Blockstack, like Linux, is an open-source project with a GPLv3 license for the core technology. Just like different companies build apps and services on top of Linux and have different individual business models, there are companies who're building apps & services for Blockstack on top of the core open-source technology and these companies have various business models and funding sources respectively. Having more venture-backed companies join the ecosystem for a decentralized internet is a good thing for everyone participating in the ecosystem including users and developers.

## Where is my data stored and how do I control who access it?

You control where your data is stored (you could run your own server, or use your own cloud storage - Dropbox, Amazon S3, and keep backups across all). You then use those places as locations pointed to by the URLs in your Blockstack ID's zone file. 

## Why should I trust the information, like name ownership or public key mappings, read from Blockstack?

Blockstack records are extremely hard to tamper with. This is because the bindings for name ownership (names on Blockstack are owned by public keys) are announced in a proof-of-work blockchain (Bitcoin) and to change these binding an attacker will need to come up with a blockchain with more proof-of-work than the current Bitcoin blockchain but with a different history. Bitcoin's [current hash rate](https://blockchain.info/charts/hash-rate) makes this task almost impossible for non-state actors.

## Can anyone register a TLD?

Yes, anyone can register a TLD. If a TLD has not been registered already and you're willing to pay the registration fee for it, you can go ahead and register that TLD. There is no centralized party that can stop you from registering a TLD.


## What programming language can I use to build these apps?

To make apps that run in the web browser using Blockstack, you can use JavaScript and any of the same web frameworks or libraries you use today such as React, AngularJs, Vue.js or jQuery. The Blockstack Core is implementated in Python, but you can use any language you like for native apps as long as you are able to consume a JSON REST API.


## Do I need to run a full Blockstack node to use Blockstack?

tl;dr: You don't, but its very easy to.

To reduce the overhead involved in getting started we maintain a fleet of Blockstack Core nodes that your Blockstack applications connect to by default. If you want to run your own we provide detailed instructions on our [install page](https://blockstack.org/install). It only takes about 5-10 minutes to spin up your full node!

## What is the capacity per block for registrations using Blockstack?

Initial registrations can be done at an order of hundreds per block and once an identity is registered you can do “unlimited” updates to the data because that is off-chain. We’re also working on a more scalable solution where a very large number of identities can be registered but that’s not live yet and is in the pipeline as a rough benchmark. in summer 2015, Blockstack did 30,000+ identity registrations in a matter of few days live on the blockchain and Blockstack was actually throttling its servers and not taking up more than 100-200 transactions per block. It could’ve easily taken up more transactions without impacting the network.

## What language is the Blockstack software written in?

Python 2 and Node.js

## What incentives are there to run a Blockstack node?

Running a Blockstack node keeps you secure by ensuring that your app gets the right names and public keys. It's not expensive; it takes as much resources as a Chrome tab.

## Can Blockstack apps scale, given that Blockstack uses blockchains which don't scale that well?

Yes. Blockstack only uses the blockchain for name registration. Everything else happens off-chain, so apps work just as fast as they do on the Web.

## What if the current companies and developers working on Blockstack disappear, would the network keep running?

Yes, the Blockstack network will keep running. All of Blockstack's code is open-source and anyone can deploy Blockstack nodes or maintain the code. Further, Blockstack nodes don't need to coordinate with each other to function. Any node that a user deploys can function correctly independently.


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

The [Blockstack Naming Service]({{ site.baseurl }}/core/naming/introduction.html) and the [Atlas network]({{ site.baseurl }}/core/atlas/overview.html) work together to help other users discover your
app-specific public data, given your Blockstack ID.

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
documentation]({{ site.baseurl }}/core/naming/introduction.html) describes them in detail.

Subdomains provide a fast, inexpensive way to onboard many users at once.

## Can I get a Blockstack ID without spending Bitcoin?

Blockstack subdomains can be obtained without spending Bitcoin
by asking a subdomain registrar to create one for you.

## Is there a Blockstack name explorer?

Yes!  It's at https://explorer.blockstack.org
