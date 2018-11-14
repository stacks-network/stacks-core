## What is the Blockstack ecosystem

In the Blockstack ecosystem, users control their data and apps run on their devices. There
are no middlemen, no passwords, no massive data silos to breach, and no services
tracking us around the internet.

The applications on blockstack are server-less and decentralized. Developers
start by building a single-page application in Javascript, Then, instead of
plugging the frontend into a centralized API, they plug into an API run by the
user. Developers install a library called `blockstack.js` and don't have to
worry about running servers, maintaining databases, or building out user
management systems.

Personal user APIs ship with the Blockstack app and handle everything from
identity and authentication to data storage. Applications can request
permissions from users and then gain read and write access to user resources.

Data storage is simple and reliable and uses existing cloud infrastructure.
Users connect with their Dropbox, Google Drive, S3, etc... and data is synced
from their local device up to their cloud.

Identity is user-controlled and utilizes the blockchain for secure management of
keys, devices and usernames. When users login with apps, they are anonymous by
default and use an app-specific key, but their full identity can be revealed and
proven at any time. Keys are for signing and encryption and can be changed as
devices need to be added or removed.

Under the hood, Blockstack provides a decentralized domain name system (DNS),
decentralized public key distribution system, and registry for apps and user
identities.

## What problems does Blockstack solve?

Developers can now build Web applications where:

- you own your data, not the application
- you control where your data is stored
- you control who can access your data

Developers can now build Web applications where:

- you don't have to deal with passwords
- you don't have to host everyone's data
- you don't have to run app-specific servers

Right now, Web application users are "digital serfs" and applications are the "digital landlords". Users don't own their data; the app owns it. Users don't control where data gets stored; they can only store it on the application. Users don't control access to it; they only advise the application on how to control access (which the application can ignore).

Blockstack applications solve both sets of problems. Users pick and choose highly-available storage providers like Dropbox or BitTorrent to host their data, and applications read it with the user's consent. Blockstack ensures that all data is signed and verified and (optionally) encrypted end-to-end, so users can treat storage providers like dumb hard drives: if you don't like yours, you can swap it out with a better one. Users can take their data with them if they leave the application, since it was never the application's in the first place.

At the same time, developers are no longer on the hook for hosting user data. Since users bring their own storage and use public-key cryptography for authentication, applications don't have to store anything--there's nothing to steal when they get hacked. Moreover, many Web applications today can be re-factored so that everything happens client-side, obviating the need for running dedicated application servers.


## What is a Blockstack ID?

Blockstack IDs are usernames.  Unlike normal Web app usernames, Blockstack IDs
are usable *across every Blockstack app.*  They fill a similar role to
centralized single-signon services like Facebook or Google.  However, you and
only you control your Blockstack ID, and no one can track your logins.

## How do I get a Blockstack ID?

If you use the [Blockstack Browser]({{ site.baseurl }}/browser/browser-introduction.md) to create a
new ID.

## Why do I need a Blockstack ID?

Blockstack IDs are used to discover where you are keeping your
(publicly-readable) application data.  For example, if `alice.id` wants to share
a document with `bob.id`, then `bob.id`'s browser uses the Blockstack ID
`alice.id` to look up where `alice.id` stored it.

The technical descriptions of how and why this works are quite long.
Please see the [Blockstack Naming Service]({{site.baseurl}}/core/naming/introduction.html)
documentation for a full description.

=

## What components make ups the Blockstack ecosystem?

The components that make up Blockstack do not have any central points of
control.

* The [Blockstack Naming Service]({{ site.baseurl }}/core/naming/introduction.html) runs on top of
  the Bitcoin blockchain, which itself is decentralized.  It binds Blockstack
IDs to a small amount of on-chain data (usually a hash of off-chain data).
* The [Atlas Peer Network]({{ site.baseurl }}/core/atlas/overview.html) stores chunks of data referenced by
names in BNS.  It operates under similar design principles to BitTorrent, and
has no single points of failure.  The network is self-healing---if a node
crashes, it quickly recovers all of its state from its peers.
* The [Gaia storage system](https://github.com/blockstack/gaia) lets users
  choose where their application data gets hosted.  Gaia reduces all storage
systems---from cloud storage to peer-to-peer networks---to dumb, interchangeable
hard drives.  Users have maximum flexibility and control over their data in a
way that is transparent to app developers.


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


## What's the difference between Onename and Blockstack?

Onename is the free Blockstack ID registrar run by Blockstack. It makes it easy to register your name and setup your profile. Once the name has been registered in Onename you can transfer it to a wallet you control, or leave it there and use it as you like.

## How is Blockstack different from Namecoin?

Blockstack DNS differs from Namecoin DNS in a few fundamental ways: blockchain layering, storage models, name pricing models, and incentives for miners. We wrote a post where you can learn more here: https://blockstack.org/docs/blockstack-vs-namecoin

## I heard you guys were on Namecoin, what blockchain do you use now?

We use the Bitcoin blockchain for our source of truth.

## How long has the project been around?

Work on the project started in late 2013. First public commits on the code are
from Jan 2014. The first registrar for Blockstack was launched in March 2014 and
the project has been growing since then.

## Who started the project? Who maintains it?

The project was started by two engineers from Princeton University. Muneeb Ali
and Ryan Shea met at the Computer Science department at Princeton, where Muneeb
was finishing his PhD and Ryan was running the enterprenurship club. In 2014,
frustrated by the walled-gardens and security problems of the current internet
they started working on a decentralized internet secured by blockchains. A full
list of contributors can be found
[here](https://github.com/blockstack/blockstack-core/graphs/contributors).
