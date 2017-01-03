# Glossary

Commonly used terms and jargon in Blockstack

## Account

A field in a profile that links the name to an existing service, like Twitter or OpenBazaar.  They are listed under the `accounts` listing in a profile.

Some accounts serve as social proofs, but they can contain any data the user wants.

## Blockstack ID

(Also called a "name").

A human-readable name in Blockstack.  It is comprised only of upper and lower-case ASCII characters, numbers, as well as `-`, `_`, and `.`.  It must end with a `.`, followed by a namespace ID.  It has at least 3 characters, and at most 37 (including the `.` and the namespace ID).

Anyone can register a Blockstack ID, either via [Onename](https://onename.com) or via the Blockstack CLI.  The former is free for most names (subject to spam and squatter filtering), but latter costs Bitcoin.

## Blockstack Server

A server that reads a blockchain with [virtualchain](https://github.com/blockstack/blockstack-virtualchain), filters out transactions that represent name operations, and builds up a database of (name, public key, zonefile hash) triples.

## Consensus Hash

A cryptographic hash that represents a proof-of-computation by a Blockstack Server.  Two Blockstack Servers have seen and processed the same name operations up to block `n` if and only if they each calculate the same consensus hash at height `n`.

A Blockstack Server only accepts a name operation if it has a previously-calculated but recent consensus hash.  The Blockstack CLI obtains a consensus hash from a Blockstack Server in order to construct a name operation.

## Immutable Data

This is data stored in your storage providers, but linked to by your *zonefile*.  It is called "immutable" since its hash is linked to by the blockchain directly.  While this is an extremely secure way of sharing data, the downside is that it's slow--each time you change a piece of immutable data, you have to send a new transaction and wait for it to confirm.

Storing data as immutable data is useful when the data is read-only, or changes very rarely.

## Mutable Data

This is data stored in your storage providers, but linked to by your *profile*.  It is called "mutable" since it can be changed without touching the blockchain.  Mutable data is signed by your wallet's data key, so anyone who reads it can verify that it came from you (i.e. the storage providers aren't trusted with authenticity).

Storing data as mutable data is useful when the data has to change quickly, and you don't really care if other readers won't see some of the changes.  This is the recommended way to associating external data with your Blockstack ID.  The only downside is that someone who's never read your new data can be tricked into reading old data by a malicious storage provider.  If this is a concern, you should use immutable data.

## Name

See Blockstack ID.

## Name Database

The set of (name, public key, zonefile hash) triples that the Blockstack Server generates by reading the blockchain.

## Name Operation

A specially-crafted transaction in the underlying blockchain that, when processed, will change each Blockstack Server's name database.  Examples include `NAME_PREORDER` (preorders a name), `NAME_REGISTER` (registers a name), `NAME_UPDATE` (changes a name's zonefile hash), `NAME_TRANSFER` (changes a name's public key), and `NAME_REVOKE` (locks everyone out of a name until it expires).

Name operations are encoded on Bitcoin as `OP_RETURN` outputs that start with `id`, followed by a 1-byte character that identifies the particular operation.

## Namespace

Analogous to a DNS TLD, it represents a grouping of names.  All names under the same namespace have the same pricing and lifetime rules.

Anyone can create a namespace, but doing so is expensive by design.

## Preorder

The first of two steps to acquire a name.  This operation writes the hash of both the name and the address that will own it.

## Profile

A signed JSON web token that describes a [Person](https://schema.org/Person), which describes the name's owner.  You can put anything you want into your profile.

Additionally, profiles hold lists of accounts, and pointers to mutable data.

## Register

(1) The act of acquiring a name in Blockstack.

(2) The second of two steps to create a new name entry in the name database.  Reveals the name as plaintext to the world.  Must match a recent preorder to be accepted.

## Registrar

An online service that lets you sign up for and manage the profiles of Blockstack IDs.  [Onename](https://onename.com) offers a registrar.

## Resolver

An online service that displays zonefile and profile data for a Blockstack ID.  [Onename](https://onename.com) offers a resolver.

## Social proof

A post in an account on an existing Web service like Twitter, Facebook, or GitHub that points back to a Blockstack ID.  Used to provide some evidence that the person who owns the Blockstack ID is also the person who owns the Web service account.

Social proofs are listed as profile accounts.

## Storage Provider

This is any service that can serve your zonefile, profile, or data.  In all cases, the data is signed by one of your wallet's keys, so you can use any provider without having to worry about it trying to change the data.

Not all storage providers support writes--some of them are read-only.

Supported storage providers today include:
* Amazon S3
* Your harddrive
* Onename's Kademila DHT
* Any HTTP/HTTPS/FTP server (read-only)
* Onename's profile resolver (read-only)
* Any Blockstack Server

Support is being added for:
* Dropbox
* Google Drive
* Microsoft OneDrive
* Box.com
* BitTorrent
* IPFS

If you have a preferred storage provider, and you're a developer, please consider sending us a pull request to add support for it!

## Zonefile

A type of file usually used by DNS servers, but used by Blockstack to point the CLI to various storage providers that hold copies of a user's profile information.  Its hash is written to the blockchain, and Blockstack Servers constantly try to replicate each zonefile to each other server, so each one has a full replica of all zonefiles in existence.

In addition, zonefiles store your data public key, as well as any pointers to immutable data.
