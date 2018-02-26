# Glossary

Commonly used terms and jargon in Blockstack

## Account

A field in a profile that links the name to an existing service, like Twitter or OpenBazaar.  They are listed under the `accounts` listing in a profile.

Some accounts serve as social proofs, but they can contain any data the user wants.

## Atlas

A peer-to-peer network maintained by Blockstack Core nodes that stores each
name's zone files and immutable data.  See [this document](atlas_network.md) for
details.

## Blockstack ID

(Also called a "name").

A human-readable name in Blockstack.  It is comprised only of upper and lower-case ASCII characters, numbers, as well as `-`, `_`, and `.`.  It must end with a `.`, followed by a namespace ID.  It has at least 3 characters, and at most 37 (including the `.` and the namespace ID).

Anyone can register a Blockstack ID, such as through the [Blockstack Browser](https://github.com/blockstack/blockstack-browser) 

## Blockstack Core

A server that reads a blockchain with [virtualchain](https://github.com/blockstack/blockstack-virtualchain), filters out transactions that represent name operations, and builds up a database of (name, public key, state value) triples.

## Blockstack Naming Service (BNS)

This is the naming protocol that Blockstack Core implements.  See [this
document](blockstack_naming_service.md) for details.

## Consensus Hash

A cryptographic hash that represents a proof-of-computation by a Blockstack Core node.  Two Blockstack Core nodes have seen and processed the same name operations up to block `n` if and only if they each calculate the same consensus hash at height `n`.

A Blockstack Core node only accepts a name operation if it has a previously-calculated but recent consensus hash.  Blockstack clients obtain a consensus hash from a Blockstack Core node in order to construct a name operation.

## Gaia

This is Blockstack's storage system.  Gaia hosts all of your app-specific data.

## Gaia Hub

This is a publicly-routable server that serves as an entry point for Gaia data.
Anyone can stand up and run a Gaia hub by following [these
instructions](https://github.com/blockstack/gaia).
Blockstack provides a [default Gaia hub](https://gaia.blockstack.org).

## Immutable Data

This is the general term for chunks of data whose hash is cryptographically
bound to a blockchain transaction.  This includes all data stored in the Atlas
network (such as your Blockstack ID's zone file),
as well as any data whose hash is stored in the Atlas network.

## Mutable Data

This is the general term for data that is (1) signed by your Blockstack ID, and
(2) can be looked up using your Blockstack ID.  This includes all your Gaia
data, as well as your profile.

## Name

See Blockstack ID.

## Name Database

The set of (name, public key, name state) triples that the Blockstack Core node generates by reading the blockchain.  The name state is usually the hash of a DNS zone file stored in Atlas.

## Name Operation

A specially-crafted transaction in the underlying blockchain that, when processed, will change each Blockstack Core's name database.  Examples include `NAME_PREORDER` (preorders a name), `NAME_REGISTRATION` (registers a name), `NAME_UPDATE` (changes a name's zonefile hash), `NAME_TRANSFER` (changes a name's public key), and `NAME_REVOKE` (locks everyone out of a name until it expires).

Name operations are encoded on Bitcoin as `OP_RETURN` outputs that start with `id`, followed by a 1-byte character that identifies the particular operation.

See the [wire format](wire-format.md) document for details.

## Namespace

Analogous to a DNS TLD, it represents a grouping of names.  All names under the same namespace have the same pricing and lifetime rules.

Anyone can create a namespace, but doing so is expensive by design.  See the
[namespace creation](namespace_creation.md) tutorial for details.

## Preorder

The first of two steps to acquire a name.  This operation writes the hash of both the name and the address that will own it.

## Profile

A signed JSON web token that describes a [Person](https://schema.org/Person), which describes the name's owner.  You can put anything you want into your profile.

Additionally, profiles hold lists of social verifications and pointers to your Gaia data.

## Register

(1) The act of acquiring a name in Blockstack.

(2) The second of two steps to create a new name entry in the name database.  Reveals the name as plaintext to the world.  Must match a recent preorder to be accepted.

## Registrar

An online service that lets you sign up for and manage the profiles of Blockstack IDs.

## Resolver

An online service that displays zonefile and profile data for a Blockstack ID.  [The Blockstack Explorer](https://explorer.blockstack.org) is a resolver.

## Social proof

A post in an account on an existing Web service like Twitter, Facebook, or GitHub that points back to a Blockstack ID.  Used to provide some evidence that the person who owns the Blockstack ID is also the person who owns the Web service account.

Social proofs are listed in your profile.

## Storage Provider

This is any service that can serve your zone file, profile, or data.  In all cases, the data is signed by one of your wallet's keys, so you can use any provider without having to worry about it trying to change the data.

Storage providers are accessed through a Gaia hub.  Gaia hubs ship with drivers
that allow them to treat storage providers as dumb hard drives, which store
signed encrypted data on the hub's behalf.

Not all storage providers support writes--some of them are read-only.

Supported storage providers today include:
* Amazon S3
* Dropbox
* Your harddrive
* Any HTTP/HTTPS/FTP server (read-only)
* Any public-use Gaia hub
* IPFS

Support is being added for:
* Google Drive
* Microsoft OneDrive
* Box.com
* BitTorrent

If you have a preferred storage provider, and you're a developer, please consider sending us a pull request to add support for it!

## Zone file

A specially-formatted file that stores routing information for a Blockstack ID.
Blockstack clients use your zone file to find out where your preferred Gaia
hub(s) are.  Ever Blockstack Core node stores a copy of every zone file for
every Blockstack ID by participating in the Atlas network.
