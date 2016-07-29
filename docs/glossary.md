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

A signed JSON web token that describes a [Person](https://schema.org/Person).  It describes the name's owner.

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

## Zonefile

A type of file usually used by DNS servers, but used by Blockstack to point the CLI to various storage providers that hold copies of a user's profile information.  Its hash is written to the blockchain, and Blockstack Servers constantly try to replicate each zonefile to each other server, so each one has a full replica of all zonefiles in existence.
