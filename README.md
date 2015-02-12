# Openname Key-Value Store

__Table of Contents__

- [Intro](<#intro>)
    - [What this project is](#what-this-project-is)
    - [What this repo contains](#what-this-repo-contains)
- [Installation](<#installation>)
    - [Debian](#debian)
- [Design](<#design>)
    - [Design overview](<#design-overview>)
    - [The stack](<#the-stack>)
    - [Name operations](<#name-operations>)
    - [Definitions](<#definitions>)
    - [Data storage comparison](<#data-storage-comparison>)
    - [Name ownership](<#name-ownership>)
    - [Consensus hashes](<#consensus-hashes>)
    - [Operation fields](<#field-packing>)
    - [Field lengths](<#field-lengths>)
    - [Constraints](<#constraints>)




## Intro
<a name="intro"/>

#### What this project is

A key-value store on the Bitcoin Blockchain.

#### What this repo contains

+ code for running a node that participates in the KV store network
    + opennamed
+ code for issuing commands to openname nodes like name lookups and name registrations
    + openname-cli
    + openname python lib

## Installation
<a name="installation"/>

> pip install openname

#### Debian

Install libzmq-dev

> sudo apt-get install libzmq-dev

## Design
<a name="design"/>

#### Design overview

+ validated sequence of operations + rules to interpret them = global consensus / agreed upon view of the system
+ data is simply stored in the blockchain in a defined sequence, and nodes read the blockchain and interpret the sequence of events with a set of defined rules. From this, they build a view of the system that should be in sync.
register names by being the first to include the name in a “registration” operation
+ to prevent people from stealing your name, first secretly “preorder” the name, but include a salted hash of the name in the blockchain
+ to associate data with the name, issue an “update” operation by including a hash of the data and storing the data itself in the DHT
+ to lookup the data associated with a name, issue a request to an opennamed node, which will lookup the name’s entry in the nameset, find the hash associated with the name, then go into the DHT with the hash and get the data associated with it
+ there are many, many possible namespaces
+ each namespace can have a custom pricing scheme

#### The stack

+ Blockchain: bitcoin
+ Hash storage method: OP_RETURN
+ Data storage method: Kademlia distributed hash table
+ Language: Python
+ Frameworks: Twisted

#### Name operations

1. name preorder
1. name register
1. name update
1. name transfer
1. name renew

#### Definitions

- `nameset`: all the names ever registered on all possible namespaces
- `hash160`: a 20-byte ripemd160 hash
- `salt`: a random value appended to data in order to prevent reverse-lookups of the hashed data
- `preorder hash`: a hash160 of a given name to preorder, a random salt, and the scriptPubKey of the registrant
- `name encoding`: a given name converted from base 40 to base 256
- `consensus hash`: a hash of a data string generated from a representation of the nameset (also known as the historical record hash or merkle snapshot)
- `update hash`: a hash of the data to be associated with a given name

#### Data storage comparison

+ nulldata in OP_RETURN output = 40 bytes
+ nulldata in multi-sig output = 66 bytes
+ namecoin operation = 520 bytes
+ hash in nulldata, full data in DHT = unlimited bytes

#### Name ownership

Each transaction operation has a "sender". If any pre-orders or name registrations occur as a result of a given transaction, the "sender" is also considered the "owner" of those pre-orders and/or name registrations.

In a transaction, the sender is established as the funder of the first non-OP_RETURN input.

In a name transfer, name ownership is transferred to the recipient of the first non-OP\_RETURN output, while name admin rights are given to the recipient of the second non-OP_RETURN output.

#### Consensus hashes

Consensus hashes (16 bytes) are to potentially be added to name preorders and/or name transfers.

The consensus hash must be a hash of a data string generated from a snapshot of the nameset at some point in the recent past (e.g. the last 12 blocks).

#### Operation fields

All name operations start with the magic bytes and an operation code.

|Operation|Fields|Max Size|
|---|---|---|
|preorder/reserve|preorder hash, consensus hash|39|
|register/claim/reveal|nameLen, name|20|
|update|nameLen, name, update hash|40|
|transfer|nameLen, name|20|
|renew|nameLen, name|20|

#### Field lengths

- magic bytes = 2 bytes
- operation code = 1 byte
- name hash = 20 bytes
- name length (nameLen) = 1 byte
- name = 1 byte - 16 bytes
- update hash = 20 bytes
- consensus hash (truncated) = 16 bytes

#### Constraints:

- 40 bytes available in OP_RETURN
- 1 byte = 256 values
- charspace of alphanumerics and a few special chars (-._+) = 40 values
- 1.5 name characters can fit in each byte
