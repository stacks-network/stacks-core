# Openname Key-Value Store

__Table of Contents__

- [Intro](<#intro>)
    - [What this project is](<#project>)
    - [What this repo contains](<#repo>)
- [Specs](<#specs>)
- [Installation](<#installation>)

## Intro
<a name="intro"/>

### What this project is

A key-value store on the Bitcoin Blockchain.

### What this repo contains

+ code for running a node that participates in the KV store network (opennamed)
+ code for issuing commands to openname nodes like name lookups and name registrations (openname-cli and openname python lib)

## Installation
<a name="installation"/>

On Debian you need to install libzmq-dev

> sudo apt-get install libzmq-dev

## Specs
<a name="specs"/>

### Operations

1. name preorder
2. name register
3. name update
4. name transfer

### Definitions

- `nameset`: all the names ever registered on all possible namespaces
- `hash160`: a 20-byte ripemd160 hash
- `salt`: a random value appended to data in order to prevent reverse-lookups of the hashed data
- `preorder hash`: a hash160 of a given name to preorder, a random salt, and the scriptPubKey of the registrant
- `name encoding`: a given name converted from base 40 to base 256
- `historical record hash`: a hash of a data string generated from a representation of the nameset
- `update hash`: a hash of the data to be associated with a given name

### Data Encoding

#### Constraints:

- 40 bytes available in OP_RETURN
- 1 byte = 256 values
- charspace of alphanumerics and a few special chars (-._+) = 40 values
- 1.5 name characters can fit in each byte

#### Field lengths

- magic bytes = 2 bytes
- name hash = 20 bytes
- nameLen = 1 byte
- name = 1 byte - 16 bytes
- salt = 16 bytes
- update hash = 20 bytes
- historical record hash (truncated) = 16 bytes

#### Name encoding lengths

- 12 bytes = 18 characters
- 13 bytes = 19.5 characters
- 14 bytes = 21 characters
- 15 bytes = 22.5 characters
- 16 bytes = 24 characters
- 17 bytes = 25.5 characters
- 18 bytes = 27.0 characters
- 19 bytes = 28.5 characters
- 20 bytes = 30 characters

### Transaction Senders/Name Owners

Each transaction operation has a "sender". If any pre-orders or name registrations occur as a result of a given transaction, the "sender" is also considered the "owner" of those pre-orders and/or name registrations.

In a transaction, the sender is established as the funder of the first non-OP_RETURN input.

### Name Preorder (reserve)

- magic bytes (2 bytes)
- operation code (1 byte)
- preorder hash (20 bytes)
- consensus hash (16 bytes)

### Name Register (claim/reveal)

- magic bytes (2 bytes)
- operation code (1 byte)
- nameLen (1 byte)
- name (up to 16 bytes)
- salt (16 bytes)

### Name Update

- magic bytes (2 bytes)
- operation code (1 byte)
- nameLen (1 byte)
- name (up to 16 bytes)
- update hash (20 bytes)

### Name Transfer

- magic byte (2 byte)
- operation code (1 byte)
- nameLen (1 byte)
- name (up to 16 bytes)

In a name transfer, name ownership is transferred to the recipient of the first non-OP_RETURN output, while name admin rights are given to the recipient of the second non-OP_RETURN output.

### Misc.

Example of a transaction with an OP\_RETURN and multiple outputs:
https://blockchain.info/tx/1ae39745fd3891c16806bba44e6540944d145452ff156cab03076d7c08462e38?show_adv=true

### Historical Record Hashes

Historical record hashes (16 bytes) are to potentially be added to name preorders and/or name transfers.

The historical record hash must be a hash of a data string generated from a snapshot of the nameset at some point in the recent past (e.g. the last 12 blocks).
