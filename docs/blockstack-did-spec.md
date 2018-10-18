# Blockstack DID Method Specification 

# Abstract

Blockstack is a network for decentralized applications where users own their
identities and data.  Blockstack utilizes a public blockchain to implement a
decentralized [naming layer](https://docs.blockstack.org/core/naming/introduction.html),
which binds a user's human-readable username to their current public key and a pointer to 
their data storage buckets.  The naming layer ensures that names are globally
unique, that names can be arbitrary human-meaningful strings, and that names 
are owned and controlled by cryptographic key pairs such that only the owner of the private key
can update the name's associated state.

The naming layer implements DIDs as a mapping
between the initial name operation for a user's name and the name's current
public key.  The storage pointers in the naming layer are leveraged to point to
the authoritative replica of the user's DID document.

# Status of This Document

This document is not a W3C Standard nor is it on the W3C Standards Track.  This is
a draft document and may be updated, replaced or obsoleted by other documents at
any time. It is inappropriate to cite this document as other than work in
progress.

Comments regarding this document are welcome.  Please file issues directly on
[Github](https://github.com/blockstack/blockstack-core/blob/master/docs/did-spec.md).

# 1. System Overview

Blockstack's DID method is specified as part of its decentralized naming system.
Each name in Blockstack has one or more corresponding DIDs, and each Blockstack
DID corresponds to exactly one name -- even if the name was revoked by its
owner, expired, or was re-registered to a different owner.

Blockstack is unique among decentralized identity systems in that it is *not*
anchored to a specific blockchain or DLT implementation.  The system is designed
from the ground up to be portable, and has already been live-migrated from the
Namecoin blockchain to the Bitcoin blockchain.  The operational ethos of
Blockstack is to leverage the must secure blockchain at all times -- that is,
the one that is considered hardest to attack.

Blockstack's naming system and its DIDs transcend the underlying blockchain, and
will continue to resolve to DID document objects (DDOs) even if the system
migrates to a new blockchain in the future.

## 1.1 DID Lifecycle

Understanding how Blockstack DIDs operate requires understanding how Blockstack
names operate.  Fundamentally, a Blockstack DID is defined as a pointer to the
*nth name registered by an address.*  How this information is determined depends
on the category of name being registered -- a DID can be derived from an
*on-chain* name or an *off-chain* name.  We call these DIDs *on-chain DIDs* and
*off-chain DIDs*, respectively.

### 1.1.1 On-Chain DIDs

On-chain names are written directly to Blockstack's underlying blockchain.
Instantiating an on-chain name requires two transactions -- a `NAME_PREORDER`
transaction, and a `NAME_REGISTRATION` transaction.  Upon successful
confirmation of the `NAME_REGISTRATION` transaction, the system assigns name to
an on-chain address indicated by the `NAME_REGISTRATION` transaction itself.
This address is the name's *owner*.

Since these transactions are written to the blockchain, the blockchain provides
a total ordering of name-to-address assignments.  Thus, a DID instanted for an
on-chain name may be referenced by the name's owner address, and the number of
names evern assigned to the owner address *at the time of this DID's
instantiation*.  For example, the DID
`did:stack:v0:15gxXgJyT5tM5A4Cbx99nwccynHYsBouzr-3` was instantiated when the
fourth on-chain name was created and initially assigned to the address `15gxXgJyT5tM5A4Cbx99nwccynHYsBouzr` 
(note that the index parameter -- the `-3` -- starts counting from 0).

### 1.1.2 Off-chain DIDs

Off-chain names, sometimes called *subdomains* in the Blockstack literature,
refer to names whose transaction histories are instantiated and stored outside
of Blockstack's blockchain within Blockstack's Atlas peer network.  Off-chain
name transactions are encoded in batches, where each batch is hashed and written
to the underlying blockchain through a transaction for an on-chain name.  This
provides them with the same safety properties as on-chain names -- off-chain
names are globally unique, off-chain names can be arbitrary human-meaningful
strings, off-chain names are owned by cryptographic key pairs, and all
Blockstack nodes see the same linearized history of off-chain name operations.

Off-chain names are instantiated by an on-chain name, indicated by the off-chain
name's suffix.  For example, `cicero.res_publica.id` is an off-chain name
whose initial transaction history is processed by the owner of the on-chain
name `res_publica.id`.  Note that the owner of `res_publica.id` does *not* own
`cicero.res_publica.id`, and cannot issue well-formed name updates to it.

Off-chain names -- and by extension, their corresponding DIDs -- have
different liveness properties than on-chain names.  The Blockstack
naming system protocol requires the owner of `res_publica.id` to not only
propagate the signed transactions that instantiate and transfer ownership of
`cicero.res_publica.id`.  However, *any* on-chain name can process a name update
for an off-chain name -- that is, an update that changes where the name's
assocaited state resides.  For details as to why this is the case, please refer
to the [Blockstack subdomain documentation](https://docs.blockstack.org/core/naming/subdomains.html).

An off-chain DID is similarly structured to an on-chain DID.  Like on-chain
names, each off-chain name is owned by an address (but not necessarily an
address on the blockchain), and each Blockstack node sees the same sequence of
off-chain name-to-address assignments.  Thus, it has enough information to
assign each off-chain name user a DID.

# 2. Blockstack DID Method

The namestring that shall identify this DID method is: `stack`

A DID that uses this method *MUST* begin with the following literal prefix: `did:stack`.
The remainder of the DID is its namespace-specific identifier.

# 2.1 Namespace-Specific Identifier

The namespace-specific identifier (NSI) of the Blockstack DID encodes two pieces
of information:  an address, and an index.

The **address** shall be a base58check encoding of a version byte concatenated with 
the RIPEMD160 hash of a SHA256 hash of a DER-encoded secp256k1 public key.
For example, in this Python 2 snippit:

```python
import hashlib
import base58

pubkey = '042bc8aa4eb54d779c1fb8a2d5022aec8ed7fc2cc34d57356d9e1c417ce416773f45b0299ea7be347d14c69c403d9a03c8ec0ccf47533b4bee8cd002e5de81f945'
sha256_pubkey = hashlib.sha256(pubkey.decode('hex')).hexdigest()
# '18328b13b4df87cbcd190c083ef1d74487fc1383792f208f52c596b4588fb665'
ripemd160_sha256_pubkey = hashlib.new('ripemd160', sha256_pubkey.decode('hex')).hexdigest()
# '1651c1a6001d4750e46be8a02cc19550d4309b71'
version_byte = '\x00'
address = base58.b58check_encode(version_byte + ripemd160_sha256_pubkey.decode('hex'))
# '1331okvQ3Jr2efzaJE42Supevzfzg8ahYW'
```

The **index** shall be a non-negative monotonically-increasing integer.

The (address, index) pair uniquely identifies a DID.  Blockstack's naming system
ensures that the index increments monotonically each time a DID is instantiated
(e.g. by incrementing it each time a name gets registered to the address).

## 2.2 Address Encodings

The address's version byte encodes whether or not a DID corresponds to an
on-chain name transaction or an off-chain name transaction, and whether or not
it corresponds to a mainnet or testnet address.  The version bytes for each
configuration shall be as follows:

* On-chain names on mainnet: `0x00`
* On-chain names on testnet: `0x6f`
* Off-chain names on mainnet: `0x3f`
* Off-chain names on testnet: `0x7f`

For example, the RIPEMD160 hash `1651c1a6001d4750e46be8a02cc19550d4309b71` would
encode to the following base58check strings:

* On-chain mainnet: `1331okvQ3Jr2efzaJE42Supevzfzg8ahYW`
* On-chain testnet: `mhYy6p1NrLHHRnUC1o2QGq2ynzGhduVoEX`
* Off-chain mainnet: `SPL1qbhYmg3EAyn2qf36zoyDamuRXm2Gjk`
* Off-chain testnet: `t8xcrYmzDDhJWihaQWMW2qPZs4Po1PfvCB`

# 3. Blockstack DID Operations

## 3.1 Creating a Blockstack DID

Creating a Blockstack DID requires registering a name -- be it on-chain or
off-chain.  To register an on-chain name, the user must send two transactions to
Blockstack's underlying blockchain (currently Bitcoin) that implement the
`NAME_PREORDER` and `NAME_REGISTRATION` commands.  Details on the wire formats
for these transactions can be found in Appendix A.  Blockstack supplies both a
[graphical tool](https://github.com/blockstack/blockstack-browser) and a
[command-line tool](https://github.com/blockstackl/cli-blockstack) for
generating and broadcasting these transactions, as well as a 
[reference library](https://github.com/blockstack/blockstack.js).

To register an off-chain name, the user must be able to submit a request to an
off-chain registrar.  Anyone with an on-chain name can use it to operate a
registrar for off-chain names.  A reference implementation can be found
[here](https://github.com/blockstack/subdomain-registrar).

To register an off-chain DID, the user
must submit a JSON body as a HTTP POST request to the registrar's
registration endpoint with the following format:

```
{
   "zonefile": "<zonefile encoding the location of the DDO>",
   "name": "<off-chain name, excluding the on-chain suffix>",
   "owner_address": "<b58check-encoded address that will own the name, with version byte \x00>",
}
```

For example, to register the name `spqr` on a registrar for `res_publica.id`:

```bash
$ curl -X POST -H 'Authorization: bearer API-KEY-IF-USED' -H 'Content-Type: application/json' \
> --data '{"zonefile": "$ORIGIN spqr\n$TTL 3600\n_https._tcp URI 10 1 \"https://gaia.blockstack.org/hub/1HgW81v6MxGD76UwNbHXBi6Zre2fK8TwNi/profile.json\"\n", \
>          "name": "spqr", \
>          "owner_address": "1HgW81v6MxGD76UwNbHXBi6Zre2fK8TwNi"}' \
> http://localhost:3000/register/
```

The `zonefile` field must be a well-formed DNS zonefile, and must have the
following properties:

* It must have its `$ORIGIN` field set to the off-chain name.
* It must have at least one `URI` resource record that encodes an HTTP or
  HTTPS URL.  Note that its name must be either `_http._tcp` or `_https._tcp`, per the
`URI` record specification.
* The HTTP or HTTPS URL must resolve to a JSON Web token signed by a secp256k1 public key
  that hashes to the `owner_address` field, per section 2.1.

Once the request is accepted, the registrar will issue a subsequent `NAME_UPDATE`
transaction for its on-chain name and broadcast the batch of off-chain zone
files it has accumulated to the Blockstack Atlas network (see Appendix A).  The batch
of off-chain names' zone files will be hashed, and the hash will be written to
the blockchain as part of the `NAME_UPDATE`.  This proves the existence of these
off-chain names, as well as their corresponding DIDs.

Once the transaction confirms and the off-chain zone files are propagated to the
peer network, any Blockstack node will be able to resolve the off-chain name's associated DID.

## 3.2  Storing a Blockstack DID's DDO

Each name in Blockstack, and by extention, each DID, must have one or more
associated URLs.  To resolve a DID (section 3.3), the DID's URLs must point to
a well-formed signed DDO.  It is up to the DID owner to sign and upload the DDO
to the relevant location(s) so that DID resolution works as expected, and it is
up to the DID owner to ensure that the DDO is well-formed.  Resolvers should
validate DDOs before returning them to clients.

In order for a DID to resolve to a DDO, the DDO must be encoded as a JSON web
token, and must be signed by the secp256k1 private key whose public key hashes
to the DID's address.  This is used by the DID resolver to authenticate the DDO,
thereby removing the need to trust the server(s) hosting the DDO with replying
authentic data.

## 3.3  Resolving a Blockstack DID

Any Blockstack node with an up-to-date view of the underlying blockchain and a
complete set of off-chain zone files can translate any name into its DID, and
translate any DID into its name.

Since DID registration in Blockstack is achieved by first registering a name,
the user must first determine the DID's NSI.  To do so, the user simply requests
it from a Blockstack node of their choice as a GET request to the node's
`/v1/dids/{:blockstack_did}` endpoint.  The response must be a JSON object with
a `public_key` field containing the secp256k1 public key that hashes to the
DID's address, and a `document` field containing the DDO.  The DDO's `publicKey` field
shall be an array of objects with one element, where the 
only element describes the `public_key` given in the top-level object.

For example:

```bash
$ curl -s https://core.blockstack.org/v1/dids/did:stack:v0:15gxXgJyT5tM5A4Cbx99nwccynHYsBouzr-0 | jq
{
   'public_key': '022af593b4449b37899b34244448726aa30e9de13c518f6184a29df40823d82840', 
   'document': { 
      ...
      '@context': 'https://w3id.org/did/v1', 
      'publicKey': [
         {
            'id': 'did:stack:v0:15gxXgJyT5tM5A4Cbx99nwccynHYsBouzr-0', 
            'type': 'secp256k1',
            'publicKeyHex': '022af593b4449b37899b34244448726aa30e9de13c518f6184a29df40823d82840'
         }
      ],
      ...
   }
}
```

## 3.4 Updating a Blockstack DID

The user can change their DDO at any time by uploading a new signed DDO to the
relevant locations, per section 3.2, *except for* the `publicKey` field.  In
order to change the DID's public key, the user must transfer the underlying name
to a new address.

If the DID corresponds to an on-chain name, then the user must send a
`NAME_TRANSFER` transaction to send the name to the new address.  Once the
transaction is confirmed by the Blockstack network, the DID's public key will be
updated.  See Appendix A for the `NAME_TRANSFER` wire format.  Blockstack
provides a [reference library](https://github.com/blockstack/blockstack.js) for
generating this transaction.

### 3.4.1 Off-Chain DID Updates

If the DID corresponds to an off-chain name, then the user must request that the
registrar that instantiated the name to broadcast an off-chain name transfer
operation.  To do so, the user must submit a string with the following format to
the registrar:

```
${name} TXT "owner=${new_address}" "seqn=${update_counter}" "parts=${length_of_zonefile_base64}" "zf0=${base64_part_0}" "zf1=${base64_part_1}" ... "sig=${base64_signature}"
```

The string is a well-formed DNS TXT record with the following fields:

* The `${name}` field is the subdomain name without the on-chain suffix (e.g.
  `spqr` in `spqr.res_publica.id`.
* The `${new_address}` field is the new owner address of the subdomain name.
* The `${update_counter}` field is a non-negative integer equal to the number of
  subdomain name operations that have occurred so far.  It starts with 0 when
the name is created, and must increment each time the name owner issues an
off-chain name operation.
* The `${length_of_zonefile_base64}` field is equal to the length of the
  base64-encoded zone file for the off-chain name.
* The fields `zf0`, `zf1`, `zf2`, etc. and their corresponding variables
  `${base64_part_0}`, `${base64_part_1}`, `${base64_part_2}`, etc. correspond to
256-byte segments of the base64-encoded zone file.  They must occur in a
sequence of `zf${n}` where `${n}` starts at 0 and increments by 1 until all
segments of the zone file are represented.
* The `${base64_signature}` field is a secp256k1 signature over the resulting
  string, up to the `sig=` field, and base64-encoded.  The signature must come
from the secp256k1 private key that currently owns the name.

Thus to generate this TXT record for their DID, the user would do the following:

1. Base64-encode the off-chain DID's zone file.
2. Break the base64-encoded zone file into 256-byte segments.
3. Assemble the TXT record from the name, new address, update counter, and zone
   file segments.
4. Sign the resulting string with the DID's current private key.
5. Generate and append the `sig=${base64_signature}` field to the TXT record.

Sample code to generate these TXT records can be found in the [Blockstack Core
reference implementation](https://github.com/blockstack/blockstack-core), under
the `blockstack.lib.subdomains` package.  For example, the Python 2 program here
generates such a TXT record:

```python
import blockstack

offchain_name = 'bar'
onchain_name = 'foo.test'
new_address = '1Jq3x8BAYz9Xy9AMfur5PXkDsWtmBBsNnC'
seqn = 1
privk = 'da1182302fee950e64241a4103646992b1bed7f6c4ced858282e493d57df33a501'
full_name = '{}.{}'.format(offchain_name, onchain_name)
zonefile = "$ORIGIN {}\n$TTL 3600\n_http._tcp\tIN\tURI\t10\t1\t\"https://gaia.blockstack.org/hub/{}/profile.json\"\n\n".format(offchain_name, new_address)

print blockstack.lib.subdomains.make_subdomain_txt(full_name, onchain_name, new_address, seqn, zonefile, privk)
```

The program prints a string such as:
```
bar TXT "owner=1Jq3x8BAYz9Xy9AMfur5PXkDsWtmBBsNnC" "seqn=1" "parts=1" "zf0=JE9SSUdJTiBiYXIKJFRUTCAzNjAwCl9odHRwLl90Y3AJSU4JVVJJCTEwCTEJImh0dHBzOi8vZ2FpYS5ibG9ja3N0YWNrLm9yZy9odWIvMUpxM3g4QkFZejlYeTlBTWZ1cjVQWGtEc1d0bUJCc05uQy9wcm9maWxlLmpzb24iCgo\=" "sig=QEA+88Nh6pqkXI9x3UhjIepiWEOsnO+u1bOBgqy+YyjrYIEfbYc2Q8YUY2n8sIQUPEO2wRC39bHQHAw+amxzJfkhAxcC/fZ0kYIoRlh2xPLnYkLsa5k2fCtXqkJAtsAttt/V"
```

(Note that the `sig=` field will differ between invocations, due to the way
ECDSA signatures work).

Once this TXT record has been submitted to the name's original registrar, the
registrar will pack it along with other such records into a single zone file,
and issue a `NAME_UPDATE` transaction for the on-chain name to announce them to
the rest of the peer network.  The registrar will then propagate these TXT
records to the peer network once the transaction confirms, thereby informing all
Blockstack nodes of the new state of the off-chain DID.

### 3.4.2 Changing the Storage Locations of a DDO

If the user wants to change where the resolver will look for a DDO, they must do
one of two things.  If the DID corresponds to an on-chain name, then the user
must send a `NAME_UPDATE` transaction for the underlying name, whose 20-byte
hash field is the RIPEMD160 hash of the name's new zone file.  See Appendix A
for the wire format of `NAME_UPDATE` transactions.

If the DID corresponds to an off-chain name, then the user must submit a request
to an off-chain name registrar to propagate a new zone file for the name.
Unlike changing the public key, the user can ask *any* off-chain registrar to
broadcast a new zone file.  The method for doing this is described in section
3.4.1 -- the user simply changes the zone file contents instead of the address.

# 4. Deleting a Blockstack DID

If the user wants to delete their DID, they can do so by revoking the underlying
name.  To do this with an on-chain name, the user constructs and broadcasts a
`NAME_REVOKE` transaction.  Once confirmed, the DID will stop resolving.

To do this with an off-chain name, the user constructs and broadcasts a TXT
record for their DID's underlying name that (1) changes the owner address to a
"nothing-up-my-sleeve" address (such as `1111111111111111111114oLvT2` -- the
base58-check encoding of 20 bytes of 0's), and (2) changes the zone file to
include an unresolvable URL.  This prevents the DID from resolving, and prevents
it from being updated.

# 5. Security Considerations

This section briefly outlines possible ways to attack Blockstack's DID method,
as well as countermeasures the Blockstack protocol and the user can take to
defend against them.

## 5.1 Public Blockchain Attacks

Blockstack operates on top of a public blockchain, which could be attacked by a
sufficiently pwowerful adversary -- such as rolling back and changing the chain's
transaction history, denying new transactions for Blockstack's name
operations, or eclipsing nodes.

Blockstack makes the first two attacks difficult by operating on top of the most
secure blockchain -- currently Bitcoin.  If the blockchain is attacked, or a
stronger blockchain comes into being, the Blockstack community would migrate the
Blockstack network to a new blockchain.

The underlying blockchain provides some immunity towards eclipse attacks, since a
blockchain peer expects blocks to arrive at roughly fixed intervals and expects
blocks to have a proof of an expenditure of an expensive resource (like
electricity).  In Bitcoin's case, the computational difficulty of finding new blocks puts a
high lower bound on the computational effort required to eclipse a Bitcoin node --
in order to sustain 10-minute block times, the attacker must expend an equal
amount of energy as the rest of the network.  Moreover, the required expenditure
rate (the "chain difficulty") decreases slowly enough that an attacker with less
energy would have to spend months of time on the attack, giving the victim
ample time to detect it.  The countermeasures the blockchain employs to deter
eclipse attacks are beyond the scope of this document, but it is worth pointing
out that Blockstack's DID method benefits from them since they also help ensure
that DID creation, updates and deletions get processed in a timely manner.

## 5.2 Blockstack Peer Network Attacks

Because Blockstack stores each DID's DDO's URL in its own peer network outside
of its underlying blockchain, it is possible to eclipse Blockstack nodes and
prevent them from seeing both off-chain DID operations and updates to on-chain
DIDs.  In an effort to make this as difficult as possible, the
Blockstack peer network implements an unstructured overlay network -- nodes select
a random sample of the peer graph as their neighbors.  Moreover, Blockstack
nodes strive to fetch a full replica of all zone files, and pull zone files from
their neighbors in rarest-first order to prevent zone files from getting lost
while they are propagating.  This makes eclipsing a node
maximally difficult -- an attacker would need to disrupt all of a the victim
node's neighbor links.

In addition to this protocol-level countermeasure, a user has the option of
uploading zone files manually to their preferred Blockstack nodes.  If 
vigilent users have access to a replica of the zone files, they can re-seed
Blockstack nodes that do not have them.

## 5.3 Stale Data and Replay Attacks

A DID's DDO is stored on a 3rd party storage provider.  The DDO's public key is
anchored to the blockchain, which means each time the DDO public key changes,
all previous DDOs are invalidated.  Similarly, the DDO's storage provider URLs
are anchored to the blockchain, which means each time the DID's zone file
changes, any stale DDOs will no longer be fetched.  However, if the user changes
other fields of their DDO, a malicious storage provider or a network adversary
can serve a stale but otherwise valid DDO and the resolver will accept it.

The user has a choice of which storage providers host their DDO.  If the storage
provider serves stale data, the user can and should change their storage
provider to one that will serve only fresh data.  In addition, the user should
use secure transport protocols like HTTPS to make replay attacks on the network
difficult.  For use cases where these are not sufficient to prevent replay
attacks, the user should change their zone file and/or public key each time they
change their DDO.

# 6. Privacy Considerations

Blockstack's DIDs are underpinned by Blockstack IDs (human readable
names), and every Blockstack node records where every DID's DDO is
hosted.  However, users have the option of encrypting their DDOs so that only a
select set of other users can decrypt them.

Blockstack's peer network and DID resolver use HTTP(S), meaning that
intermediate middleboxes like CDNs and firewalls can cache data and log
requests.

# 7.  Reference Implementations

Blockstack implements a [RESTful API](https://core.blockstack.org) for querying
DIDs.  It also implements a [reference
library](https://github.com/blockstack/blockstack.js) for generating well-formed
on-chain transactions, and it implements a [Python
library](https://github.com/blockstack/blockstack/core/blob/master/blockstack/lib/subdomains.py)
for generating off-chain DID operations.  The Blockstack node [reference
implementation](https://github.com/blockstack/blockstack-core) is available
under the terms of the General Public Licence, version 3.

# 8.  Resources

Many Blockstack developers communicate via the [Blockstack
Forum](https://forum.blockstack.org) and via the [Blockstack
Slack](https://blockstack.slack.com).  Interested developers are encouraged to
join both.

# Appendix A: On-chain Wire Formats

This section is for organizations who want to be able to create and send name operation
transactions to the blockchain(s) Blockstack supports.
It describes the transaction formats for the Bitcoin blockchain.

Only the transactions that affect DID creation, updates, resolution, and
deletions are documented here.  A full listing of all Blockstack transaction
formats can be found
[here](https://github.com/blockstack/blockstack-core/blob/master/docs/wire-format.md).

## Transaction format

Each Bitcoin transaction for Blockstack contains signatures from two sets of keys: the name owner, and the payer.  The owner `scriptSig` and `scriptPubKey` fields are generated from the key(s) that own the given name.  The payer `scriptSig` and `scriptPubKey` fields are used to *subsidize* the operation.  The owner keys do not pay for any operations; the owner keys only control the minimum amount of BTC required to make the transaction standard.  The payer keys only pay for the transaction's fees, and (when required) they pay the name fee.

This construction is meant to allow the payer to be wholly separate from the owner.  The principal that owns the name can fund their own transactions, or they can create a signed transaction that carries out the desired operation and request some other principal (e.g. a parent organization) to actually pay for and broadcast the transaction.

The general transaction layout is as follows:

| **Inputs**               | **Outputs**            |
| ------------------------ | ----------------------- |
| Owner scriptSig (1)      | `OP_RETURN <payload>` (2)  |
| Payment scriptSig        | Owner scriptPubKey (3) |
| Payment scriptSig... (4) |
| ...                  (4) | ... (5)                |

(1) The owner `scriptSig` is *always* the first input.
(2) The `OP_RETURN` script that describes the name operation is *always* the first output.
(3) The owner `scriptPubKey` is *always* the second output.
(4) The payer can use as many payment inputs as (s)he likes.
(5) At most one output will be the "change" `scriptPubKey` for the payer.
Different operations require different outputs.

## Payload Format

Each Blockstack transaction in Bitcoin describes the name operation within an `OP_RETURN` output.  It encodes name ownership, name fees, and payments as `scriptPubKey` outputs.  The specific operations are described below.

Each `OP_RETURN` payload *always* starts with the two-byte string `id` (called the "magic" bytes in this document), followed by a one-byte `op` that describes the operation.

### NAME_PREORDER

Op: `?`

Description:  This transaction commits to the *hash* of a name.  It is the first
transaction of two transactions that must be sent to register a name in BNS.

Example: [6730ae09574d5935ffabe3dd63a9341ea54fafae62fde36c27738e9ee9c4e889](https://www.blocktrail.com/BTC/tx/6730ae09574d5935ffabe3dd63a9341ea54fafae62fde36c27738e9ee9c4e889)

`OP_RETURN` wire format:
```
    0     2  3                                                  23             39
    |-----|--|--------------------------------------------------|--------------|
    magic op  hash_name(name.ns_id,script_pubkey,register_addr)   consensus hash
```

Inputs:
* Payment `scriptSig`'s

Outputs:
* `OP_RETURN` payload
* Payment `scriptPubkey` script for change
* `p2pkh` `scriptPubkey` to the burn address (0x00000000000000000000000000000000000000)

Notes:
* `register_addr` is a base58check-encoded `ripemd160(sha256(pubkey))` (i.e. an address).  This address **must not** have been used before in the underlying blockchain.
* `script_pubkey` is either a `p2pkh` or `p2sh` compiled Bitcoin script for the payer's address.

### NAME_REGISTRATION

Op: `:`

Description:  This transaction reveals the name whose hash was announced by a
previous `NAME_PREORDER`.  It is the second of two transactions that must be
sent to register a name in BNS.

When this transaction confirms, the corresponding Blockstack DID will be
instantiated.  It's address will be the owner address in this transaction, and
its index will be equal to the number of names registered to this address previously.

Example: [55b8b42fc3e3d23cbc0f07d38edae6a451dfc512b770fd7903725f9e465b2925](https://www.blocktrail.com/BTC/tx/55b8b42fc3e3d23cbc0f07d38edae6a451dfc512b770fd7903725f9e465b2925)

`OP_RETURN` wire format (2 variations allowed):

Variation 1:
```
    0    2  3                             39
    |----|--|-----------------------------|
    magic op   name.ns_id (37 bytes)
```

Variation 2:
```
    0    2  3                                  39                  59
    |----|--|----------------------------------|-------------------|
    magic op   name.ns_id (37 bytes, 0-padded)       value
```

Inputs:
* Payer `scriptSig`'s

Outputs:
* `OP_RETURN` payload
* `scriptPubkey` for the owner's address
* `scriptPubkey` for the payer's change

Notes:

* Variation 1 simply registers the name.  Variation 2 will register the name and
set a name value simultaneously.  This is used in practice to set a zone file
hash for a name without the extra `NAME_UPDATE` transaction.
* Both variations are supported.  Variation 1 was designed for the time when
  Bitcoin only supported 40-byte `OP_RETURN` outputs.

### NAME_RENEWAL

Op: `:`

Description:  This transaction renews a name in BNS.  The name must still be
registered and not expired, and owned by the transaction sender.

Depending on which namespace the name was created in, you may never need to
renew a name.  However, in namespaces where names expire (such as `.id`), you
will need to renew your name periodically to continue using its associated DID.
If this is a problem, we recommend creating a name in a namespace without name
expirations, so that `NAME_UPDATE`, `NAME_TRANSFER` and `NAME_REVOKE` -- the operations that
underpin the DID's operations -- will work indefinitely.

Example: [e543211b18e5d29fd3de7c0242cb017115f6a22ad5c6d51cf39e2b87447b7e65](https://www.blocktrail.com/BTC/tx/e543211b18e5d29fd3de7c0242cb017115f6a22ad5c6d51cf39e2b87447b7e65)

`OP_RETURN` wire format (2 variations allowed):

Variation 1:
```
    0    2  3                             39
    |----|--|-----------------------------|
    magic op   name.ns_id (37 bytes)
```

Variation 2:
```
    0    2  3                                  39                  59
    |----|--|----------------------------------|-------------------|
    magic op   name.ns_id (37 bytes, 0-padded)       value
```

Inputs:

* Payer `scriptSig`'s

Outputs:

* `OP_RETURN` payload
* `scriptPubkey` for the owner's addess.  This can be a different address than
  the current name owner (in which case, the name is renewed and transferred).
* `scriptPubkey` for the payer's change
* `scriptPubkey` for the burn address (to pay the name cost)

Notes:

* This transaction is identical to a `NAME_REGISTRATION`, except for the presence of the fourth output that pays for the name cost (to the burn address).
* Variation 1 simply renews the name.  Variation 2 will both renew the name and
  set a new name value (in practice, the hash of a new zone file).
* Both variations are supported.  Variation 1 was designed for the time when
  Bitcoin only supported 40-byte `OP_RETURN` outputs.
* This operation can be used to transfer a name to a new address by setting the
  second output (the first `scriptPubkey`) to be the `scriptPubkey` of the new
  owner key.

### NAME_UPDATE

Op: `+`

Description:  This transaction sets the name state for a name to the given
`value`.  In practice, this is used to announce new DNS zone file hashes to the [Atlas
network](https://docs.blockstack.org/core/atlas/overview.html), and in doing so,
change where the name's off-chain state resides.  In DID terminology, this
operation changes where the authoritative replica of the DID's DDO will be
retrieved on the DID's lookup.

Example: [e2029990fa75e9fc642f149dad196ac6b64b9c4a6db254f23a580b7508fc34d7](https://www.blocktrail.com/BTC/tx/e2029990fa75e9fc642f149dad196ac6b64b9c4a6db254f23a580b7508fc34d7)

`OP_RETURN` wire format:
```
    0     2  3                                   19                      39
    |-----|--|-----------------------------------|-----------------------|
    magic op  hash128(name.ns_id,consensus hash)      zone file hash
```

Note that `hash128(name.ns_id, consensus hash)` is the first 16 bytes of a SHA256 hash over the name concatenated to the hexadecimal string of the consensus hash (not the bytes corresponding to that hex string).
See the [Method Glossary](#method-glossary) below.

Example: `hash128("jude.id" + "8d8762c37d82360b84cf4d87f32f7754") == "d1062edb9ec9c85ad1aca6d37f2f5793"`.

The 20 byte zone file hash is computed from zone file data by using `ripemd160(sha56(zone file data))`

Inputs:
* owner `scriptSig`
* payment `scriptSig`'s

Outputs:
* `OP_RETURN` payload
* owner's `scriptPubkey`
* payment `scriptPubkey` change

### NAME_TRANSFER

Op: `>`

Description:  This transaction changes the public key hash that owns the name in
BNS.  When the name or its DID is looked up after this transaction confirms, the
resolver will list the new public key as the owner.

Example: [7a0a3bb7d39b89c3638abc369c85b5c028d0a55d7804ba1953ff19b0125f3c24](https://www.blocktrail.com/BTC/tx/7a0a3bb7d39b89c3638abc369c85b5c028d0a55d7804ba1953ff19b0125f3c24)

`OP_RETURN` wire format:
```
    0     2  3    4                   20              36
    |-----|--|----|-------------------|---------------|
    magic op keep  hash128(name.ns_id) consensus hash
             data?
```

Inputs:

* Owner `scriptSig`
* Payment `scriptSig`'s

Outputs:

* `OP_RETURN` payload
* new name owner's `scriptPubkey`
* old name owner's `scriptPubkey`
* payment `scriptPubkey` change

Notes:

* The `keep data?` byte controls whether or not the name's 20-byte value is preserved (i.e. whether or not the name's associated zone file is preserved across the transfer).
This value is either `>` to preserve it, or `~` to delete it.  If you're simply
re-keying, you should use `>`.  You should only use `~` if you want to
simultaneously dissociate the name (and its DID) from its off-chain state, like
the DID's DDO.

### NAME_REVOKE

Op: `~`

Description:  This transaction destroys a registered name.  Its name state value
in BNS will be cleared, and no further transactions will be able to affect the
name until it expires (if its namespace allows it to expire at all).  Once
confirmed, this transaction ensures that neither the name nor the DID will
resolve to a DDO.

Example: [eb2e84a45cf411e528185a98cd5fb45ed349843a83d39fd4dff2de47adad8c8f](https://www.blocktrail.com/BTC/tx/eb2e84a45cf411e528185a98cd5fb45ed349843a83d39fd4dff2de47adad8c8f)

`OP_RETURN` wire format:
```
    0    2  3                             39
    |----|--|-----------------------------|
    magic op   name.ns_id (37 bytes)
```

Inputs:

* owner `scriptSig`
* payment `scriptSig`'s

Outputs:

* `OP_RETURN` payload
* owner `scriptPubkey`
* payment `scriptPubkey` change

## Method Glossary

Some hashing primitives are used to construct the wire-format representation of each name operation.  They are enumerated here:

```
B40_REGEX = '^[a-z0-9\-_.+]*$'

def is_b40(s):
    return isinstance(s, str) and re.match(B40_REGEX, s) is not None

def b40_to_bin(s):
    if not is_b40(s):
        raise ValueError('{} must only contain characters in the b40 char set'.format(s))
    return unhexlify(charset_to_hex(s, B40_CHARS))

def hexpad(x):
    return ('0' * (len(x) % 2)) + x

def charset_to_hex(s, original_charset):
    return hexpad(change_charset(s, original_charset, B16_CHARS))

def bin_hash160(s, hex_format=False):
    """ s is in hex or binary format
    """
    if hex_format and is_hex(s):
        s = unhexlify(s)
    return hashlib.new('ripemd160', bin_sha256(s)).digest()

def hex_hash160(s, hex_format=False):
    """ s is in hex or binary format
    """
    if hex_format and is_hex(s):
        s = unhexlify(s)
    return hexlify(bin_hash160(s))

def hash_name(name, script_pubkey, register_addr=None):
    """
    Generate the hash over a name and hex-string script pubkey.
    Returns the hex-encoded string RIPEMD160(SHA256(x)), where
    x is the byte string composed of the concatenation of the
    binary
    """
    bin_name = b40_to_bin(name)
    name_and_pubkey = bin_name + unhexlify(script_pubkey)

    if register_addr is not None:
        name_and_pubkey += str(register_addr)

    # make hex-encoded hash
    return hex_hash160(name_and_pubkey)

def hash128(data):
    """
    Hash a string of data by taking its 256-bit sha256 and truncating it to the
    first 16 bytes
    """
    return hexlify(bin_sha256(data)[0:16])
```

