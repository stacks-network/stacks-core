---
layout: core
permalink: /:collection/:path.html
---
## Resolve a name
{:.no_toc}

This section explains resolving BNS names and provides instructions for methods
you can use to accomplish namespace resolution.

* TOC
{:toc}

## Understand resolution

BNS names are bound to both public keys and to about 40Kb of off-chain state.
The off-chain state is encoded as a [DNS zone file](https://en.wikipedia.org/wiki/Zone_file),
which contains routing information for discovering the user's Blockstack data
(such as their profile and app data, which are hosted in the [Gaia storage
system](https://github.com/blockstack/gaia)).

The blockchain is not used to store this information directly.  Instead, the
blockchain stores the *public key hash* and the *zone file hash*.  When
indexing the blockchain, each BNS node builds a database with
three columns:  all the on-chain BNS names that have been registered, each
name's public key hash, and each name's zone file's hash.
In addition, each BNS node maintains the *transaction history* of each name.
A developer can resolve a name to any configuration it was in at any prior
point in time.

Below is an example name table pulled from a live BNS node:

| Name | Public key hash | Zone File Hash |
|------|-----------------|--------------|
| `ryan.id` | `15BcxePn59Y6mYD2fRLCLCaaHScefqW2No` | `a455954b3e38685e487efa41480beeb315f4ec65` |
| `muneeb.id` | `1J3PUxY5uDShUnHRrMyU6yKtoHEUPhKULs` | `37aecf837c6ae9bdc9dbd98a268f263dacd00361` |
| `jude.id` | `16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg` | `b6e99200125e70d634b17fe61ce55b09881bfafd` |
| `verified.podcast` | `1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH` | `6701ce856620d4f2f57cd23b166089759ef6eabd` |
| `cicero.res_publica.id` | `1EtE77Aa5AA8etzF2irk56vvkS4v7rZ7PE` | `7e4ac75f9d79ba9d5d284fac19617497433b832d` |
| `podsaveamerica.verified.podcast` | `1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH` | `0d6f090db8945aa0e60759f9c866b17645893a95` |

In practice, the zone file hash is the `RIPEMD160` hash of the `SHA256` hash of
the zone file, and the public key is the `base58check`-encoded `RIPEMD160` hash
of the double-`SHA256` hash of the ECDSA public key (i.e. a Bitcoin address).

The BNS consensus rules ensure that
a BNS name can only be registered if it is not already taken, and that only the
user who owns the name's private key can change its public key hash or zone file
hash.  This means that a name's public key and zone file can be stored anywhere,
since they can be authenticated using the hashes discovered by indexing the
blockchain under the BNS consensus rules.

BNS nodes implement a decentralized storage system for zone files called the
[Atlas network]({{ site.baseurl }}/core/atlas/overview.html).  In this system, BNS nodes eagerly replicate
all the zone files they know about to one another, so that eventually every BNS
node has a full replica of all zone files.

The public keys for names are stored off-chain in [Gaia](https://github.com/blockstack/gaia).
The user controls where their public keys are hosted using the zone file
contents (if they are hosted online anywhere at all).

Developers can query this table via the BNS API.  The API offers routes
to do the following:

## Look up a name's public key and zone file ([reference](https://core.blockstack.org/#name-querying-get-name-info))

```bash
$ curl https://core.blockstack.org/v1/names/muneeb.id
{
  "address": "1J3PUxY5uDShUnHRrMyU6yKtoHEUPhKULs",
  "blockchain": "bitcoin",
  "expire_block": 599266,
  "last_txid": "7e16e8688ca0413a398bbaf16ad4b10d3c9439555fc140f58e5ab4e50793c476",
  "status": "registered",
  "zonefile": "$ORIGIN muneeb.id\n$TTL 3600\n_http._tcp URI 10 1 \"https://gaia.blockstack.org/hub/1J3PUxY5uDShUnHRrMyU6yKtoHEUPhKULs/0/profile.json\"\n",
  "zonefile_hash": "37aecf837c6ae9bdc9dbd98a268f263dacd00361"
}
```

Note that the `zonefile` field is given with the off-chain data that hashes
to the `zonefile_hash` field.

## List all names the node knows about ([reference](https://core.blockstack.org/#name-querying-get-all-names))

```bash
$ curl https://core.blockstack.org/v1/names?page=0
[
  "judecn.id",
  "3.id",
  "4.id",
  "8.id",
  "e.id",
  "h.id",
  "5.id",
  "9.id",
  "i.id",
  "l.id",
  "p.id",
  "w.id",
  "ba.id",
  "df.id",
...
]
```

Each page returns 100 names.  While no specific ordering is mandated by the
protocol, the reference implementation orders names by their order of creation
in the blockchain.

## Look up the history of states a name was in ([reference](https://core.blockstack.org/#name-querying-name-history))

```bash
$ curl https://core.blockstack.org/v1/names/patrickstanley.id/history
{
  "445838": [
    {
      "address": "1occgbip7tFDXX9MvzQhcnTUUjcVX2dYK",
      "block_number": 445838,
      "burn_address": "1111111111111111111114oLvT2",
      "consensus_hash": "7b696b6f4060b792d41912068944d73b",
      "op": "?",
      "op_fee": 25000,
      "opcode": "NAME_PREORDER",
      "preorder_hash": "26bf7874706ac761afdd403ed6b3b9578fb01a34",
      "sender": "76a91408d0dd44c1f0a3a4f0957ae95901929d7d66d55788ac",
      "sender_pubkey": "039a8948d339ecbff44cf426cb85d90fce876f1658d385cdc47f007f279be626ea",
      "txid": "6730ae09574d5935ffabe3dd63a9341ea54fafae62fde36c27738e9ee9c4e889",
      "vtxindex": 40
    }
  ],
  "445851": [
    {
      "address": "17CbHgTgBG3kLedXNneEKBkCTgW2fyrnUD",
      "block_number": 445838,
      "consensus_hash": null,
      "first_registered": 445851,
      "importer": null,
      "importer_address": null,
      "last_creation_op": "?",
      "last_renewed": 445851,
      "name": "patrickstanley.id",
      "name_hash128": "683a3e1ee5f0296833c56e481cf41b77",
      "namespace_block_number": 373601,
      "namespace_id": "id",
      "op": ":",
      "op_fee": 25000,
      "opcode": "NAME_REGISTRATION",
      "preorder_block_number": 445838,
      "preorder_hash": "26bf7874706ac761afdd403ed6b3b9578fb01a34",
      "revoked": false,
      "sender": "76a9144401f3be5311585ea519c1cb471a8dc7b02fd6ee88ac",
      "sender_pubkey": "039a8948d339ecbff44cf426cb85d90fce876f1658d385cdc47f007f279be626ea",
      "transfer_send_block_id": null,
      "txid": "55b8b42fc3e3d23cbc0f07d38edae6a451dfc512b770fd7903725f9e465b2925",
      "value_hash": null,
      "vtxindex": 54
    }
  ],
  "445873": [
    {
      "address": "17CbHgTgBG3kLedXNneEKBkCTgW2fyrnUD",
      "block_number": 445838,
      "consensus_hash": "18b8d69f0182b89ccb1aa536f83be18a",
      "first_registered": 445851,
      "importer": null,
      "importer_address": null,
      "last_creation_op": "?",
      "last_renewed": 445851,
      "name": "patrickstanley.id",
      "name_hash128": "683a3e1ee5f0296833c56e481cf41b77",
      "namespace_block_number": 373601,
      "namespace_id": "id",
      "op": "+",
      "op_fee": 25000,
      "opcode": "NAME_UPDATE",
      "preorder_block_number": 445838,
      "preorder_hash": "26bf7874706ac761afdd403ed6b3b9578fb01a34",
      "revoked": false,
      "sender": "76a9144401f3be5311585ea519c1cb471a8dc7b02fd6ee88ac",
      "sender_pubkey": "039a8948d339ecbff44cf426cb85d90fce876f1658d385cdc47f007f279be626ea",
      "transfer_send_block_id": null,
      "txid": "dc478659fc684a1a6e1e09901971e82de11f4dfe2b32a656700bf9a3b6030719",
      "value_hash": "02af0ef21161ad06b0923106f40b994b9e4c1614",
      "vtxindex": 95
    }
  ],
  "445884": [
    {
      "address": "1GZqrVbamkaE6YNveJFWK6cDrCy6bXyS6b",
      "block_number": 445838,
      "consensus_hash": "18b8d69f0182b89ccb1aa536f83be18a",
      "first_registered": 445851,
      "importer": null,
      "importer_address": null,
      "last_creation_op": "?",
      "last_renewed": 445851,
      "name": "patrickstanley.id",
      "name_hash128": "683a3e1ee5f0296833c56e481cf41b77",
      "namespace_block_number": 373601,
      "namespace_id": "id",
      "op": ">>",
      "op_fee": 25000,
      "opcode": "NAME_TRANSFER",
      "preorder_block_number": 445838,
      "preorder_hash": "26bf7874706ac761afdd403ed6b3b9578fb01a34",
      "revoked": false,
      "sender": "76a914aabffa6dd90d731d3a349f009323bb312483c15088ac",
      "sender_pubkey": null,
      "transfer_send_block_id": 445875,
      "txid": "7a0a3bb7d39b89c3638abc369c85b5c028d0a55d7804ba1953ff19b0125f3c24",
      "value_hash": "02af0ef21161ad06b0923106f40b994b9e4c1614",
      "vtxindex": 16
    }
  ]
}
```

All of the above information is extracted from the blockchain.  Each top-level
field encodes the states the name transitioned to at the given block height (e.g.
445838, 445851, 445873, adn 445884).  At each block height, the name's zone file
hashes are returned in the order they were discovered in the blockchain.

Each name state contains a lot of ancillary data that is used internally by
other API calls and client libraries.  The relevant fields for this document's
scope are:

* `address`: This is the base58check-encoded public key hash.
* `name`:  This is the name queried.
* `value_hash`:  This is the zone file hash.
* `opcode`:  This is the type of transaction that was processed.
* `txid`:  This is the transaction ID in the underlying blockchain.

The name's *entire* history is returned.  This includes the history of the name
under its previous owner, if the name expired and was reregistered.

## Look up the list of names owned by a given public key hash ([reference](https://core.blockstack.org/#name-querying-get-names-owned-by-address))

```bash
$ curl https://core.blockstack.org/v1/addresses/bitcoin/16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg
{
  "names": [
    "judecn.id",
    "patrickstanley1.id",
    "abcdefgh123456.id",
    "duckduckgo_tor.id",
    "jude.id",
    "blockstacknewyear2017.id",
    "jude.statism.id"
  ]
}
```

Note that this API endpoint includes names and
[subdomains](#bns-subdomains).
