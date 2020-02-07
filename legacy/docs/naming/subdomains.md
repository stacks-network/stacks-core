---
layout: core
permalink: /:collection/:path.html
---
# BNS Subdomains

{:.no_toc}

This section explains BNS subdomains and provides instructions for methods
you can use to work with them. The following topics are included:

* TOC
{:toc}

# Overview of subdomains

BNS names are strongly-owned because the owner of its private key can generate
valid transactions that update its zone file hash and owner.  However, this comes at the
cost of requiring a name owner to pay for the underlying transaction in the
blockchain.  Moreover, this approach limits the rate of BNS name registrations
and operations to the underlying blockchain's transaction bandwidth.

BNS overcomes this with subdomains.  A **BNS subdomain** is a type of BNS name whose state
and owner are stored outside of the blockchain, but whose existence and
operation history are anchored to the
blockchain.  In the example table in the [Resolving BNS
Names](#resolving-bns-names) section, the names `cicero.res_publica.id` and
`podsaveamerica.verified.podcast` are subdomains.

Like their on-chain counterparts, subdomains are globally
unique, strongly-owned, and human-readable.  BNS gives them their own name state
and public keys.

Unlike on-chain names, subdomains can be created and managed
cheaply, because they are broadcast to the
BNS network in batches.  A single blockchain transaction can send up to 120
subdomain operations.

This is achieved by storing subdomain records in the [Atlas Network]({{ site.baseurl }}/core/atlas/overview.html).
An on-chain name owner broadcasts subdomain operations by encoding them as
`TXT` records within a DNS zone file.  To broadcast the zone file,
the name owner sets the new zone file hash with a `NAME_UPDATE` transaction and
replicates the zone file via Atlas.  This, in turn, replicates all subdomain
operations it contains, and anchors the set of subdomain operations to
an on-chain transaction.  The BNS node's consensus rules ensure that only
valid subdomain operations from *valid* `NAME_UPDATE` transactions will ever be
stored.

For example, the name `verified.podcast` once wrote the zone file hash `247121450ca0e9af45e85a82e61cd525cd7ba023`,
which is the hash of the following zone file:

```bash
$ curl -sL https://core.blockstack.org/v1/names/verified.podcast/zonefile/247121450ca0e9af45e85a82e61cd525cd7ba023 | jq -r '.zonefile'
$ORIGIN verified.podcast
$TTL 3600
1yeardaily TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAxeWVhcmRhaWx5CiRUVEwgMzYwMApfaHR0cC5fdGNwIFVSSSAxMCAxICJodHRwczovL3BoLmRvdHBvZGNhc3QuY28vMXllYXJkYWlseS9oZWFkLmpzb24iCg=="
2dopequeens TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAyZG9wZXF1ZWVucwokVFRMIDM2MDAKX2h0dHAuX3RjcCBVUkkgMTAgMSAiaHR0cHM6Ly9waC5kb3Rwb2RjYXN0LmNvLzJkb3BlcXVlZW5zL2hlYWQuanNvbiIK"
10happier TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAxMGhhcHBpZXIKJFRUTCAzNjAwCl9odHRwLl90Y3AgVVJJIDEwIDEgImh0dHBzOi8vcGguZG90cG9kY2FzdC5jby8xMGhhcHBpZXIvaGVhZC5qc29uIgo="
31thoughts TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAzMXRob3VnaHRzCiRUVEwgMzYwMApfaHR0cC5fdGNwIFVSSSAxMCAxICJodHRwczovL3BoLmRvdHBvZGNhc3QuY28vMzF0aG91Z2h0cy9oZWFkLmpzb24iCg=="
359 TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAzNTkKJFRUTCAzNjAwCl9odHRwLl90Y3AgVVJJIDEwIDEgImh0dHBzOi8vcGguZG90cG9kY2FzdC5jby8zNTkvaGVhZC5qc29uIgo="
30for30 TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAzMGZvcjMwCiRUVEwgMzYwMApfaHR0cC5fdGNwIFVSSSAxMCAxICJodHRwczovL3BoLmRvdHBvZGNhc3QuY28vMzBmb3IzMC9oZWFkLmpzb24iCg=="
onea TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiBvbmVhCiRUVEwgMzYwMApfaHR0cC5fdGNwIFVSSSAxMCAxICJodHRwczovL3BoLmRvdHBvZGNhc3QuY28vb25lYS9oZWFkLmpzb24iCg=="
10minuteteacher TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAxMG1pbnV0ZXRlYWNoZXIKJFRUTCAzNjAwCl9odHRwLl90Y3AgVVJJIDEwIDEgImh0dHBzOi8vcGguZG90cG9kY2FzdC5jby8xMG1pbnV0ZXRlYWNoZXIvaGVhZC5qc29uIgo="
36questionsthepodcastmusical TXT "owner=1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH" "seqn=0" "parts=1" "zf0=JE9SSUdJTiAzNnF1ZXN0aW9uc3RoZXBvZGNhc3RtdXNpY2FsCiRUVEwgMzYwMApfaHR0cC5fdGNwIFVSSSAxMCAxICJodHRwczovL3BoLmRvdHBvZGNhc3QuY28vMzZxdWVzdGlvbnN0aGVwb2RjYXN0bXVzaWNhbC9oZWFkLmpzb24iCg=="
_http._tcp URI 10 1 "https://dotpodcast.co/"
```

Each `TXT` record in this zone file encodes a subdomain-creation.
For example, `1yeardaily.verified.podcast` resolves to:

```bash
$ curl https://core.blockstack.org/v1/names/1yeardaily.verified.podcast
{
  "address": "1MwPD6dH4fE3gQ9mCov81L1DEQWT7E85qH",
  "blockchain": "bitcoin",
  "last_txid": "d87a22ebab3455b7399bfef8a41791935f94bc97aee55967edd5a87f22cce339",
  "status": "registered_subdomain",
  "zonefile_hash": "e7acc97fd42c48ed94fd4d41f674eddbee5557e3",
  "zonefile_txt": "$ORIGIN 1yeardaily\n$TTL 3600\n_http._tcp URI 10 1 \"https://ph.dotpodcast.co/1yeardaily/head.json\"\n"
}
```

This information was extracted from the `1yeardaily` `TXT` resource record in the zone
file for `verified.podcast`.

## Subdomain Lifecycle

Note that `1yeardaily.verified.podcast` has a different public key
hash (address) than `verified.podcast`.  A BNS node will only process a
subsequent subdomain operation on `1yeardaily.verified.podcast` if it includes a
signature from this address's private key.  `verified.podcast` cannot generate
updates; only the owner of `1yeardaily.verified.podcast can do so`.

The lifecycle of a subdomain and its operations is shown in Figure 2.

```
   subdomain                  subdomain                  subdomain
   creation                   update                     transfer
+----------------+         +----------------+         +----------------+
| cicero         |         | cicero         |         | cicero         |
| owner="1Et..." | signed  | owner="1Et..." | signed  | owner="1cJ..." |
| zf0="7e4..."   |<--------| zf0="111..."   |<--------| zf0="111..."   |<---- ...
| seqn=0         |         | seqn=1         |         | seqn=2         |
|                |         | sig="xxxx"     |         | sig="xxxx"     |
+----------------+         +----------------+         +----------------+
        |                          |                          |
        |        off-chain         |                          |
~ ~ ~ ~ | ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~|~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ | ~ ~ ~ ~ ~ ~ ~ ...
        |         on-chain         |                          |
        V                          V (zone file hash    )     V
+----------------+         +----------------+         +----------------+
| res_publica.id |         |    jude.id     |         | res_publica.id |
|  NAME_UPDATE   |<--------|  NAME_UPDATE   |<--------|  NAME_UPDATE   |<---- ...
+----------------+         +----------------+         +----------------+
   blockchain                 blockchain                 blockchain
   block                      block                      block


Figure 2:  Subdomain lifetime with respect to on-chain name operations.  A new
subdomain operation will only be accepted if it has a later "sequence=" number,
and a valid signature in "sig=" over the transaction body.  The "sig=" field
includes both the public key and signature, and the public key must hash to
the previous subdomain operation's "addr=" field.

Thesubdomain-creation and subdomain-transfer transactions for
"cicero.res_publica.id" are broadcast by the owner of "res_publica.id".
However, any on-chain name ("jude.id" in this case) can broadcast a subdomain
update for "cicero.res_publica.id".
```

Subdomain operations are ordered by sequence number, starting at 0.  Each new
subdomain operation must include:

* The next sequence number
* The public key that hashes to the previous subdomain transaction's address
* A signature from the corresponding private key over the entire subdomain
  operation.

If two correctly-signed but conflicting subdomain operations are discovered
(i.e. they have the same sequence number), the one that occurs earlier in the
blockchain's history is accepted.  Invalid subdomain operations are ignored.

Combined, this ensures that a BNS node with all of the zone files with a given
subdomain's operations will be able to determine the valid sequence of
state-transitions it has undergone, and determine the current zone file and public
key hash for the subdomain.

## Resolving Subdomains

Developers interact with subdomains the same way they interact with names.
Using the BNS API, a developer can:

### Look up a subdomain's public key and zone file ([reference](https://core.blockstack.org/#name-querying-get-name-info))

```bash
$ curl https://core.blockstack.org/v1/names/aaron.personal.id
{
  "address": "1PwztPFd1s2STMv4Ntq6UPBdYgHSBr5pdF",
  "blockchain": "bitcoin",
  "last_txid": "85e8273b0a38d3e9f0af7b4b72faf0907de9f4616afc101caac13e7bbc832394",
  "status": "registered_subdomain",
  "zonefile_hash": "a6dda6b74ffecf85f4a162627d8df59577243813",
  "zonefile_txt": "$ORIGIN aaron.personal.id\n$TTL 3600\n_https._tcp URI 10 1 \"https://gaia.blockstack.org/hub/1PwztPFd1s2STMv4Ntq6UPBdYgHSBr5pdF/profile.json\"\n"
}
```

### Look up a subdomain's transaction history ([reference](https://core.blockstack.org/#name-querying-name-history))

```bash
$ curl https://core.blockstack.org/v1/names/aaron.personal.id/history
{
  "509981": [
    {
      "address": "1PwztPFd1s2STMv4Ntq6UPBdYgHSBr5pdF",
      "block_number": 509981,
      "domain": "personal.id",
      "name": "aaron.personal.id",
      "sequence": 0,
      "txid": "85e8273b0a38d3e9f0af7b4b72faf0907de9f4616afc101caac13e7bbc832394",
      "value_hash": "a6dda6b74ffecf85f4a162627d8df59577243813",
      "zonefile": "JE9SSUdJTiBhYXJvbi5wZXJzb25hbC5pZAokVFRMIDM2MDAKX2h0dHBzLl90Y3AgVVJJIDEwIDEgImh0dHBzOi8vZ2FpYS5ibG9ja3N0YWNrLm9yZy9odWIvMVB3enRQRmQxczJTVE12NE50cTZVUEJkWWdIU0JyNXBkRi9wcm9maWxlLmpzb24iCg=="
    }
  ]
}
```

### Look up the list of names and subdomains owned by a given public key hash ([reference](https://core.blockstack.org/#name-querying-get-names-owned-by-address))

```bash
$ curl https://core.blockstack.org/v1/addresses/bitcoin/1PwztPFd1s2STMv4Ntq6UPBdYgHSBr5pdF
{
  "names": [
    "aaron.personal.id"
  ]
}
```

## Subdomain Creation and Management

Unlike an on-chain name, a subdomain owner needs an on-chain name owner's help
to broadcast their subdomain operations.  In particular:
* A subdomain-creation transaction can only be processed by the owner of the on-chain
name that shares its suffix.  For example, only the owner of `res_publica.id`
can broadcast subdomain-creation transactions for subdomain names ending in
`.res_publica.id`.
* A subdomain-transfer transaction can only be broadcast by the owner of the
on-chain name that created it.  For example, the owner of
`cicero.res_publica.id` needs the owner of `res_publica.id` to broadcast a
subdomain-transfer transaction to change `cicero.res_publica.id`'s public key.
* In order to send a subdomain-creation or subdomain-transfer, all
  of an on-chain name owner's zone files must be present in the Atlas network.
  This lets the BNS node prove the *absence* of any conflicting subdomain-creation and
subdomain-transfer operations when processing new zone files.
* A subdomain update transaction can be broadcast by *any* on-chain name owner,
  but the subdomain owner needs to find one who will cooperate.  For example,
the owner of `verified.podcast` can broadcast a subdomain-update transaction
created by the owner of `cicero.res_publica.id`.

That said, to create a subdomain, the subdomain owner generates a
subdomain-creation operation for their desired name
and gives it to the on-chain name owner.
The on-chain name owner then uses Atlas to
broadcast it to all other BNS nodes.

Once created, a subdomain owner can use any on-chain name owner to broadcast a
subdomain-update operation.  To do so, they generate and sign the requisite
subdomain operation and give it to an on-chain name owner, who then packages it
with other subdomain operations into a DNS zone file
and sends them all out on the Atlas network.

If the subdomain owner wants to change the address of their subdomain, they need
to sign a subdomain-transfer operation and give it to the on-chain name owner
who created the subdomain.  They then package it into a zone file and broadcast
it.

## Subdomain Registrars

Because subdomain names are cheap, developers may be inclined to run
subdomain registrars on behalf of their applications.  For example,
the name `personal.id` is used to register Blockstack application users without
requiring them to spend any Bitcoin.

We supply a reference
implementation of a [BNS Subdomain Registrar](https://github.com/blockstack/subdomain-registrar)
to help developers broadcast subdomain operations.  Users would still own their
subdomain names; the registrar simply gives developers a convenient way for them
to register and manage them in the context of a particular application.
Please see the [tutorial on running a subdomain registrar]({{ site.baseurl }}/core/naming/tutorial_subdomains.html) for
details on how to use it.
