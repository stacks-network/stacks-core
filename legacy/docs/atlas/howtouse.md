---
layout: core
permalink: /:collection/:path.html
---
# How to Use the Atlas Network
{:.no_toc}

This section teaches you how to use the Atlas network, it contains the
following sections:

* TOC
{:toc}

## The API

While the Blockstack software stack expects that Atlas-hosted data is made up of
DNS zone files, Atlas itself does not enforce this (nor does it care about the
format of its chunks).  It is designed as a general-purpose chunk store.
Nevertheless, the ubiquitous use of Atlas to store data as DNS zone files has
had an influence on its API design---fields and method names frequently allude
to zone files and zone file hashes.  This is intentional.

The [public BNS API endpoint](https://core.blockstack.org) does not support
resolving Atlas chunks that do not encode Gaia routing information or subdomain
information.  To directly interact with Atlas, developers will need to install
[Blockstack Core](https://github.com/blockstack/blockstack-core) and use its
Python client libraries for these examples.

## Looking up Chunks

All Atlas chunks are addressed by the RIPEMD160 hash of the SHA256 hash of the
chunk data.  A client can query up to 100 chunks in one RPC call.

A client can look up a chunk with the `get_zonefiles()` method.  If successful,
the returned payload will be a `dict` with a `zonefiles` key that maps the chunk
hashes to their respective data.

```python
>>> import blockstack
>>> data = blockstack.lib.client.get_zonefiles('https://node.blockstack.org:6263', ['1b89a685f4c4ea245ce9433d0b29166c22175ab4'])
>>> print data['zonefiles']['1b89a685f4c4ea245ce9433d0b29166c22175ab4']
$ORIGIN duckduckgo_tor.id
$TTL 3600
tor TXT "3g2upl4pq6kufc4m.onion"

>>>
```

(This particular chunk happens to be associated with the BNS name
`duckduckgo_tor.id`).

## Adding a New Chunk

The only way to add a chunk to Atlas is to do so through an on-chain name in
BNS.  Adding a new chunk is a two-step process:

* The name owner announces the chunk hash as a name's state
via a `NAME_REGISTRATION`, `NAME_UPDATE`, `NAME_RENEWAL`, or `NAME_IMPORT` transaction.
* Once the transaction is confirmed and processed by BNS, the name owner
  broadcasts the matching zone file.

Setting a name's state to be the hash of a chunk is beyond the scope of this
document, since it needs to be done through a BNS client.
See the relevant documentation for
[blockstack.js](https://github.com/blockstack/blockstack.js) and the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser) for doing this.

Once the name operation is confirmed, you can announce the data to the
Atlas network.  You can do so with the Python client as follows:

```python
>>> import blockstack
>>> import base64
>>> data = "..."   # this is the chunk data you will announce
>>> data_b64 = base64.b64encode(data)
>>> result = blockstack.lib.client.put_zonefiles('https://node.blockstack.org:6263', [data_b64])
>>> assert result['saved'][0] == 1
>>>
```

At most five chunks can be announced in one RPC call.
Note that the data must be base64-encoded before it can be announced.

When the `put_zonefiles()` method succeeds, it returns a `dict` with a list
under the `saved` key.  Here, `result['saved'][i]` will be 1 if the `i`th
chunk given to `put_zonefiles()` was saved by the node, and 0 if not.
The node will not save a chunk if it is too big, or if it has not yet processed
the name operation that contained the chunk's hash.

The `put_zonefiles()` method is idempotent.

## Propagating Chunks

Atlas peers will each store a copy of the chunks you announce.  In the
background, they will asynchronously announce to one another which chunks they
have available, and replicate them to one another in a rarest-first order (much
like how BitTorrent works).  Eventually, every Atlas peer will receive the
chunk.

However, developers can accelerate this process by eagerly propagating chunks.
To do so, they can ask an Atlas peer for its immediate neighbors in the Atlas
peer graph, and replicate the chunk to each of them as well.

For example, this code will replicate the chunk to not only
`https://node.blockstack.org:6263`, but also to its immediate neighbors.

```python
>>> import blockstack
>>> import base64
>>> data = "..."   # this is the chunk you will replicate widely
>>> data_b64 = base64.b64encode(data)
>>>
>>> result = blockstack.lib.client.get_atlas_peers('https://node.blockstack.org:6263')
>>> neighbors = result['peers']
>>> print ", ".join(neighbors)
13.65.207.163:6264, 52.225.128.191:6264, node.blockstack.org:6264, 23.102.162.7:6264, 52.167.230.235:6264, 23.102.162.124:6264, 52.151.59.26:6264, 13.92.134.106:6264
>>>
>>> for neighbor in neighbors:
...    result = blockstack.lib.client.put_zonefiles(neighbor, [data_b64])
...    assert result['saved'][0] == 1
...
>>>
```

This is not strictly necessary, but it does help accelerate chunk replication
and makes it less likely that a chunk will get lost due to individual node
failures.
