---
layout: core
permalink: /:collection/:path.html
---
## Decentralized Identifiers (DIDs)

BNS nodes are compliant with the emerging
[Decentralized Identity Foundation](http://identity.foundation) protocol
specification for decentralized identifiers (DIDs).

Each name in BNS has an associated DID.  The DID format for BNS is:

```
    did:stack:v0:{address}-{index}
```

Where:
* `{address}` is an on-chain public key hash (e.g. a Bitcoin address).
* `{index}` refers to the `nth` name this address created.

For example, the DID for `personal.id` is
`did:stack:v0:1dARRtzHPAFRNE7Yup2Md9w18XEQAtLiV-0`, because the name
`personal.id` was the first-ever name created by
`1dARRtzHPAFRNE7Yup2Md9w18XEQAtLiV`.

As another example, the DID for `jude.id` is `did:stack:v0:16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg-1`.
Here, the address `16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg` had created one earlier
name in history prior to this one (which happens to be `abcdefgh123456.id`).

The purpose of a DID is to provide an eternal identifier for a public key.
The public key may change, but the DID will not.

Blockstack Core implements a DID method of its own
in order to be compatible with other systems that use DIDs for public key resolution.
In order for a DID to be resolvable, all of the following must be true for a
name:

* The name must exist
* The name's zone file hash must be the hash of a well-formed DNS zone file
* The DNS zone file must be present in the BNS [Atlas Network]({{ site.baseurl }}/core/atlas/overview.html)
* The DNS zone file must contain a `URI` resource record that points to a signed
  JSON Web Token
* The public key that signed the JSON Web Token (and is included with it) must
  hash to the address that owns the name

Not all names will have DIDs that resolve to public keys.  However, names created by the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser) will have DIDs that
do.

Developers can programmatically resolve DIDs via the Python API:

```Python
>>> import blockstack
>>> blockstack.lib.client.resolve_DID('did:stack:v0:16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg-1', hostport='https://node.blockstack.org:6263')
{'public_key': '020fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc8'}
```

A RESTful API is under development.


# DID Encoding for Subdomains

Every name and subdomain in BNS has a DID.  The encoding is slightly different
for subdomains, so the software can determine which code-path to take.

* For on-chain BNS names, the `{address}` is the same as the Bitcoin address
  that owns the name.  Currently, both version byte 0 and version byte 5
addresses are supported (i.e. addresses starting with `1` or `3`, meaning `p2pkh` and
`p2sh` addresses).

* For off-chain BNS subdomains, the `{address}` has version byte 63 for
  subdomains owned by a single private key, and version byte 50 for subdomains
owned by a m-of-n set of private keys.  That is, subdomain DID addresses start
with `S` or `M`, respectively.

The `{index}` field for a subdomain's DID is distinct from the `{index}` field
for a BNS name's DID, even if the same created both names and subdomains.
For example, the name `abcdefgh123456.id` has the DID `did:stack:v0:16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg-0`,
because it was the first name created by `16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg`.
However, `16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg` *also* created `jude.statism.id`
as its first subdomain name.  The DID for `jude.statism.id` is
`did:stack:v0:SSXMcDiCZ7yFSQSUj7mWzmDcdwYhq97p2i-0`.  Note that the address
`SSXMcDiCZ7yFSQSUj7mWzmDcdwYhq97p2i` encodes the same public key hash as the address
`16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg` (the only difference between these two
strings is that the first is base58check-encoded with version byte 0, and the
second is encoded with version byte 63).

You can see this play out in practice with the following code snippit:

```python
>>> import blockstack
>>> blockstack.lib.client.get_name_record('jude.statism.id', hostport='https://node.blockstack.org:6263')['address']
u'16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg'
>>> import virtualchain
>>> virtualchain.address_reencode('16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg', version_byte=63)
'SSXMcDiCZ7yFSQSUj7mWzmDcdwYhq97p2i'
>>> blockstack.lib.client.resolve_DID('did:stack:v0:SSXMcDiCZ7yFSQSUj7mWzmDcdwYhq97p2i-0', hostport='https://node.blockstack.org:6263')
{'public_key': '020fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc8'}
```
