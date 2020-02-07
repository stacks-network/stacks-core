---
layout: core
permalink: /:collection/:path.html
---
# Manage BNS Names
{:.no_toc}

This section teaches you how to manage your namespace, it contains the
following sections:

* TOC
{:toc}

## Overview of management

Once you register a BNS name, you have the power to change its zone file hash,
change its public key hash, destroy it (i.e. render it unresolvable),
or renew it.  The BNS consensus rules ensure that *only* you, as the owner of
the name's private key, have the ability to carry out these operations.

Each of these operations are executed by sending a specially-formatted
blockchain transaction to the blockchain, which BNS nodes read and process.
The operations are listed below:

| Transaction Type | Description |
|------------------|-------------|
| `NAME_UPDATE`    | This changes the name's zone file hash.  Any 20-byte string is allowed. |
| `NAME_TRANSFER`  | This changes the name's public key hash.  In addition, the current owner has the option to atomically clear the name's zone file hash (so the new owner won't "receive" the zone file). |
| `NAME_REVOKE`    | This renders a name unresolvable.  You should do this if your private key is compromised. |
| `NAME_RENEWAL`   | This pushes back the name's expiration date (if it has one), and optionally both sets a new zone file hash and a new public key hash. |

The reference BNS clients---
[blockstack.js](https://github.com/blockstack/blockstack.js) and the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser)---can handle creating
and sending all of these transactions for you.

## NAME_UPDATE ([live example](https://www.blocktrail.com/BTC/tx/e2029990fa75e9fc642f149dad196ac6b64b9c4a6db254f23a580b7508fc34d7))

A `NAME_UPDATE` transaction changes the name's zone file hash.  You would send
one of these transactions if you wanted to change the name's zone file contents.
For example, you would do this if you want to deploy your own [Gaia
hub](https://github.com/blockstack/gaia) and want other people to read from it.

A `NAME_UPDATE` transaction is generated from the name, a recent [consensus
hash](#bns-forks), and the new zone file hash.  The reference clients gather
this information automatically.  See the [transaction format]({{ site.baseurl }}/core/wire-format.html)
document for details on how to construct this transaction.

## NAME_TRANSFER ([live example](https://www.blocktrail.com/BTC/tx/7a0a3bb7d39b89c3638abc369c85b5c028d0a55d7804ba1953ff19b0125f3c24))

A `NAME_TRANSFER` transaction changes the name's public key hash.  You would
send one of these transactions if you wanted to:

* Change your private key
* Send the name to someone else

When transferring a name, you have the option to also clear the name's zone
file hash (i.e. set it to `null`).
This is useful for when you send the name to someone else, so the
recipient's name does not resolve to your zone file.

The `NAME_TRANSFER` transaction is generated from the name, a recent [consensus
hash](#bns-forks), and the new public key hash.  The reference clients gather
this information automatically.  See the [transaction format]({{ site.baseurl }}/core/wire-format.html)
document for details on how to construct this transaction.

## NAME_REVOKE ([live example](https://www.blocktrail.com/BTC/tx/eb2e84a45cf411e528185a98cd5fb45ed349843a83d39fd4dff2de47adad8c8f))

A `NAME_REVOKE` transaction makes a name unresolvable.  The BNS consensus rules
stipulate that once a name is revoked, no one can change its public key hash or
its zone file hash.  The name's zone file hash is set to `null` to prevent it
from resolving.

You should only do this if your private key is compromised, or if you want to
render your name unusable for whatever reason.  It is rarely used in practice.

The `NAME_REVOKE` operation is generated using only the name.  See the
[transaction format]({{ site.baseurl }}/core/wire-format.html) document for details on how to construct
it.

## NAME_RENEWAL ([live example](https://www.blocktrail.com/BTC/tx/e543211b18e5d29fd3de7c0242cb017115f6a22ad5c6d51cf39e2b87447b7e65))

Depending in the namespace rules, a name can expire.  For example, names in the
`.id` namespace expire after 2 years.  You need to send a `NAME_RENEWAL` every
so often to keep your name.

A `NAME_RENEWAL` costs both transaction fees and registration fees.  You will
pay the registration cost of your name to the namespace's designated burn address when you
renew it.  You can find this fee using the `/v1/prices/names/{name}` endpoint.

When a name expires, it enters a month-long "grace period" (5000 blocks).  It
will stop resolving in the grace period, and all of the above operations will
cease to be honored by the BNS consensus rules.  You may, however, send a
`NAME_RENEWAL` during this grace period to preserve your name.

If your name is in a namespace where names do not expire, then you never need to
use this transaction.

When you send a `NAME_RENEWAL`, you have the option of also setting a new public
key hash and a new zone file hash.  See the [transaction format]({{ site.baseurl }}/core/wire-format.html)
document for details on how to construct this transaction.
