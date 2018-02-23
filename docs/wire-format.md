This page is for organizations who want to be able to create and send name operation transactions to the blockchain(s) Blockstack supports.

# Bitcoin

This section describes the transaction formats for the Bitcoin blockchain.

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

Each `OP_RETURN` payload *always* starts with `id` (called the "magic" bytes in this document), followed by a one-byte `op` that describes the operation.

### NAME_PREORDER

Op: `?`

Description:  This transaction commits to the *hash* of a name.  It is the first
transaction of two transactions that must be sent to register a name in BNS.

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
network](atlas_network.md).

`OP_RETURN` wire format:
```
    0     2  3                                   19                      39
    |-----|--|-----------------------------------|-----------------------|
    magic op  hash128(name.ns_id,consensus hash)        value
```

Note that `hash128(name.ns_id, consensus hash)` is the first 16 bytes of a SHA256 hash over the name concatenated to the hexadecimal string of the consensus hash (not the bytes corresponding to that hex string).

Example: `hash128("jude.id" + "8d8762c37d82360b84cf4d87f32f7754") == "d1062edb9ec9c85ad1aca6d37f2f5793"`.

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
BNS.

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

* The `keep data?` byte controls whether or not the name's 20-byte value is preserved.  This value is either `>` to preserve it, or `~` to delete it.

### NAME_REVOKE

Op: `~`

Description:  This transaction destroys a registered name.  Its name state value
in BNS will be cleared, and no further transactions will be able to affect the
name until it expires (if its namespace allows it to expire at all).

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

### ANNOUNCE

Op: `#`

Description:  This transaction does not affect any names in BNS, but it allows a
user to send a message to other BNS nodes.  In order for the message to be
received, the following must be true:

* The sender must have a BNS name
* The BNS nodes must list the sender's BNS name as being a "trusted message
  sender"
* The message must have already been propagated through the [Atlas
  network](atlas_network.md).  This transaction references it by content hash.

`OP_RETURN` wire format:

```
    0    2  3                             23
    |----|--|-----------------------------|
    magic op   ripemd160(sha256(message))
```

Inputs:

* The payer `scriptSig`'s

Outputs:

* `OP_RETURN` payload
* change `scriptPubKey`

Notes:

* The payer key should be an owner key for an existing name, since Blockstack users can subscribe to announcements from specific name-owners.

### NAMESPACE_PREORDER

Op: `*`

Description:  This transaction announces the *hash* of a new namespace.  It is the
first of three transactions that must be sent to create a namespace.

`OP_RETURN` wire format:
```
   0     2   3                                         23               39
   |-----|---|-----------------------------------------|----------------|
   magic op  hash_name(ns_id,script_pubkey,reveal_addr)   consensus hash
```

Inputs:

* Namespace payer `scriptSig`

Outputs:

* `OP_RETURN` payload
* Namespace payer `scriptPubkey` change address
* `p2pkh` script to the burn address `1111111111111111111114oLvT2`, whose public key hash is 0x00000000000000000000000000000000

Notes:

* The `reveal_addr` field is the address of the namespace revealer public key.  The revealer private key will be used to generate `NAME_IMPORT` transactions.

### NAMESPACE_REVEAL

Op: `&`

Description:  This transaction reveals the namespace ID and namespace rules
for a previously-anounced namespace hash (sent by a previous `NAMESPACE_PREORDER`).

`OP_RETURN` wire format:
```
   0     2   3        7     8     9    10   11   12   13   14    15    16    17       18        20                        39
   |-----|---|--------|-----|-----|----|----|----|----|----|-----|-----|-----|--------|----------|-------------------------|
   magic  op  life    coeff. base 1-2  3-4  5-6  7-8  9-10 11-12 13-14 15-16  nonalpha  version   namespace ID
                                                     bucket exponents         no-vowel
                                                                              discounts
```

Inputs:

* Namespace payer `scriptSig`s

Outputs:

* `OP_RETURN` payload
* namespace revealer `scriptPubkey`
* namespace payer change `scriptPubkey`

Notes:

* This transaction must be sent within 1 day of the `NAMESPACE_PREORDER`
* The second output (with the namespace revealer) **must** be a `p2pkh` script
* The address of the second output **must** be the `reveal_addr` in the `NAMESPACE_PREORDER`

Pricing:

The rules for a namespace are as follows:

   * a name can fall into one of 16 buckets, measured by length.  Bucket 16 incorporates all names at least 16 characters long.
   * the pricing structure applies a multiplicative penalty for having numeric characters, or punctuation characters.
   * the price of a name in a bucket is ((coeff) * (base) ^ (bucket exponent)) / ((numeric discount multiplier) * (punctuation discount multiplier))
   
Example:
* base = 10
* coeff = 2
* nonalpha discount: 10
* no-vowel discount: 10
* buckets 1, 2: 9
* buckets 3, 4, 5, 6: 8
* buckets 7, 8, 9, 10, 11, 12, 13, 14: 7
* buckets 15, 16+:

With the above example configuration, the following are true:

* The price of "john" would be 2 * 10^8, since "john" falls into bucket 4 and has no punctuation or numerics.
* The price of "john1" would be 2 * 10^6, since "john1" falls into bucket 5 but has a number (and thus receives a 10x discount)
* The price of "john_1" would be 2 * 10^6, since "john_1" falls into bucket 6 but has a number and punctuation (and thus receives a 10x discount)
* The price of "j0hn_1" would be 2 * 10^5, since "j0hn_1" falls into bucket 6 but has a number and punctuation and lacks vowels (and thus receives a 100x discount)


### NAME_IMPORT

Op: `;`

Description:  This transaction registers a name and some name state into a
namespace that has been revealed, but not been launched.  Only the namespace
creator can import names.  See the [namespace creation
tutorial](namespace_creation.md) for details.

`OP_RETURN` wire format:
```
    0    2  3                             39
    |----|--|-----------------------------|
    magic op   name.ns_id (37 bytes)
```

Inputs:

* The namespace reveal `scriptSig` (with the namespace revealer's public key), or one of its first 300 extended public keys
* Any payment inputs

Outputs:

* `OP_RETURN` payload
* recipient `scriptPubKey`
* zone file hash (using the 20-byte hash in a standard `p2pkh` script)
* payment change `scriptPubKey`

Notes:

* These transactions can only be sent between the `NAMESPACE_REVEAL` and `NAMESPACE_READY`.
* The first `NAME_IMPORT` transaction **must** have a `scriptSig` input that matches the `NAMESPACE_REVEAL`'s second output (i.e. the reveal output).
* Any subsequent `NAME_IMPORT` transactions **may** have a `scriptSig` input whose public key is one of the first 300 extended public keys from the `NAMESPACE_REVEAL`'s `scriptSig` public key.

### NAMESPACE_READY

Op: `!`

Description:  This transaction launches a namesapce.  Only the namespace creator
can send this transaction.  Once sent, anyone can register names in the
namespace.

`OP_RETURN` wire format:
```
   
   0     2  3  4           23
   |-----|--|--|------------|
   magic op  .  ns_id
```

Inputs:
* Namespace revealer's `scriptSig`s

Outputs:
* `OP_RETURN` payload
* Change output to the namespace revealer's `p2pkh` script

Notes:
* This transaction must be sent within 1 year of the corresponding `NAMESPACE_REVEAL` to be accepted.

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

