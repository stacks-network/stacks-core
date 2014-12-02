Bitcoin DNS Specs + Design
==========

### Operations

1. name preorder
2. name claim
3. name update
4. name transfer

### Definitions

- `hash160`: a 20-byte ripemd160 hash
- `salt`: a random value appended to data in order to prevent reverse-lookups of the hashed data
- `name hash`: a hash160 of a given name and a random salt
-`name encoding`: a given name converted from base 40 to base 256
- `historical record hash`: a hash of a data string generated from a representation of the namespace
- `update hash`: a hash of the data to be associated with a given name

### Data Encoding

#### Constraints:

- 40 bytes available in OP_RETURN
- 1 byte = 256 values
- charspace of alphanumerics and a few special chars (-._+) = 40 values
- 1.5 name characters can fit in each byte

#### Field lengths

- prefix = 1 byte
- name hash = 20 bytes
- previous block hash (truncated) = 19 bytes
- name = 19 bytes
- salt = 16 bytes
- update hash = 20 bytes

#### Name encoding lengths

- 16 bytes = 24 characters
- 17 bytes = 25.5 characters
- 18 bytes = 27.0 characters
- 19 bytes = 28.5 characters
- 20 bytes = 30 characters
- 24 bytes = 36 characters

### Transaction Senders/Name Owners

Each transaction operation has a "sender". If any pre-orders or name registrations occur as a result of a given transaction, the "sender" is also considered the "owner" of those pre-orders and/or name registrations.

In a transaction, the sender is established as the funder of the first non-OP_RETURN input.

### Name Preorder (reserve)

- magic bytes (2 bytes)
- operation code (1 byte)
- name/salt hash (20 bytes)
- historical record hash (16 bytes)

### Name Claim (reveal)

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

Name ownership is transferred to the recipient of the first output.
Name admin rights are given to the recipient of the second output.

### Misc.

Example of a transaction with an OP\_RETURN and multiple outputs:
https://blockchain.info/tx/1ae39745fd3891c16806bba44e6540944d145452ff156cab03076d7c08462e38?show_adv=true

