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
-`name encoding`: a given name converted from base 37 to base 256, then padded with zeros
- `historical record hash`: a hash of a data string generated from the combined list of the last block's valid names
- `update hash`: a hash of the data to be associated with a given name

### Data Encoding

#### Constraints:

- 40 bytes available in OP_RETURN
- 1 byte = 256 values
- alphanumeric-dash-dot charspace = 38 values
- 1.5244 name characters can fit in each byte

#### Field lengths

- prefix = 1 byte
- name hash = 20 bytes
- previous block hash (truncated) = 19 bytes
- name = 19 bytes
- salt = 16 bytes
- update hash = 20 bytes

#### Name encoding lengths

- 18 bytes = 27.4 characters
- 19 bytes = 28.9 characters
- 20 bytes = 30.4 characters
- 24 bytes = 36.5 characters

### Name Preorder (reserve)

- prefix (1 bytes)
- name hash (20 bytes)
- historical record hash (19 bytes)

### Name Claim (reveal)

- prefix (1 bytes)
- name (19 bytes)
- salt (16 bytes)

### Name Update

- prefix (1 bytes)
- name (19 bytes)
- update hash (20 bytes)

### Name Transfer

- prefix (1 bytes)
- name (19 bytes)

Name ownership is transferred to the recipient of the first output.
Name admin rights are given to the recipients of the second output.

### Misc.

Example of a transaction with an OP\_RETURN and multiple outputs:
https://blockchain.info/tx/1ae39745fd3891c16806bba44e6540944d145452ff156cab03076d7c08462e38?show_adv=true

