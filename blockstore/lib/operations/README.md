Blockstore Virtualchain Operations
==================================

**WARNING!** This code affects the virtualchain consensus.  TEST [THOROUGHLY](https://github.com/blockstack/blockstore/wiki/Releases) BEFORE RELEASE.

Operation Structure
-------------------

Each operation is a Python file with the following variables and methods defined:

* `FIELDS`:  This is a list of names of fields in the operation which Blockstore must achieve consensus on.
* `build()`:  This method constructs a serialized OP_RETURN encoding the operation.
* `tx_extract()`:  This method takes the serialized OP_RETURN and virtualchain-supplied transaction information and turns it into a `dict` describing the operation.
* `broadcast()`:  This method takes the operation's data and generates a transaction.  It will send it to Bitcoin by default, but may optionally return it (without signing it), or sign it with a subsidy key and return it.
* `get_fees()`:  This method takes the transaction's inputs and outputs, and calculates both a dust fee and an operation-specific fee that must be paid for the transaction to be accepted by Blockstore.

