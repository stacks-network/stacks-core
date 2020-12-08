# SIP 005 Blocks, Transactions, and Accounts

## Preamble

Title: Blocks, Transactions, and Accounts

Authors: Jude Nelson <jude@blockstack.com>, Aaron Blankstein
<aaron@blockstack.com>

Status: Draft

Type: Standard

Created: 7/23/2019

License: BSD 2-Clause

## Abstract

This SIP describes the structure, validation, and lifecycle for transactions and blocks in
the Stacks blockchain, and describes how each peer maintains a materialized view
of the effects of processing all state-transitions encoded in the blockchain's sequence of
transactions.  It presents the account model for the Stacks blockchain, and
describes how accounts authorize and pay for processing transactions on the
network.

## Rationale

The Stacks blockchain is a replicated state machine.
A _transaction_ encodes a single state-transition on the
Stacks blockchain.  The Stacks blockchain's state evolves by materializing the
effects of a sequence of transactions -- i.e. by applying each transaction's encoded
state-transitions to the blockchain's state.

Transactions in the Stacks blockchain encode various kinds of state-transitions,
the principal ones being:

* To instantiate a smart contract (see SIP 002)
* To invoke a public smart contract function
* To transfer STX tokens between accounts
* To punish leaders who fork their microblock streams (see SIP 001)
* To allow leaders to perform limited on-chain signaling

Processing transactions is not free.  Each step in the process of validating and
executing the transaction incurs a non-zero computational cost.  To incentivize 
peers and leaders to execute transactions, the transaction's computational costs
are paid for by an _account_.

An _account_ is the logical entity that executes and/or pays for transactions.  A transaction's
execution is governed by three accounts, which may or may not be distinct:

* The **originating account** is the account that creates and sends the
  transaction.  This is always an account owned by a user.  Each transaction is
_authorized_ by its originating account.

* The **paying account** is the account that is billed by the leader for the cost
  of validating and executing the transaction.  This is also always an account
owned by a user.  If not identified in the transaction, the paying account and
the originating account are the same account.

* The **sending account** is the account that identifies _who_ is
  _currently_ executing the transaction. The sending account can
  change during the course of transaction execution via the Clarity
  function `as-contract`, which executes the provided code block as
  the _current contract's_ account. Each transaction's initial sending
  account is its originating account -- i.e. the account that
  authorizes the transaction.  Smart contracts determine the sending
  account's principal using the `tx-sender` built-in function.

This document frames accounts in the Stacks blockchain as the unit of agency for 
processing transactions.  The tasks
that a transaction carries out are used to inform the decisions on what
data goes into the transaction, as well as the data that goes into a block.
As such, understanding blocks and transactions in the Stacks blockchain first
requires understanding accounts.

## Accounts

Transactions in the Stacks blockchain originate from, are paid for by, and
execute under the authority of accounts.  An account is fully
described by the following information:

* **Address**.  This is a versioned cryptographic hash that uniquely identifies the
  account.  The type of account (described below) determines what information is
hashed to derive the address.  The address itself contains two or three fields:
   * A 1-byte **version**, which indicates whether or not the address
     corresponds to a mainnet or testnet account and what kind of hash algorithm
to use to generate its hash.
   * A 20-byte **public key hash**, which is calculated using the address
     version and the account's owning public key(s).
   * A variable-length **name**.  This is only used in contract accounts, and it
     identifies the code body that belongs to this account.  The name
     may be up to 128 bytes.  Accounts belonging to users do not have this field.

* **Nonce**.  This is a Lamport clock, used for ordering the transactions
  originating from and paying from an account.  The nonce ensures that a transaction
is processed at most once.  The nonce counts the number of times
an account's owner(s) have authorized a transaction (see below).
The first transaction from an account will have a nonce value equal to 0,
the second will have a nonce value equal to 1, and so
on.  A valid transaction authorization from this account's owner(s) must include the _next_ nonce
value of the account; when the transaction is accepted by the peer network, the
nonce is incremented in the materialized view of this account.

* **Assets**.  This is a mapping between all Stacks asset types and the
  quantities of each type owned by the account.  This includes the STX token, as
well as any other on-chain assets declared by a Clarity smart contract (i.e.
fungible and non-fungible tokens).

All accounts for all possible addresses are said to exist, but nearly all of
them are "empty" -- they have a nonce value of 0, and their asset mappings
contain no entries.  The state for an account is lazily materialized once
the Stacks peer network processes a transaction that _funds_ it.
That is, the account state is materialized only once a transaction's state-transition inserts
an entry into an account's assets mapping for some (possibly zero) quantity of some asset.
Even if the account depletes all asset holdings, it remains materialized.
Materialized accounts are distinguished from empty accounts in that the former
are all represented in a leader's commitment to its materialized view of the blockchain state
(described below).

### Account Types

The Stacks blockchain supports two kinds of accounts:

* **Standard accounts**.  These are accounts owned by one or more private keys.
  Only standard accounts can originate and pay for transactions.  A transaction originating
from a standard account is only valid if a threshold of its private keys sign
it.  The address for a standard account is the hash of this threshold value and
all allowed public keys.  Due to the need for backwards compatibility with
Stacks v1, there are four ways to hash an account's public keys and threshold,
and they are identical to Bitcoin's pay-to-public-key-hash, multisig
pay-to-script-hash, pay-to-witness-public-key-hash, and multisig
pay-to-witness-script-hash hashing algorithms (see appendix).

* **Contract accounts**.  These are accounts that are materialized whenever a
smart contract is instantiated.  Each contract is paired with exactly one contract account.
It cannot authorize or pay for transactions, but may serve as the sending account
of a currently-executing transaction, via Clarity's `as-contract` function.  A
contract's address's public key hash matches the public key hash of the standard
account that created it, and each contract account's address contains a name for
its code body.  The name is unique within the set of code bodies instantiated by
the standard account.

Both kinds of accounts may own on-chain assets.  However, the nonce of a
contract account must always be 0, since it cannot be used to originate or pay
for a transaction.

### Account Assets

As described in SIP 002, the Stacks blockchain supports on-chain assets as a
first-class data type -- in particular, _fungible_ and _non-fungible_ assets are
supported.  All assets (besides STX) are scoped to a particular contract, since 
they are created by contracts.  Within a contract, asset types are unique.
Therefore, all asset types are globally addressible via their identifier in the
contract and their fully-qualified contract names.

Regardless of where asset types are declared, a particular instance of an asset 
belongs to exactly one account at all times.  Once a contract declares an asset type,
instances of that asset can be sent to and owned by other accounts.

## Transactions

Transactions are the fundamental unit of execution in the Stacks blockchain.
Each transaction is originated from a standard account, and is retained in
the Stacks blockchain history for eternity.  Transactions are atomic -- they
either execute completely with respect to other transactions, or not at all.
Moreover, transactions are processed in the same total order by all Stacks
nodes.

At its core, a transaction is an authorization statement (see below),
a snippet of executable Clarity code, and a list of
_post-conditions_ that must be true before the transaction is accepted.  The
transaction body supplies the Stacks blockchain this code, as well as all of
the necessary metadata to describe how the transaction should be executed.
The various types of Stacks transactions encode different metadata, and
thus have different validation rules.

All transactions are originated from a set of private keys that own a standard
account, even if it is not yet materialized.  The owner(s) of these
private keys sign the transaction, attach a _transaction fee_ to it, and
relay it to the Stacks peer network.  If the transaction is well-formed,
then it will be propagated to all reachable Stacks peers.
Eventually, assuming the transaction remains resident in the peers' memories
for long enough, a Stacks leader will select the transaction for inclusion
in the longest fork's next block.  Once this happens, the state-transitions
encoded by the transaction are materialized in the blockchain state replicas in all
peers.

### Transaction Authorizations

The Stacks blockchain supports two ways to authorize a transaction:  a
_standard_ authorization, and a _sponsored_ authorization.  The distinction is
in whether or not the originating account is also the paying account.  In a
transaction with a standard authorization, the origin and paying accounts are
the same.  In a transaction with a sponsored authorization, the origin and
paying accounts are distinct, and both accounts must sign the transaction for it
to be valid (first the origin, then the spender).

The intended use-case for sponsored authorizations is to enable developers
and/or infrastructure operators to pay for users to call into their
smart contracts, even if users do not have the STX to do so.  The signing flow
for sponsored transactions would be to have the user first sign the transaction
with their origin account with the intent of it being sponsored (i.e. the user
must explicitly allow a sponsor to sign), and then have the sponsor sign with their paying
account to pay for the user's transaction fee.

### Transaction Payloads

The key difference between Stacks transaction payloads is what functionality is
available to them from the Clarity VM (and by extension, what side-effects are
materializable).  The reasons for distinguishing between these types of
transactions are to make static analysis cheaper for certain common use-cases,
and to provide greater security for the user(s) that own the account.

#### Type-0: Transferring an Asset

A type-0 transaction may only transfer a single asset from one account to
another.  It may not directly execute Clarity code.  A type-0
transaction can only send STX.  It cannot have post-conditions
(see below).

#### Type-1: Instantiating a Smart Contract

A type-1 transaction has unrestricted access to the Clarity VM,
and when successfully evaluated, will materialize a new smart contract
account.  Type-1 transactions are meant to instantiate smart contracts, and to
call into multiple smart contract functions and/or access their state
atomically.

#### Type-2: Calling an Existing Smart Contract

A type-2 transaction has restricted access to the Clarity VM.  A
type-2 transaction may only contain a single public function call (via
`contract-call?`), and may only supply Clarity `Value`s as its
arguments. These transactions do _not_ materialize a contract account.

The intended use-case for a type-2 transaction is to invoke an existing public
smart contract function.  Because they have such restricted access to the
Clarity VM, they are much cheaper to execute compared to a type-1 transaction.

#### Type-3: Punishing an Equivocating Stacks Leader

A type-3 transaction encodes two well-formed, signed, but conflicting
microblock headers.  That is, the headers are different, but have the same
sequence number and/or parent block hash.  If mined before the block reward
matures, this transaction will cause the offending leader to lose their block reward,
and cause the sender of this transaction to receive a fraction of the lost
coinbase as a reward for catching the bad behavior.
This transaction has no access to the Clarity VM.

#### Type-4: Coinbase

A type-4 transaction encodes a 32-byte scratch space for a block leader's own
use, such as signaling for network upgrades or announcing a digest of a set of
available peers.  This transaction must be the first transaction in an anchored
block in order for the block to be considered well-formed.  This transaction 
has no access to the Clarity VM.  Only one coinbase transaction may be mined per
epoch.

### Transaction Post-Conditions

A key use-case of smart contracts is to allow programmatic control over the
assets in one or more accounts.  However, where there is programmatic control,
there are bound to be bugs.  In the world of smart contract programming, bugs
(intentional or not) can have severe consequences to the user's well-being.
In particular, bugs can destroy a user's assets and cause them to lose wealth.
Transaction post-conditions are a feature meant to limit the damage a bug can
do in terms of destroying a user's assets.

Post-conditions are intended to be used to force a transaction to abort if the
transaction would cause a principal to send an asset in a way that is not to
the user's liking.  For example, a user may append a post-condition saying that
upon successful execution, their account's STX balance should have decreased by no more
than 1 STX (excluding the fee).  If this is not the case, then the transaction would abort
and the account would only pay the transaction fee of processing it.
As another example, a user purchasing a BNS name may append a post-condition saying that upon
successful execution, the seller will have sent the BNS name.  If it
did not, then the transaction aborts, the account is not billed for the name,
and the selling account receives no payment.

Each transaction includes a field that describes zero or more post-conditions
that must all be true when the transaction finishes running.  Each
post-condition is a quad that encodes the following information:

* The **principal** that sent the asset.  It can be a standard or contract address.
* The **asset name**, i.e. the name of one of the assets in the originating
  account's asset map.
* The **comparator**, described below.
* The **literal**, an integer or boolean value used to compare instances of the
  asset against via the condition.  The type of literal depends on both the
  type of asset (fungible or non-fungible) and the comparator.

The Stacks blockchain supports the following two types of comparators:

* **Fungible asset changes** -- that is, a question of _how much_ of a
  fungible asset was sent by a given account when the transaction ran.
  The post-condition can assert that the quantity of tokens increased,
  decreased, or stayed the same.
* **Non-fungible asset state** -- that is, a question of _whether or not_ an
  account sent a non-fungible asset when the transaction ran.

In addition, the Stacks blockchain supports an "allow" or "deny" mode for
evaluating post-conditions:  in "allow" mode, other asset transfers not covered
by the post-conditions are permitted, but in "deny" mode, no other asset
transfers are permitted besides those named in the post-conditions.

Post-conditions are meant to be added by the user (or by the user's wallet
software) at the moment they sign with their origin account.  Because the
user defines the post-conditions, the user has the power to protect themselves
from buggy or malicious smart contracts proactively, so even undiscovered bugs
cannot steal or destroy their assets if they are guarded with post-conditions.
Well-designed wallets would provide an intuitive user interface for
encoding post-conditions, as well as provide a set of recommended mitigations
based on whether or not the transaction would interact with a known-buggy smart contract.

Post-conditions may be used in conjunction with only contract-calls and smart contract 
instantiation transaction payloads.

#### Post-Condition Limitations

Post-conditions do not consider who _currently owns_ an asset when the
transaction finishes, nor do they consider the sequence of owners an asset
had during its execution.  It only encodes who _sent_ an asset, and how much.
This information is much cheaper to track, and requires no
I/O to process (rocessing time is _O(n)_ in the number of post-conditions).
Users who want richer post-conditions are encouraged to deploy their own
proxy contracts for making such queries.

### Transaction Encoding

A transaction includes the following information.  Multiple-byte fields are
encoded as big-endian.

* A 1-byte **version number**, identifying whether or not the transaction is
  meant as a mainnet or testnet transaction.
* A 4-byte **chain ID**, identifying which Stacks chain this transaction is
  destined for.
* A **transaction authorization** structure, described below, which encodes the
  following information (details are given in a later section):
   * The address of the origin account.
   * The signature(s) and signature threshold for the origin account.
   * The address of the sponsor account, if this is a sponsored transaction.
   * The signature(s) and signature threshold for the sponsor account, if given.
   * The **fee rate** to pay, denominated in microSTX/compute unit.
* A 1-byte **anchor mode**, identifying how the transaction should be mined.  It
  takes one of the following values:
   * `0x01`:  The transaction MUST be included in an anchored block
   * `0x02`:  The transaction MUST be included in a microblock
   * `0x03`:  The leader can choose where to include the transaction.
* A 1-byte **post-condition mode**, identifying whether or not post-conditions
  must fully cover all transferred assets.  It can take the following values:
   * `0x01`:  This transaction may affect other assets not listed in the
     post-conditions.
   * `0x02`:  This transaction may NOT affect other assets besides those listed
     in the post-conditions.
* A length-prefixed list of **post-conditions**, describing properties that must be true of the
  originating account's assets once the transaction finishes executing.  It is encoded as follows:
   * A 4-byte length, indicating the number of post-conditions.
   * A list of zero or more post-conditions, whose encoding is described below.
* The **transaction payload**, described below.

#### Version Number

The version number identifies whether or not the transaction is a mainnet or
testnet transaction.  A mainnet transaction MUST have its highest bit cleared, and a
testnet transaction MUST have the highest bit set (i.e. `version & 0x80` must be
non-zero for testnet, and zero for mainnet).  The lower 7 bits are ignored for
now.

#### Chain ID

The chain ID identifies which instance of the Stacks blockchain this transaction
is destined for.  Because the main Stacks blockchain and Stacks app chains
(described in a future SIP) share the same transaction wire format, this field
is used to distinguish between each chain's transactions.  Transactions for the
main Stacks blockchain MUST have a chain ID of `0x00000000`.

#### Transaction Authorization

Each transaction contains a transaction authorization structure, which is used
by the Stacks peer to identify the originating account and sponsored account, to
determine the maximum fee rate the spending account will pay, and to
and determine whether or not it is allowed to carry out the encoded state-transition.
It is encoded as follows:

* A 1-byte **authorization type** field that indicates whether or not the
  transaction has a standard or sponsored authorization.
   * For standard authorizations, this value MUST be `0x04`.
   * For sponsored authorizations, this value MUST be `0x05`.
* One or two **spending conditions**, whose encoding is described below.  If the
  transaction's authorization type byte indicates that it is a standard
authorization, then there is one spending condition.  If it is a sponsored
authorization, then there are two spending conditions that follow.

_Spending conditions_ are encoded as follows:

* A 1-byte **hash mode** field that indicates how the origin account authorization's public
  keys and signatures should be used to calculate the account address.  Four
modes are supported, in the service of emulating the four hash modes supported
in Stacks v1 (which uses Bitcoin hashing routines):
   * `0x00`: A single public key is used.  Hash it like a Bitcoin P2PKH output.
   * `0x01`: One or more public keys are used.  Hash them as a Bitcoin multisig P2SH redeem script.
   * `0x02`: A single public key is used.  Hash it like a Bitcoin P2WPKH-P2SH
     output.
   * `0x03`: One or more public keys are used.  Hash them as a Bitcoin
     P2WSH-P2SH output.
* A 20-byte **public key hash**, which is derived from the public key(s) according to the
  hashing routine identified by the hash mode.  The hash mode and public key
hash uniquely identify the origin account, with the hash mode being used to
derive the appropriate account version number.
* An 8-byte **nonce**.
* An 8-byte **fee rate**.
* Either a **single-signature spending condition** or a **multisig spending
  condition**, described below.  If the hash mode byte is either `0x00` or
`0x02`, then a signle-signature spending condition follows.  Otherwise, a
multisig spending condition follows.

A _single-signature spending condition_ is encoded as follows:

* A 1-byte **public key encoding** field to indicate whether or not the
  public key should be compressed before hashing.  It will be:
   * `0x00` for compressed
   * `0x01` for uncompressed
* A 65-byte **recoverable ECDSA signature**, which contains a signature
and metadata for a secp256k1 signature.

A _multisig spending condition_ is encoded as follows:

* A length-prefixed array of **spending authorization fields**, described
  below.
* A 2-byte **signature count** indicating the number of signatures that
  are required for the authorization to be valid.

A _spending authorization field_ is encoded as follows:

* A 1-byte **field ID**, which can be `0x00`, `0x01`, `0x02`, or
  `0x03`.
* The **spending field body**, which will be the following,
  depending on the field ID:
   * `0x00` or `0x01`:  The next 33 bytes are a compressed secp256k1 public key.
     If the field ID is `0x00`, the key will be loaded as a compressed
     secp256k1 public key.  If it is `0x01`, then the key will be loaded as
     an uncompressed secp256k1 public key.
   * `0x02` or `0x03`:  The next 65 bytes are a recoverable secp256k1 ECDSA
     signature.  If the field ID is `0x03`, then the recovered public
     key will be loaded as a compressed public key.  If it is `0x04`,
     then the recovered public key will be loaded as an uncompressed
     public key.

A _compressed secp256k1 public key_ has the following encoding:

* A 1-byte sign byte, which is either `0x02` for even values of the curve's `y`
  coordinate, or `0x03` for odd values.
* A 32-byte `x` curve coordinate.

An _uncompressed secp256k1 public key_ has the following encoding:

* A 1-byte constant `0x04`
* A 32-byte `x` coordinate
* A 32-byte `y` coordinate

A _recoverable ECDSA secp256k1 signature_ has the following encoding:

* A 1-byte **recovery ID**, which can have the value `0x00`, `0x01`, `0x02`, or
  `0x03`.
* A 32-byte `r` curve coordinate
* A 32-byte `s` curve coordinate.  Of the two possible `s` values that may be
  calculated from an ECDSA signature on secp256k1, the lower `s` value MUST be
used.

The number of required signatures and the list of public keys in a spending
condition structure uniquely identifies a standard account.
and can be used to generate its address per the following rules:

| Hash mode | Spending Condition | Mainnet version | Hash algorithm |
| --------- | ------------------ | --------------- | -------------- |
| `0x00` | Single-signature | 22 | Bitcoin P2PKH |
| `0x01` | Multi-signature | 20 | Bitcoin redeem script P2SH |
| `0x02` | Single-signature | 20 | Bitcoin P2WPK-P2SH |
| `0x03` | Multi-signature | 20 | Bitcoin P2WSH-P2SH |

The corresponding testnet address versions are:
*  For 22 (`P` in the c32 alphabet), use 26 (`T` in the c32 alphabet)
*  For 20 (`M` in the c32 alphabet), use 21 (`N` in the c32 alphabet).

The hash algorithms are described below briefly, and mirror hash algorithms used
today in Bitcoin.  This is necessary for backwards compatibility with Stacks v1
accounts, which rely on Bitcoin's scripting language for authorizations.

_Hash160_:  Takes the SHA256 hash of its input, and then takes the RIPEMD160
hash of the 32-byte

_Bitcoin P2PKH_:  This algorithm takes the ECDSA recoverable signature and
public key encoding byte from the single-signature spending condition, converts them to 
a public key, and then calculates the Hash160 of the key's byte representation
(i.e. by serializing the key as a compressed or uncompressed secp256k1 public
key).

_Bitcoin redeem script P2SH_:  This algorithm converts a multisig spending
condition's public keys and recoverable signatures
into a Bitcoin BIP16 P2SH redeem script, and calculates the Hash160
over the redeem script's bytes (as is done in BIP16).  It converts the given ECDSA
recoverable signatures and public key encoding byte values into their respective
(un)compressed secp256k1 public keys to do so.

_Bitcoin P2WPKH-P2SH_:  This algorithm takes the ECDSA recoverable signature and
public key encoding byte from the single-signature spending condition, converts
them to a public key, and generates a P2WPKH witness program, P2SH redeem
script, and finally the Hash160 of the redeem script to get the address's public
key hash.

_Bitcoin P2WSH-P2SH_:  This algorithm takes the ECDSA recoverable signatures and
pbulic key encoding bytes, as well as any given public keys, and converts them
into a multisig P2WSH witness program.  It then generates a P2SH redeem script
from the witness program, and obtains the address's public key hash from the
Hash160 of the redeem script.

The resulting public key hash must match the public key hash given in the
transaction authorization structure.  This is only possible if the ECDSA
recoverable signatures recover to the correct public keys, which in turn is only
possible if the corresponding private key(s) signed this transaction.

#### Transaction Post-Conditions

The list of post-conditions is encoded as follows:
* A 4-byte length prefix
* Zero or more post-conditions.

A post-condition can take one of the following forms:
* A 1-byte **post-condition type ID**
* A variable-length **post-condition**

The _post-condition type ID_ can have the following values:
* `0x00`:  A **STX post-condition**, which pertains to the origin account's STX.
* `0x01`:  A **Fungible token post-condition**, which pertains to one of the origin
account's fungible tokens.
* `0x02`:   A **Non-fungible token post-condition**, which pertains to one of the origin
account's non-fungible tokens.

A _STX post condition_ body is encoded as follows:
* A variable-length **principal**, containing the address of the standard account or contract
  account
* A 1-byte **fungible condition code**, described below
* An 8-byte value encoding the literal number of microSTX

A _Fungible token post-condition_ body is encoded as follows:
* A variable-length **principal**, containing the address of the standard account or contract
  account
* A variable-length **asset info** structure that identifies the token type, described below
* A 1-byte **fungible condition code**
* An 8-byte value encoding the literal number of token units

A _Non-fungible token post-condition_ body is encoded as follows:
* A variable-length **principal**, containing the address of the standard account or contract
  account
* A variable-length **asset info** structure that identifies the token type
* A variable-length **asset name**, which is the Clarity value that names the token instance,
  serialized according to the Clarity value serialization format.
* A 1-byte **non-fungible condition code**

A **principal** structure encodes either a standard account address or a
contract account address.
* A standard account address is encoded as a 1-byte version number and a 20-byte
  Hash160
* A contract account address is encoded as a 1-byte version number, a 20-byte
  Hash160, a 1-byte name length, and a variable-length name of up to 128
characters.  The name characters must be a valid contract name (see below).

An **asset info** structure identifies a token type declared somewhere in an
earlier-processed Clarity smart contract.  It contains the following fields:
* An **address**, which identifies the standard account that created the
  contract that declared the token.  This is encoded as a 1-byte version,
  followed by a 20-byte public key hash (i.e. a standard account address).
* A **contract name**, a length-prefixed Clarity string that encodes the
  human-readable part of the contract's name.
* An **asset name**, a length-prefixed Clarity string that encodes the name of
  the token as declared in the Clarity code. 

The _address_ and _contract name_ fields together comprise the smart contract's
fully-qualified name, and the asset name field identifies the specific token
declaration within the contract.

The _contract name_ is encoded as follows:
* A 1-byte length prefix, up to 128 
* A variable-length string of valid ASCII characters (up to 128 bytes).  This
  string must be accepted by the regex `^[a-zA-Z]([a-zA-Z0-9]|[-_])`<code>&ast;</code>`$`.

The _asset name_ is encoded as follows:
* A 1-byte length prefix, up to 128 
* A variable length string of valid ASCII characters (up to 128 bytes).  This
  string must be accepted by the regex `^[a-zA-Z]([a-zA-Z0-9]|[-_!?])`<code>&ast;</code>`$`.

A **fungible condition code** encodes a statement being made for either STX or
a fungible token, with respect to the originating account.  It can take one of the 
following values, with the following meanings regarding the associated token
units:
* `0x01`: "The account sent an amount equal to the number of units"
* `0x02`: "The account sent an amount greater than the number of units"
* `0x03`: "The account sent an amount greater than or equal to the number of units"
* `0x04`: "The account sent an amount less than the number of units"
* `0x05`: "The account sent an amount less than or equal to the number of units"

A **non-fungible condition code** encodes a statement being made about a
non-fungible token, with respect to whether or not the particular non-fungible
token is owned by the account.  It can take the following values:
* `0x10`: "The account does NOT own this non-fungible token"
* `0x11`: "The account owns this non-fungible token"

Post-conditions are defined in terms of which assets the origin account sends or
does not send during the transaction's execution.  To enforce post-conditions,
the Clarity VM records which assets the origin account sends as the transaction
is evaluated to produce an "asset map."  The asset map is used to evaluate the post-conditions.

#### Transaction Payloads

There are five different types of transaction payloads.  Each payload is encoded
as follows:
* A 1-byte **payload type ID**, between 0 and 5 exclusive.
* A variable-length **payload**, of which there are five varieties.

The _payload type ID_ can take any of the following values:
* `0x00`:  the payload that follows is a **token-transfer payload**
* `0x01`:  the payload that follows is a **smart-contract payload**
* `0x02`:  the payload that follows is a **contract-call payload**
* `0x03`:  the payload that follows is a **poison-microblock payload**
* `0x04`:  the payload that follows is a **coinbase payload**.

The _STX token-transfer_ structure is encoded as follows:
* A **recipient principal** encoded as follows:
  * A 1-byte type field indicating whether the principal is
    * `0x05`: a recipient address
    * `0x06`: a contract recipient
  * If a simple recipient address, the 1-byte type is followed by a
    1-byte address version number and a 20-byte hash identifying a standard
    recipient account.
  * If a contract recipient address, the 1-byte type is followed by
    the issuer address of the contract, encoded with a 1-byte address
    version number and the 20-byte hash that identifies the standard
    account of the issuer. This is followed by the encoding of the
    contract name -- encoded as described above.
* An 8-byte number denominating the number of microSTX to send to the recipient
  address's account.

Note that if a transaction contains a token-transfer payload, it MUST
have only a standard authorization field. It cannot be sponsored. The
recipient principal does not need to be a materialized account -- STX
may be transfered to an account which has not been used in any prior
transactions. In the case of a contract principal, the unmaterialized
contract principal will receive the funds and maintain a balance in
the STX holdings map. If and when that contract is published, the contract
will be able to spend those STX via `(as-contract (stx-transfer? ...`
invocations.

A _smart-contract payload_ is encoded as follows:
* A **contract name** string, described above, that encodes the human-readable
  part of the contract's fully-qualified name.
* A **code body** string that encodes the Clarity smart contract itself.  This
  string is encoded as:
   * A 4-byte length prefix
   * Zero or more human-readable ASCII characters -- specifically, those between `0x20` and
     `0x7e` (inclusive), and the whitespace characters `\n` and `\t`.

Note that when the smart contract is instantiated, its fully-qualified name will
be computed from the transaction's origin account address and the given contract
name.  The fully-qualified name must be globally unique -- the transaction will
not be accepted if its fully-qualified name matches an already-accepted smart
contract.

A _contract-call payload_ is encoded as follows:
* A **contract address**, comprised of a 1-byte address version number and a
  20-byte public key hash of the standard account that created the smart
contract whose public function is to be called,
* A length-prefixed **contract name** string, described above, that encodes the
  human readable part of the contract's fully-qualified name,
* A length-prefixed **function name** string, comprised of a 1-byte length and
  up to 128 characters of valid ASCII text, that identifies the public function
to call.  The characters must match the regex `^[a-zA-Z]([a-zA-Z0-9]|[-_!?])`<code>&ast;</code>`$`.
* A length-prefixed list of **function arguments**, encoded as follows:
   * A 4-byte length prefix, indicating the number of arguments
   * Zero or more binary strings encoding the arguments as Clarity values.
     Clarity values are serialized as described in the section
     [Clarity Value Representation](#clarity-value-representation).

Note that together, the _contract address_ and _contract name_ fields uniquely identify
the smart contract within the Clarity VM.

A _poison microblock payload_ is encoded as follows:
* Two Stacks microblock headers, such that either the `prev_block` or `sequence`
  values are equal.  When validated, the ECDSA recoverable `signature` fields of both microblocks
must recover to the same public key, and it must hash to the leader's parent
anchored block's public key hash.  See the following sections for the exact
encoding of a Stacks microblock header.

This transaction type is sent to punish leaders who intentionally equivocate
about the microblocks they package, as described in SIP 001.

A _coinbase payload_ is encoded as follows:
* A 32-byte field called a **coinbase buffer** that the Stacks leader can fill with whatever it wants.

Note that this must be the first transaction in an anchored block in order for the
anchored block to be considered well-formed (see below).

#### Transaction Signing and Verifying

A transaction may have one or two spending conditions.  The act of signing
a transaction is the act of generating the signatures for its authorization
structure's spending conditions, and the act of verifying a transaction is the act of (1) verifying
the signatures in each spending condition and (2) verifying that the public key(s) 
of each spending condition hash to its address.

Signing a transaction is performed after all other fields in the transaction are
filled in.  The high-level algorithm for filling in the signatures in a spending
condition structure is as follows:

0. Set the spending condition address, and optionally, its signature count.
1. Clear the other spending condition fields, using the appropriate algorithm below.
   If this is a sponsored transaction, and the signer is the origin, then set the sponsor spending condition
   to the "signing sentinal" value (see below).
2. Serialize the transaction into a byte sequence, and hash it to form an
   initial `sighash`.
3. Calculate the `presign-sighash` over the `sighash` by hashing the 
   `sighash` with the authorization type byte (0x04 or 0x05), fee rate (as an 8-byte big-endian value),
   and nonce (as an 8-byte big-endian value).
4. Calculate the ECDSA signature over the `presign-sighash` by treating this
   hash as the message digest.  Note that the signature must be a `libsecp256k1`
   recoverable signature.
5. Calculate the `postsign-sighash` over the resulting signature and public key
   by hashing the `presign-sighash` hash, the signing key's public key encoding byte, and the
   signature from step 4 to form the next `sighash`.  Store the message
   signature and public key encoding byte as a signature auth field.
6. Repeat steps 3-5 for each private key that must sign, using the new `sighash`
   from step 5.

The algorithms for clearing an authorization structure are as follows:
* If this is a single-signature spending condition, then set the fee rate and
  nonce to 0, set the public key encoding byte to `Compressed`, and set the
  signature bytes to 0 (note that the address is _preserved_).
* If this is a multi-signature spending condition, then set the fee rate and
  nonce to 0, and set the vector of authorization fields to the empty vector
  (note that the address and the 2-byte signature count are _preserved_).

While signing a transaction, the implementation keeps a running list of public
keys, public key encoding bytes, and signatures to use to fill in the spending condition once signing
is complete.  For single-signature spending conditions, the only data the
signing algorithm needs to return is the public key encoding byte and message signature.  For multi-signature
spending conditions, the implementation returns the sequence of public keys and
(public key encoding byte, ECDSA recoverable signature) pairs that make up the condition's authorization fields.
The implementation must take care to preserve the order of public keys and
(encoding-byte, signature) pairs in the multisig spending condition, so that
the verifying algorith will hash them all in the right order when verifying the
address.

When signing a sponsored transaction, the origin spending condition signatures
are calculated first, and the sponsor spending conditions are calculated second.
When the origin key(s) sign, the set the sponsor spending condition to a
specially-crafted "signing sentinel" structure.  This structure is a
single-signature spending condition, with a hash mode equal to 0x00, an
address and signature of all 0's, a fee rate and a nonce equal to 0, and a
public key encoding byte equal to 0x00.  This way, the origin commits to the
fact that the transaction is sponsored without having to know anything about the
sponsor's spending conditions.

When sponsoring a transaction, the sponsor uses the same algorithm as above to
calculate its signatures.  This way, the sponsor commits to the signature(s) of
the origin when calculating its signatures.

When verifying a transaction, the implementation verifies the sponsor spending
condition (if present), and then the origin spending condition.  It effectively
performs the signing algorithm again, but this time, it verifies signatures and
recovers public keys.

0. Extract the public key(s) and signature(s) from the spending condition.
1. Clear the spending condition.
2. Serialize the transaction into a byte sequence, and hash it to form an
   initial `sighash`.
3. Calculate the `presign-sighash` from the `sighash`, authorization type byte,
   fee rate, and nonce.
4. Use the `presign-sighash` and the next (public key encoding byte,
   ECDSA recoverable signature) pair to recover the public key that generated it.
5. Calculate the `postsign-sighash` from `presign-sighash`, the signature, public key encoding
   byte, 
6. Repeat steps 3-5 for each signature, so that all of the public keys are
   recovered.
7. Verify that the sequence of public keys hash to the address, using
   the address's indicated public key hashing algorithm.

When verifying a sponsored transaction, the sponsor's signatures are verified
first.  Once verified, the sponsor spending condition is set to the "signing
sentinal" value in order to verify the origin spending condition.

## Blocks

Blocks are batches of transactions proposed by a single Stacks leader.  The
Stacks leader gathers transactions from the peer network (by means of a
_mempool_), selects the ones they wish to package together into the next block
("mines" them), and then announces the block to the rest of the peer network.

A block is considered valid if (1) it is well-formed, (2) it contains a valid
sequence of transactions -- i.e. each transaction's state-transitions are
permitted, and (3) it follows the rules described in this document below.

Per SIP 001, there are two kinds of blocks: anchored blocks, and streamed
microblcoks.  An anchored block is comprised of the following two fields:

* A **block header**
* A list of one or more **transactions**, encoded as:
   * A 4-byte length, counting the number of transactions,
   * A coinbase transaction, with an anchor mode of `0x01` or `0x03`,
   * Zero or more additional transactions, all of which must have an anchor mode
     byte set to either `0x01` or `0x03`.

A _block header_ is encoded as follows:
* A 1-byte **version number** to describe how to validate the block.
* The **cumulative work score** for this block's fork, described below.
* An 80-byte **VRF proof** which must match the burn commitment transaction on the burn
  chain (in particular, it must hash to its VRF seed), described below.
* A 32-byte **parent block hash**, which must be the SHA512/256 hash of the last _anchored_ block
  that precedes this block in the fork to which this block is to be appended.
* A 32-byte **parent microblock hash**, which must be the SHA512/256 hash of the last _streamed_
  block that precedes this block in the fork to which this block is to be appended.
* A 2-byte **parent microblock sequence number**, which indicates the sequence
  number of the parent microblock to which this anchored block is attached.
* A 32-byte **transaction Merkle root**, the SHA512/256 root hash of a binary Merkle tree
  calculated over the sequence of transactions in this block (described below).
* A 32-byte **state Merkle root**, the SHA512/256 root hash of a MARF index over the state of
  the blockchain (see SIP-004 for details).
* A 20-byte **microblock public key hash**, the Hash160 of a compressed public key whose private
  key will be used to sign microblocks during the peer's tenure.

The _VRF proof_ field contains the following fields:
* A 32-byte **Gamma** Ristretto point, which itself is a compressed Ed25519
  curve point (see https://ristretto.group).
* A 16-byte **c scalar**, an unsigned integer (encoded big-endian)
* A 32-byte **s scalar**, an unsigned integer mod 2^255 - 19 (big-endian)

The _cumulative work score_ contains the following two fields:
* An 8-byte unsigned integer that encodes the sum of all burnchain tokens
  burned or transferred in this fork of the Stacks blockchain (i.e. by means of
  proof-of-burn or proof-of-transfer, whichever is in effect).
* An 8-byte unsigned integer that encodes the total proof-of-work done in this
  fork of the burn chain.

In-between two consecutive anchored blocks in the same fork there can exist
zero or more Stacks microblocks.

A _microblock_ is comprised of two fields:
* A **microblock header**,
* A length-prefixed list of transactions, all of which have an
  anchor mode set to `0x02` or `0x03`.  This is comprised of:
   * A 4-byte length, which counts the number of transactions,
   * Zero or more transactions.

Each _microblock header_ contains the following information:
* A 1-byte **version number** to describe how to validate the block.
* A 2-byte **sequence number** as a hint to describe how to order a set of
  microblocks.
* A 32-byte **parent microblock hash**, which is the SHA512/256 hash of the previous signed microblock
  in this stream.
* A 32-byte **transaction Merkle root**, the SHA512/256 root hash of a binary Merkle tree
  calculated over this block's sequence of transactions.
* A 65-byte **signature** over the block header from the Stacks peer that produced
  it, using the private key whose public key was announced in the anchored
  block.  This is a recoverable ECDSA secp256k1 signature, whose recovered
  compressed public key must hash to the same value as the parent anchor block's microblock
  public key hash field.

For both blocks and microblocks, a block's hash is calculated by first
serializing its header to bytes, and then calculating the SHA512/256 hash over those bytes.

### Block Validation

The hash of the anchored block's header is written to the burn chain via a block commitment
transaction, per SIP 001.  When a well-formed anchored block is received from the peer
network, the peer must confirm that:

* The block header hashes to a known commitment transaction that won
  cryptographic sortition.
* All transactions are well-formed and have the appropriate anchor byte.
* All transactions, when assembled into a Merkle tree, hash to the given
  transaction Merkle root.
* The first transaction is a coinbase transaction.
* The block version is supported.
* The cumulative work score is equal to the sum of all work
  scores on this fork.
* The block header's VRF proof hashes to the burn commitment transaction's VRF
  seed.  Note that this is the VRF seed produced by the burnchain block just before the
  burnchain block that contains the block commitment; it is _not_ the parent
  Stacks block's VRF seed.

If any of the above are false, then there is _no way_ that the block can be
valid, and it is dropped.

Once an block passes this initial test, it is queued up for processing in a
"staging" database.  Blocks remain in this staging database
until there exists a chain tip to which to append
the block (where the chain tip in this case refers both to the parent anchored
block and parent microblock).

An anchored block is _processed_ and either _accepted_ or _rejected_ once its
parent anchored block _and_ its parent microblocks are available. 
To accept the anchored block, the peer applies the parent microblock stream's
transactions to the chain state, followed by the anchored block's transactions.
If the resulting state root matches the block's state root, then the block is
valid and the leader is awarded the anchored block's coinbase and 60% of the
microblock stream's transaction fees, released over a maturation period
(per SIP 001).  The microblock stream and anchored block are marked as
_accepted_ and will be made available for other peers to download.

Not every anchored block will have a parent microblock stream.  Anchored blocks
that do not have parent microblock streams will have their parent microblock
header hashes set to all 0's, and the parent microblock sequence number set to
0.

### Microblock Validation

When a well-formed microblock arrives from the peer network, the peer 
first confirms that:

* The parent anchored block is either fully accepted, or is queued up.
* The parent anchored block's leader signed the microblock.

If all these are true, then the microblock is queued up for processing.  It will
be processed when its descendent anchored block is ready for processing.

As discussed in SIP 001, a Stacks leader can equivocate while packaging
transactions as microblocks by deliberately creating a microblock stream fork.
This will be evidenced by the discovery of either of the following:

* Two well-formed, signed microblocks with the same parent hash
* Two well-formed, signed microblocks with the same sequence number

If such a discovery is made, the microblock stream is truncated to the last
microblock before the height in the microblock stream of the equivocation, and
this microblock (or any of its predecessor microblocks in the stream) remain
viable chain tips for subsequent leaders to build off of.  In the mean time,
anyone can submit a poison-microblock transaction with both signed headers in
order to (1) destroy the equivocating leader's coinbase and fees, and (2) receive
5% of the destroyed tokens as a reward, provided that the poison-microblock
transaction is processed before the block reward becomes spendable by the
equivocating leader.

Because microblocks are released quickly, it is possible that they will not
arrive in order, and may even arrive before their parent microblock.  Peers are
expected to cache well-formed microblocks for some time, in order to help ensure that
they are eventually enqueued for processing if they are legitimate.

Valid microblocks in the parent stream may be orphaned by the child anchored block, i.e. 
because the leader didn't see them in time to build off of them.
If this happens, then the orphaned microblocks are dropped.

## Block Processing

Block processing is the act of calculating the next materialized view of the
blockchain, using both the anchored block and the parent microblcok stream
that connects it to its parent anchored block.
Processing the anchored block entails applying all of the transactions of its ancestor
microblocks, applying all of the anchored transactions,
and verifying that the cryptographic digest of the materialized view encoded
in the anchored block header matches the cryptographic digest calculated by applying
these transactions.

To begin _processing_ the anchored block and its parent microblock stream,
the peer must first ensure that:

* It has received all microblocks between the parent anchored block and the
  newly-arrived anchored block.
* The microblocks are well-formed.
* The microblocks are contiguous.  That is:
   * The first microblock's sequence number is 0, and its parent block hash is
     equal to the parent anchored block's hash.
   * The *i*th microblock's parent block hash is equal to the block hash of the
     *i-1*th microblock.
   * The *i*th microblock has a sequence number that is equal to 1 + the
     sequence number of the *i-1*th microblock.
   * The last microblock's hash and sequence number match the anchored block's
     parent microblock hash and parent microblock sequence number.
   * There are at most 65536 microblocks per epoch.

If all of these are true, then the peer may then proceed to process the microblocks' transactions.

To process a microblock stream, the peer will do the following for each
microblock:

1. Verify that each transaction authorization is valid.  If not, then reject and
   punish the previous Stacks leader.
2. Verify that each paying account has sufficient STX to pay their transaction
   fees.  If not, then reject and punish the previous Stacks leader.
3. For each transaction, grant the previous Stacks leader 40% of the transaction
   fee, and the current leader 60% of the tranasction fee.  This encourages the
leader that produced the current anchored block to build on top of as many
of the parent's microblocks as possible.

If a microblock contains an invalid transaction, then parent block's leader forfeits their 
block reward.  The deepest valid microblock remains a valid chain tip to which
subsequent anchored blocks may be attached.

Once the end of the stream is reached, the peer processes the anchored block.
To process the anchored block, the peer will process the state-transitions of
each transaction iteratively.  To do so, it will first:

1. Verify that each transaction authorization is valid.  If not, then the block
   and any of its descendent microblocks will be rejected, and the leader
punished by forfeiting the block reward.
2. Verify that each paying account has sufficient assets to pay their advertised
   fees.  If one or more do not, then reject the block and its descendent
microblocks and punish the leader.
3. Determine the *K*-highest offerred _STX fee rate per computation_ from all
   transactions in the parent microblock stream and the anchored block, as
measured by computational work.  Use the *K+1*-highest rate to find the price paid by
these top-*K* transactions, and debit each spending account by this rate
multiplied by amount of computation used by the transaction.  All other
transactions' spending accounts are not debited any fee.

A Stacks epoch has a fixed budget of "compute units" which the leader fills up.
The fee mechanism is designed to encourage leaders to fill up their epochs with
transactions while also encouraging users to bid their honest valuation of the
compute units (see [1] for details).  To do so, the Stacks peer measures a block
as *F%* full, where *F* is the fraction of compute units consumed in its epoch.
If the block consumes less than some protocol-defined fraction of
the compute units, the block is considered "under-full."

Leaders who produce under-full blocks are not given the full coinbase, but
instead given a fraction of the coinbase determined by how under-full the block
was (where an empty block receives 0 STX).  In addition, the fee rate assessed
to each transaction in the epoch is set to a protocol-defined minimum rate,
equal to the minimum-relay fee rate.  This is to encourage leaders to fill
up their epochs with unconfirmed transactions, even if they have low fees.

Stacks leaders receive all anchored block transaction fees exclusively, as well
as 40% of the microblock transaction fees they produce, as well as 60% of the
microblock transaction fees they validate by building upon. 

Leaders do not receive their block rewards immediately.  Instead, they must
mature for 100 Stacks epochs before they become spendable.

### Calculating the Materialized View

Once the microblock stream and anchored block transactions have been validated,
and the peer has determined that each paying account has sufficient funds
to pay their transaction fees, the peer will process the contained Clarity
code to produce the next materialized view of the
blockchain.  The peer determines that the previous leader processed them
correctly by calculating a cryptographic digest over the resulting materialized
view of the blockchain state.  The digest must match the digest provided in the
anchored block.  If not, then the anchored block and its parent microblock
stream are rejected, and the previous leader is punished.

Fundamentally, the materialized view of a fork is a set of sets of
key/value pairs.  Each set of key/value pairs is calculated in the service
of _light clients_ who will want to query them.  In this capacity,
the Stacks peer tracks the following sets of key/value pairs:

* the mapping between account addresses and their nonces and asset maps
* the mapping between fully-qualified smart contract names and a bundle of
  metadata about them (described below).
* the mapping between fully-qualified smart contract data keys and their 
  associated values. 

The first set of key/value pairs is the **account state**.  The Stacks peer
calculates an index over all accounts in each fork as they are created.

The second set of key/value pairs is the **smart contract context state**.  It maps the
_fully-qualified name_ of the smart contract to:
   * the transaction ID that created the smart contract (which can be used to
     derive the contract account address and to query its code),

The fully-qualified name of a smart contract is composed of the c32check-encoded
standard account address that created it, followed by an ASCII period `.`, as well
as an ASCII-encoded string chosen by the standard account owner(s) when the contract
is instantiated (subject to the constraints mentioned in the above sections).  Note that all
fully-qualified smart contract names are globally unique -- the same standard
account cannot create two smart contracts with the same name.

The third set of key/value pairs is the **smart contract data state**.
It maps the _fully-qualified_ data keys to their values. This stores
all data related to a smart contract: the values associated with data
map keys, the current value of any data variables, and the ownership
of fungible and non-fungible tokens. The construction of these keys and
values is described below.

All sets of key/value pairs are stored in the same MARF index.  Keys are
prefixed with the type of state they represent in order to avoid key collisions
with otherwise-identically-named objects.

When a key/value pair is inserted into the MARF, the hash of its key is
calculated using the MARF's cryptographic hash function in order to determine
where to insert the leaf.  The hash of the value is inserted as the leaf node,
and the (hash, leaf) pair is inserted into the peer's data store.  This ensures
that the peer can query any key/value pair on any fork it knows about in
constant-time complexity.

The text below describes the canonical encoding of key/value pairs that will be
inserted into the MARF.

#### Calculating a Fully-Qualified Object Name

All objects' fully-qualified names start with the type of object they are,
followed by an ASCII period `.`.  This can be the ASCII string "account",
"smart-contract", "data-variable", or "data-map".

Within an object type, a c32check-encoded addresses act as "namespaces" for keys in the state.  In all
sets of key/value pairs, an ASCII period `.` is used to denote the separation between
the c32check-encoded address and the following name.  Note that the c32 alphabet
does _not_ include the ASCII period.

#### Clarity Value Representation

Clarity values are represented through a specific binary encoding.  Each value
representation is comprised of a 1-byte type ID, and a variable-length
serialized payload.  The payload itself may be composed of additional Clarity
values.

The following type IDs indicate the following values:
* 0x00: 128-bit signed integer
* 0x01: 128-bit unsigned integer
* 0x02: buffer
* 0x03: boolean `true`
* 0x04: boolean `false`
* 0x05: standard principal
* 0x06: contract principal
* 0x07: Ok response
* 0x08: Err response
* 0x09: None option
* 0x0a: Some option
* 0x0b: List
* 0x0c: Tuple

The serialized payloads are defined as follows:

**128-bit signed integer**

The following 16 bytes are a big-endian 128-bit signed integer

**128-bit unsigned integer**

The following 16 bytes are a big-endian 128-bit unsigned integer

**Buffer**

The following 4 bytes are the buffer length, encoded as a 32-bit unsigned big-endian
integer.  The remaining bytes are the buffer data.

**Boolean `true`**

No bytes follow.

**Boolean `false`**

No bytes follow.

**Standard principal**

The next byte is the address version, and the following 20 bytes are the
principal's public key(s)' Hash160.

**Contract Principal**

The next byte is the address version, the following 20 bytes are a Hash160, the
21st byte is the length of the contract name, and the remaining bytes (up to
128, exclusive) encode the name itself.

**Ok Response**

The following bytes encode a Clarity value.

**Err Response**

The following bytes encode a Clarity value.

**None option**

No bytes follow.

**Some option**

The following bytes encode a Clarity value.

**List**

The following 4 bytes are the list length, encoded as a 32-bit unsigned
big-endian integer.  The remaining bytes encode the length-given number of
concatenated Clarity values.

**Tuple**

The following 4 bytes are the tuple length, encoded as a 32-bit unsigned
big-endian integer.  The remaining bytes are encoded as a concatenation of tuple
items.  A tuple item's serialized representation is a 
Clarity name (a 1-byte length and up to 128 bytes (exclusive) of valid Clarity
name characters) followed by a Clarity value.

#### Calculating the State of an Account

An account's canonical encoding is a set of key/value pairs that represent the
account's nonce, STX tokens, and assets owned.

The nonce is encoded as follows:

* Key: the string `"vm-account::"`, a c32check-encoded address, and the string
  `"::18"`
* Value: a serialized Clarity `UInt`

Example: `"vm-account::SP2RZRSEQHCFPHSBHJTKNWT86W6VSK51M7BCMY06Q::18"` refers to
the nonce of account `SP2RZRSEQHCFPHSBHJTKNWT86W6VSK51M7BCMY06Q`.

The STX balance is encoded as follows:

* Key: the string "vm-account::", a Principal Address (see below), and the string
  `"::19"`
* Value: a serialized Clarity `UInt`

Example: `"vm-account::SP2RZRSEQHCFPHSBHJTKNWT86W6VSK51M7BCMY06Q::19"` refers to
the STX balance of account `SP2RZRSEQHCFPHSBHJTKNWT86W6VSK51M7BCMY06Q`.

A fungible token balance owned by an account is encoded as follows:

* Key: the string `"vm::"`, the fully-qualified contract identifier, the string `"::2::"`,
  the name of the token as defined in its Clarity contract, the string `"::"`, and the
Principal Address of the account owning the token (see below).
* Value: a serialized Clarity `UInt`

Example: `"vm::SP13N5TE1FBBGRZD1FCM49QDGN32WAXM2E5F8WT2G.example-contract::2::example-token::SP2RZRSEQHCFPHSBHJTKNWT86W6VSK51M7BCMY06Q"`
refers to the balance of `example-token` -- a fungible token defined in contract `SP13N5TE1FBBGRZD1FCM49QDGN32WAXM2E5F8WT2G.example-contract` -- 
that is owned by account `SP2RZRSEQHCFPHSBHJTKNWT86W6VSK51M7BCMY06Q`.

A non-fungible token owned by an account is encoded as follows:

* Key: the string `"vm::"`, the fully-qualified contract identifier, the string `"::4::"`,
  the name of the token as defined in its Clarity contract, the string `"::"`,
and the serialized Clarity value that represents the token.
* Value: a serialized Clarity Principal (either a Standard Principal or a Contract Principal)

Example: `"vm::SP13N5TE1FBBGRZD1FCM49QDGN32WAXM2E5F8WT2G.example-contract::4::example-nft::\x02\x00\x00\x00\x0b\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64"` 
refers to the non-fungible token `"hello world"` (which has type `buff` and is
comprised of 11 bytes), defined in Clarity contract `SP13N5TE1FBBGRZD1FCM49QDGN32WAXM2E5F8WT2G.example-contract`
as a type of non-fungible token `example-nft`.

A Principal Address is either a c32check-encoded address in the case of standard principal, or a c32check-encoded address, followed by an ASCII period `.`, and an ASCII-encoded string for a contract principal.

#### Calculating the State of a Smart Contract

Smart contract state includes data variables, data maps, the contract code, and
type metadata.  All of this state is represented in the MARF via a layer of indirection.

Contract and type metadata is _not_ committed to by the MARF.  The MARF only
binds the contract's fully-qualified name to a "contract commitment" structure,
comprised of the contract's source code hash and the block height at which it
was instantiated.  This contract commitment, in turn, is used to refer to
implementation-defined contract analysis data, including the computed AST, cost
analysis, type information, and so on.

A contract commitment structure is comprised of the SHA512/256 hash of the
contract source code body (taken verbatim from the transaction), and the block
height at which the transaction containing it was mined.  The contract
commitment is serialized as follows:

* Bytes 0-64: the ASCII-encoding of the hash
* Bytes 65-72: the ASCII-encoding of the block height, itself as a big-endian
  unsigned 32-bit integer.

Example: The contract commitment of a contract whose code's SHA512/256 hash is
`d8faa525ecb3661e7f88f0bd18b8f6676ec3c96fcd5915cf47d48778da1b7ce0` at block
height 123456 would be `"d8faa525ecb3661e7f88f0bd18b8f6676ec3c96fcd5915cf47d48778da1b7ce0402e0100"`.

When processing a new contract, the Stacks node only commits to the serialized
contract commitment structure, and stores its analysis data separately.  For
example, the reference implementation uses the contract commitment structure as
a key prefix in a separate key/value store for loading and storing its contract
analysis data.

The MARF commits to the contract by inserting this key/value pair:

* Key: the string `"clarity-contract::", followed by the fully-qualified
  contract identifier.
* Value: A serialized `ContractCommitment` structure.

Example: `"clarity-contract::SP13N5TE1FBBGRZD1FCM49QDGN32WAXM2E5F8WT2G.example-contract"` 
refer to the contract commitment for the contract
`SP13N5TE1FBBGRZD1FCM49QDGN32WAXM2E5F8WT2G.example-contract`.

### Cryptographic Commitment

The various key/value sets that make up the materialized view of the fork are
each indexed within the same MARF.  To validate an anchored block, each Stacks
peer will:

* Load the state of the MARF as of the anchored block's parent anchored block.
* Insert a mapping between this anchored block's height and a sentinel anchor 
  hash (see below)
* Insert a mapping between the parent anchored block's height and its "anchor
  hash" derived from both the parent block's hash and the burnchain block that
  selected it (see below)
* Process all transactions in this anchored block's parent microblock stream,
  thereby adding all keys and values described above to the materialized view.
* Process all transactions in the anchored block, thereby adding all keys and
  values described above to the materialized view.
* Insert the rewards from the latest now-matured block (i.e. the
  leader reward for the Stacks block 100 epochs ago in this fork) into the
leader rewards contract in the Stacks chain boot code.  This rewards the leader
and all users that burned in support of the leader's block.

Once this process is complete, the Stacks peer checks the root hash of its MARF
against the root hash in the anchored block.  If they match, then the block is
accepted into the chain state.  If they do not match, then the block is invalid.

#### Measuring Block Height

Stacks counts its forks' lengths on a per-fork basis within each fork's MARF.
To do so, a leader always inserts four key/value pairs into the MARF when it
starts processing the next cryptographic commitment:  two to map the block's parent's height to
its anchor hash and vice versa, two to map this block's height to a sentinel 
anchor hash (and vice versa), and one to represent this block's height.
These are always added before processing any transactions.

The anchored block's _anchor hash_ is the SHA512/256 hash of the anchored block's
header concatenated with the hash of the underlying burn chain block's header.
For example, if an anchored block's header's hash is
`7f3f0c0d5219f51459578305ed2bbc198588758da85d08024c79c1195d1cd611`, and the
underlying burn chain's block header hash is
`e258d248fda94c63753607f7c4494ee0fcbe92f1a76bfdac795c9d84101eb317`, then the
(litte-endian) anchor hash would be
`7fbeb26cae32d96dbc1329f7e59f821b2c99b0a71943e153c071906ca7205f5f`.  In the case
where Bitcoin is the burn chain, the block's header hash is the double-SHA256 of
its header, in little-endian byte order (i.e. the 0's are trailing).

When beginning to process the anchored block (and similarly, when a leader
begins to produce its anchored block), the peer adds the following key/value
pairs to the MARF, in this order:

* Key: The string
  `"_MARF_BLOCK_HEIGHT_TO_HASH::af425f228a92ebe4d7741b129bb2c2f4326179f682da305b030250ccea9d4cd5"`
* Value: the height of the current Stacks block, encoded as a 4-byte
  little-endian 32-bit integer

The hash `af425f228a92ebe4d7741b129bb2c2f4326179f682da305b030250ccea9d4cd5` is
the sentinel anchored hash.  It is the SHA512/256 hash of a 64 `0x01` bytes --
equivalent to calculating an anchored hash from a Stacks block header and a burn
chain block header whose hashes were both `0101010101010101010101010101010101010101010101010101010101010101`.

* Key: The string `"_MARF_BLOCK_HASH_TO_HEIGHT::"`, followed by the ASCII string
  representation of the block height
* Value: the 32-byte sentinel anchor hash

Example: The key `"_MARF_BLOCK_HEIGHT_TO_HASH:124"` would map to the sentinel
anchor hash if the Stacks block being appended was the 124th block in the fork.

* Key: The string `"_MARF_BLOCK_HEIGHT_SELF"`
* Value: the ASCII representation of the block's height.

Example: The key `"_MARF_BLOCK_HEIGHT_SELF"` would map to the string `"123"` if
this was the 123rd block in this fork.

* Key: The string `"_MARF_BLOCK_HEIGHT_TO_HASH::"`, followed by the ASCII string
representation of the anchored block's parent's height.  Note that when
processing an anchored block, the parent's block hash will be known, so the
sentinel anchor hash is _not_ used.  The only exception is the boot block (see
below)
* Value: The 32-byte anchor hash of the block

Example: The key `"_MARF_BLOCK_HEIGHT_TO_HASH::123"` would map to the anchor
hash of the 123rd anchored Stacks block.

* Key: The string "_MARF_BLOCK_HASH_TO_HEIGHT::"`, followed by 64 characters in
  the ASCII range `[0-9a-f]`.
* Value: The little-endian 32-bit block height

Example: The key `"_MARF_BLOCK_HASH_TO_HEIGHT::7fbeb26cae32d96dbc1329f7e59f821b2c99b0a71943e153c071906ca7205f5f"` 
would map to the height of the block whose anchored hash was
`7fbeb26cae32d96dbc1329f7e59f821b2c99b0a71943e153c071906ca7205f5f`.

Using these five key/value pairs, the MARF is able to represent the height of
a fork terminating in a given block hash, and look up the height of a block in a
fork, given its anchor hash.

### Processing the Boot Block

The first-ever block in the Stacks v2 chain is the **boot block**.  It contains
a set of smart contracts and initialization code for setting up miner reward
maturation, for handling BNS names, for migrating BNS state from Stacks v1, and
so on.

When processing the boot block, the anchor hash will always be
`8aeecfa0b9f2ac7818863b1362241e4f32d06b100ae9d1c0fbcc4ed61b91b17a`, which is
equal to the anchor hash calculated from a Stacks block header hash and a
burnchain block header hash of all 0's.  The `_MARF_BLOCK_HASH_TO_HEIGHT::0` key
will be mapped to this ASCII-encoded hash, the key `_MARF_BLOCK_HASH_TO_HEIGHT::8aeecfa0b9f2ac7818863b1362241e4f32d06b100ae9d1c0fbcc4ed61b91b17a` 
will be mapped to `"0"`, and `_MARF_BLOCK_HEIGHT_SELF` will be mapped to `"0"`.  After these three  keys are inserted, the block is
processed like a normal Stacks anchored block.  The boot block has no parent,
and so it will not have height-to-hash mappings for one.

When processing a subsequent block that builds directly on top of the boot
block, the parent Stacks block header hash should be all 0's.

### References

[1] Basu, Easley, O'Hara, Sirer. [Towards a Functional Fee Market for Cryptocurrencies](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=3318327)
