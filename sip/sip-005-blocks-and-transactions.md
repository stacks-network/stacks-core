# SIP 005 Blocks, Transactions, and Accounts

## Preamble

Title: Blocks, Transactions, and Accounts

Author: Jude Nelson <jude@blockstack.com>

Status: Draft

Type: Standard

Created: 7/23/2019

License: BSD 2-Clause

## Abstract

This SIP describes the structure, validation, and lifecycle for transactions and blocks in
the Stacks blockchain, and describes how each peer maintains a materialized view
of the effects of processing all state-transitions encoded in the blockchain's sequence of
transactions.  It presents the account actor model for the Stacks blockchain, and
describes how accounts authorize and pay for processing transactions on the
network.

## Rationale

The Stacks blockchain is a replicated state machine.
A _transaction_ encodes a single state-transition on the
Stacks blockchain.  The Stacks blockchain's state evolves by materializing the
effects of a sequence of transactions' state-transitions.

Transactions in the Stacks blockchain encode various kinds of state-transitions,
the principal ones being:

* To instantiate a smart contract (see SIP 002)
* To invoke a public smart contract function
* To transfer assets between accounts

Processing transactions is not free.  Each step in the process of validating and
executing the transaction incurs a non-zero computational cost.  To incentivize 
peers and miners to execute transactions, the transaction's computational costs
are paid for by an _account_.

An _account_ is the logical entity that executes transactions.  A transaction's
execution is governed by three accounts, which may or may not be distinct:

* The **originating account** is the account that creates and sends
  the transaction.  This is always an account owned by a user.  Each
  transaction is _authorized_ by its originating account.

* The **paying account** is the account that is billed by the miner
  for the cost of validating and executing the transaction.  This is
  usually an account owned by a user, but it may also be an account
  owned by a smart contract.  Its address is identified in each
  transaction separately from the originating account.

* The **sending account** is the account that identifies _who_ is
  _currently_ executing the transaction. The sending account can
      change during the course of transaction execution via the Clarity
  function `as-contract`, which executes the provided code block as
  the _current contract's_ account. Each transaction's initial sending
  account is its originating account -- i.e. the account that
  authorizes the transaction.  Smart contracts determine the sending
  account's principal using the `tx-sender` built-in function.

This document frames accounts in the Stacks blockchain as actors that process
transactions in order to describe the lifecycle of a transaction.  The tasks
that a transaction carries out on behalf of the accounts executing it inform the
data that goes into the transaction, as well as the data that goes into a block.
As such, understanding blocks and transactions in the Stacks blockchain first
requires an understanding of accounts.

### Accounts

Transactions in the Stacks blockchains originate from, are paid for by, and
execute under the authority of accounts.  An account is fully
described by the following information:

* **Address**.  This is a versioned cryptographic hash that uniquely identifies the
  account.  The type of account (described below) determines what information is
hashed to derive the address.

* **Nonce**.  This is a Lamport clock, used for ordering the transactions
  originating and/or paying from an account, and thereby ensuring that a transaction's
state-transition is processed at most once.  The nonce counts the number of times
an account's owner(s) have created a _transaction authorization_ (see below).
The first transaction from an account will have a nonce value equal to 0,
the second will have a nonce value equal to 1, and so
on.  A valid transaction authorization from this account's owners must include the _next_ nonce
value of the account; when the transaction is accepted by the peer network, the
nonce increments in the materialized view of this account.

* **Assets**.  This is a mapping between all Stacks asset types and the
  quantities of each type owned by the account.  This includes the STX token, as
well as any other on-chain assets declared by a Clarity smart contract.  An
account may own assets that are declared _after_ the account is initialized.

All accounts for all possible addresses are said to exist, but nearly all of
them are "empty" -- they have a nonce value of 0, and their asset mappings
contain no entries.  The state for an account is lazily _materialized_ once
the Stacks peer network processes a transaction that _funds_ it.
That is, the account state is materialized only once a transaction's state-transition inserts
an entry into an account's assets mapping for some (possibly zero) quantity of some asset.
Even if the account depletes all asset holdings, it remains materialized.
Materialized accounts are distinguished from empty accounts in that the former
are all represented in a miner's commitment to its materialized view of the blockchain state
(described below).

### Account Types

The Stacks blockchain supports two kinds of accounts:

* **Standard accounts**.  These are accounts owned by one or more private keys.
  Only standard accounts can originate transactions.  A transaction originating
from a standard account is only valid if a threshold of its private keys sign
it.  The address for a standard account is the hash of this threshold value and
all allowed public keys (similar to how the hash of a Bitcoin script is used to
identify Bitcoins belonging to multiple public keys).

* **Contract accounts**.  These are accounts that are materialized whenever a
  smart contract is instantiated.  Each contract is paired with exactly one contract account.
It cannot originate transactions, but may serve as the sending account and/or the paying 
account of another transaction.  Its address is calculated from
the hash of the transaction that created it.

The purposes for providing support for contract accounts are two-fold:

* To allow programmatic control of on-chain assets in the service of a
  particular application.
* To allow contracts to fund the execution of a user's transactions (see below).

Both kinds of accounts may own on-chain assets.  However, the nonce of a
contract account must always be 0, since it cannot be used to create transaction
authorizations.

### Account Assets

As described in SIP 002, the Stacks blockchain supports on-chain assets as a
first-class data type -- in particular, _fungible_ and _non-fungible_ assets are
supported.  All assets (besides STX) are scoped to a particular contract, since 
they are created by contracts.  Within a contract, asset types are unique.
Therefore, all asset types are globally addressible via their in-contract
identifier and their contract's name.

Regardless of where asset types are declared, a particular instance of an asset 
belongs to exactly one account at all times (usually not the contract account of
the contract that defined it).  Once a contract declares an asset type,
instances of that asset can be sent to and owned by other accounts.

### Transactions

Transactions are the fundamental unit of execution in the Stacks blockchain.
Each transaction is originated from a standard account, and is retained in
the Stacks blockchain history for eternity.  Transactions are atomic -- they
either execute completely with respect to other transactions, or not at all.
Moreover, transactions are processed in the same total order by all correct
peers.

At its core, a transaction is a snippit of executable Clarity code and a list of
_post-conditions_ that must be true before the transaction is accepted.  The
transaction body supplies the Stacks blockchain this code, as well as all of
the necessary metadata to describe how the transaction should be executed.
The various types of Stacks transactions encode different metadata, and
thus have different validation rules (and associated fees).

All transactions are originated from a set of private keys that own a standard
account (even if it is not materialized).  The owner(s) of these
private keys sign the transaction, attach a _transaction fee_ to it, and
relay it to the Stacks peer network.  If the transaction is well-formed and the
transaction fee is sufficient to pay for the validation and executution the transaction, then all
Stacks peers relay the transaction to all other Stacks peers (so each peer has a
copy), and eventually, a Stacks miner will select the transaction for inclusion
in the longest fork's next block.  Once this happens, the state-transitions
encoded by the transaction are materialized in the blockchain state replicas in all
peers.

### Transaction Types

The key difference between Stacks transaction types is what functionality is
available to them from the Clarity VM (and by extension, what side-effects are
materializable).  The reasons for distinguishing between these types of
transactions are to make static analysis cheaper for certain common use-cases,
and by extension, make their transaction fees lower.

#### Type-1: Instantiating a Smart Contract

A type-1 transaction has unrestricted access to the Clarity VM,
and when successfully evaluated, will materialize a new smart contract
account.  Type-1 transactions are meant to instantiate smart contracts, and to
call into multiple smart contract functions and/or access their state
atomically.

#### Type-2: Calling an Existing Smart Contract

A type-2 transaction has restricted access to the Clarity VM.  A
type-2 transaction may only contain a single public function call (via
`contract-call!`), and may only supply literals as its
arguments. These transactions do _not_ materialize a contract account.

The intended use-case for a type-2 transaction is to invoke an existing public
smart contract function.  Because they have such restricted access to the
Clarity VM, they are much cheaper to execute compared to a type-1 transaction.

### Transaction Post-Conditions

A key use-case of smart contracts is to allow programmatic control over the
assets in one or more accounts.  However, where there is programmatic control,
there are bound to be bugs.  In the world of smart contract programming, bugs
are indistinguishable from outright scams, and both can have severe
consequences to the user's well-being.  In particular, bugs can 
destroy a user's assets and cause them to lose a lot of money.
Transaction post-conditions are a feature meant to limit the damage a bug can
do in terms of destroying a user's assets.

Post-conditions are intended to be used to force a transaction to abort if the
transaction would materialize changes to the originating account that are not
to the user's liking.  For example, a user may append a post-condition saying that
upon successful execution, their STX balance should have decreased by no more
than 1 STX.  If this were not the case, then the transaction would abort
and the user would only be billed for the transaction fee of processing it.
As another example, a user purchasing a BNS name may append a post-condition saying that upon
successful execution, the BNS name should be in their account asset map.  If it
isn't, then the seller will not receive payment for it.

Each transaction includes a field that describes zero or more post-conditions
that must be true over the set of materialized account asset tables in the
blockchain.  Each post-condition is a triple, containing:

* The **asset name**, i.e. the name of one of the assets in the originating
  account's asset map.
* The **comparator**, described below.
* The **literal**, an integer or boolean value used to compare instances of the
  asset against via the condition.  The type of literal depends on both the
  type of asset (fungible or non-fungible) and the comparator.

The Stacks blockchain supports the following two types of comparators:

* **Fungible asset changes** -- that is, a question of _how much_ the account's
  fungible asset balance increased or decreased as a result of the transaction's
  execution.  The contract can assert that the quantity of tokens increased,
  decreased, or stayed the same.  In addition, the contract can assert that the
  change was greater than, equal to, or less than a given amount.  If any fungible
  asset post-conditions are present, then such conditions are treated as a whitelist,
  meaning that any fungible tokens not present in the post-conditions are treated as
  "stays the same" constraints.
* **Non-fungible asset state** -- that is, a question of _whether or not_ the
  account owns a particular non-fungible asset when the transaction finishes
  executing.

Post-conditions are meant to be added by the user (or by the user's wallet
software) at the moment they sign and broadcast their transactions.  Because the
_user_ defines the post-conditions, and may do so _after_ the smart contract(s)
they invoke are already defined, the user has the power to protect themselves
from buggy or malicious smart contracts that would lose or steal their assets.
Specifically, this means that if a smart contract is later found to have a bug
that could be exploited to steal the user's assets, the
user would be able to rely on post-conditions as a mitigation until a newer
smart contract could be deployed.  Well-designed wallets would provide an
intuitive user interface for encoding post-conditions, as well as provide a set
of recommended mitigations based on whether or not the transaction would
interact with a known-buggy smart contract.

#### Example: Name Purchase

This post-condition encodes the requirement that a name "blocky.id" is
owned after the execution of a transaction, and at most 1 STX was paid.

```
[(STX, ft-decrease-by-at-most, 1),
 (BNS.name, nft-owns, "blocky.id")]
```

#### Post-Condition Encoding

Logically speaking, the post-conditions in a transaction are _representable_ as a single Clarity
statement that is evaluated immediately after the successful evaluation of the
transaction code body.  The post-conditions would be representable as a single
conjunction of a sequence of boolean statements containing only asset queries,
comparators, and literals.  This conjunction would be nested within an `(if
...)` statement that would evaluate an `(err ...)` if the conjunction was false
(i.e. at least one post-condition was false), thereby causing the transaction to
abort.

However, because we consider post-conditions to be such a vital safety feature,
post-conditions are encoded in the transaction _outside of_ the Clarity code
body.  In particular, they are encoded in a compressed format that losslessly
decompresses to the above Clarity code snippit.  Thus, post-conditions do not
pose a violation of the Stacks design principle of showing all code "as-is" in the
blockchain wire format.

The reasons for encoding post-conditions this way are three-fold.  First, by
treating post-conditions as a first-class transaction component, the protocol guarantees
that they will be applied regardless of the contained Clarity code.  While the
Clarity code can have its own statements that implement _de-facto_
post-conditions, the act of placing post-conditions on the originating account's
assets outside the code body guarantees that they will always be run, and will
always be unambiguous to anyone inspecting the transaction.
Second, by treating them as a separate field, we make it much easier for wallet developers to encode
them -- namely, the wallet does not need to consider or even access the
Clarity code body to process post-conditions.  Third, encoding post-conditions
separately from the code body allows us to make them cheaper to store and
evaluate than had they been defined as Clarity code.

#### Post-Condition Limitations

Post-conditions are not free, since validating, evaluating, and storing them
carries non-zero computational cost that scales linearly in the number of
post-conditions.  In addition, as mentioned, post-conditions only apply
to the originating account's assets.  If the user wants post-conditions
on other accounts or on non-asset state, they would need to be expressed in the Clarity code body.
Post-conditions are _not_ meant to be (or become) a domain-specific language for
encoding arbitrary post-conditions on arbitrary accounts -- they are _solely_
meant to help preserve the safety of the _originating account_'s assets.

Treating post-conditions as first-class transaction component strikes a balance
between the need for complex abort logic and the need for cheap but effective smart contract 
bug mitigation.  Any transaction's Clarity code body can already implement complex
sanity checks to trigger an abort if certain conditions are met.  But, we expect
that most users will send type-2 transactions to move assets to/from their
(originating) accounts and perform atomic swaps, so most such sanity checks would only apply to their
accounts in the first place.  By making this common case as easy as possible to
encode in transactions and as cheap as possible to evaluate (cheaper than
expressing directly in Clarity), the protocol encourages people to use it to protect
even low-value accounts.

### Transaction Fees

Validating and processing a transaction carries non-zero cost, which must be
paid for by a materialized account listed in the transaction.  In most
blockchains, this fee is paid for in the blockchain's native token.  The purpose
of the token in these cases is to act as a _decentralized rate-limiter_ -- as
more and more transactions are issued, users must pay higher and higher fees to
bid on their acceptance into a block.

Unlike most blockchains, the Stacks blockchain offers the following separate payment
methods for transaction fees:

* **Originator pays in STX**.  This is the most straightforward way of paying
  for a transaction.  The originating account that authorizes the transaction is
an existing standard account, and that standard account holds a quantity of STX
tokens that will be debited when the transaction's state-transitions are
materialized.  This is how most blockchains work today.

* **Originator pays in an on-chain asset**.  Unlike most blockchains, the Stacks
  blockchain has first-class support for users to pay transaction fees via _any_
on-chain asset.  In this payment mode, the originating account that authorizes
the transaction is an existing standard account (as before), but instead of
being debited STX, the transaction offers miners another asset instead, as well
as a proposed _exchange rate_ between that asset and STX.  The offerred asset and the
exchange rate are used by the peer network and miners to determine the
STX-denominated transaction fee.  When the transaction is mined, the standard
account is debited the offerred assets instead of STX.  This lets users pay for
transactions without having to own STX.

* **Another account sponsors.**  In this payment mode, another account offers to
  pay the transaction fee (either in STX or in an on-chain asset).  If the
transaction is accepted, this account will be debited the transaction fee instead.

The reason for offering these payment methods is to help users pay for
their transactions with whatever means they have.  For example, in existing
blockchains that support app tokens, many users will hold the app token but not
the native token.  The originator-pays-with-on-chain-asset payment option gives
these users the ability to pay for transaction fees without first having to
acquire some of the native token (which they may not even be aware exists).

Regardless of the payment method, the act of determining whether or not the
payer has enough balance to pay the given fee is the only operation the Stacks
peer network will carry out "for free" when relaying or validating a
transaction.  This operation is equivalent to querying an account for the
balance of a particular asset, and comparing it against the STX-denominated fee
(something that will be offerred by a peer's RPC interface anyway).

Each transaction offers a _maximum fee_ that the originator is willing to pay.
However, the fee that will actually be debited may be lower.  This is because in
the act of originating transactions, users are effectively placing bids on the
_fee rate_ -- the cost per unit of work in the Clarity VM.  When a collection
of transactions are mined into a single block, each transaction's account is
charged for the work done at the _lowest_ fee rate of all transactions mined.
The mechanics of determining the fee to pay to miners is described in a later
section.

#### Originator Pays in an On-Chain Asset

In order to pay miners in an asset other than STX, the miner must first be
willing to accept fees this way.  If the miner opts to mine such a transaction,
the STX-denominated fee is calculated using the offerred exchange rate 
in order to prioritize this transaction against other transactions paying in STX
or different assets.  This has the side-effect of allowing the miner to commit
to a STX-to-asset exchange rate in the act of mining the transaction.

Such transactions can only be mined as _batched transactions_ (see SIP 001) --
they cannot be streamed.  This is because different miners may accept different
assets, and accept them at different STX exchange rates.  Therefore, it is
impossible to split transaction fees between two miners.

#### (UNDER CONSIDERATION) Contract Pays Fee

**This section is under consideration and may be removed.**

A fourth payment option is under consideration:

* **Contract pays in STX**.  This payment option is specific to type-2
  transactions, is only available from contracts that support it,
is only available to principals authorized by the contract, and is only 
available for specific public functions within the contract. With this
payment method, the _contract account_ of the function being called is debited the
transaction fee in STX when the transaction is mined.  In order to support this,
the contract itself advertizes a maximum transaction fee, the list of sponsored
public functions, and the list of authorized principals who can have their fees
sponsored (each authorized principal corresponds to a standard account, but the
standard account does not need to be materialized).  This option gives users
the ability to send transactions without having to own any
on-chain assets at all.

The contract-pays-fee option enables _other users_ to pay for transaction fees.
This is meant to support users who do not own any on-chain assets at all, but
still need to send transactions.  By creating a contract that can fund other
users' transactions, other users (in particular, the contract's developer) can
opt to pay for them instead.

The latter payment option ("Contract Pays Fee") is only allowed for
type-2 transactions, and only if the originating account's principal is
authorized and only if the particular public function being invoked is
sponsored.

To advertize the availability of contract-pays-fee, a contract must include a
`(define-fees ...)` Clarity statement that names the public function that may
be sponsored by the contract, and the name of a data variable that
encodes the maximum fee.  In addition, the smart contract must run the 
`(fees-add-whitelist ...)` and `(fees-rm-whitelist ...)` Clarity functions to
add and remove principals who are allowed to have their type-2 transactions
sponsored.

The reason that the contract must whitelist principals who can be sponsored is
to prevent miners from stealing all of the contract funds.  Without a whitelist,
a miner can fill its block with spam type-2 transactions to claim the fees, at
the expense of users.  A whitelist makes this difficult -- a miner will need to
get its address whitelisted to carry out this attack, and even if they succeed,
a subsequent call to `(fees-rm-whitelist ...)` can be used to revoke the miner's
access.

Contracts that allow for sponsored transactions typically have a set of
"administration functions" that allow one or more administrator accounts to
change the maximum fee, and to add/remove principals from the whitelist.
Because anyone can create a smart contract, an expected design pattern for
sponsored transactions is to create a "library" contract that contains all of
the public functions that may be sponsored, and one or more "sponsor" contracts
that proxy calls to some of these public functions from their own sponsored
public functions.  Different sets of public functions in the library contract
can then be sponsored at different rates, for different principals, via multiple
sponsor contracts.  This way, a set of users of a particular contract can pool
their STX into a dedicated sponsor contract, so they can each send sponsored
transactions without having to have STX on-hand.

### Transaction Data

A transaction includes the following information:

* A **version number**, identifying the transaction type
* An **account address**, identifying the account that will pay for the
  transaction. It contains:
   * an _address version number_ for the address format scheme
   * the hash of version-specific account data, described below
* A **transaction authorization** structure, described below. It proves to the
  peer network that the originator has authorized the transaction, and that
the payer account (possibly different) has authorized authorize payment.
* A **transaction fee**, which itself contains:
   * the ID of the asset to spend
   * the quantity of the asset to spend (or 1 if it it a non-fungible asset)
   * the proposed exchange rate between STX and the asset (0 if the asset _is_
     STX)
* An **anchor mode**, identifying how the transaction should be mined
* A set of **post-conditions**, describing properties that must be true of the
  originating account's assets once the transaction finishes executing.
* A **code body** containing the Clarity code to execute
* A **smart contract name** if this is a type-1 transaction (empty if not)

#### Version Number

The version number of a transaction identifies the type of state-transition to
carry out.  It can be:

* `0`, in which case the transaction is a type-1 transaction
* `1`, in which case the transaction is a type-2 transaction

If this is a type-2 transaction, then the account address must be the contract's
account address.  Otherwise, the account address must be the address of a
standard account.

#### Account Address

This is a version number and a cryptographic hash, and identifies the account
that will pay the transaction fee.  The Stacks blockchain
supports the following version numbers:

* (UNDER CONSIDERATIN) `12`: This is a **contract address**, in which the account address matches a contract account, derived from
  the hash of the transaction that created it
* `20`: This is a **multisig address**, in which the account address matches a standard account derived from _n_
  public keys, of which _m < n_ must have signed the transaction (see
"transaction authorization")
* `22`: This is a **singlesig address**, in which the account address matches a standard account derived from exactly
  one public key, which must have signed the transaction (see "transaction
authorization")

Singlesig and multisig account addresses always correspond to standard accounts,
and are collectively referred to as a _standard address_.
Contract addresses always correspond to contract accounts.

The hash of a contract address is the RIPEMD160 hash of the transaction ID that
created the contract.

The hash of a multisig address is the RIPEMD160 hash of a Bitcoin multisig redeem
script.  All such accounts created _after_ the genesis block will have an
address hash equal to a pre-Segwit multisig pay-to-script-hash calculated over
the _compressed_ DER-encoded SECP256K1 public keys.  However, an
account created _before_ the genesis block (i.e. for Stacks v1) _may_ have an
address hash equal to either a pre-Segwit multisig pay-to-script-hash (possibly
with _uncompressed_ DER-encoded SECP256K1 public keys), or a
post-Segwit multisig pay-to-witness-script-hash pay-to-script-hash.  This is for
legacy compatibility reasons, since accounts that exist on Stacks v1 (realized
as a virtual chain on Bitcoin) must be ported to Stacks v2.

The hash of a singlesig address is the RIPEMD160 hash of the DER-encoded SECP256K1 public
key.  If the account was created _before_ the genesis block, then the 
public key may be compressed or uncompressed.  If the account was created
_after_ the genesis block, then the public key _must_ be compressed.

#### Transaction Authorization

Each transaction contains a transaction authorization structure, which is used
by the Stacks peer to identify the originating account and determine whether or
not it is allowed to carry out the encoded state-transition.  It contains:

* A "sponsored" flag as to whether or not the originating account or a separate paying
  account will be paying the transaction fee.
* The originator account's authorization
   * The next nonce of the originating account
   * The number of required signatures
   * The list of SECP256K1 public keys
   * The list of signatures
* The paying account's authorization, _if different from the originator_
   * The next nonce of the paying account
   * The number of required signatures
   * The list of SECP256K1 public keys
   * The list of signatures

The number of required signatures and the list of public keys uniquely
identifies a standard account, and can be used to generate its address per the
rules above.  The principal that owns the originating account (_not_ the transaction's
account address) is passed to the Clarity VM as `tx-sender`.

The originating account does not need to be materialized in all cases (see
below).  It only needs to be materialized if it will also be the account that
pays for the transaction fee.  If an authorization is provided for the 
paying account, then the paying account must be materialized and possess the 
asset that will be used to pay the transaction fee.

If the transaction is being sponsored by another account, then the sponsored
flag must be set, and the public keys and signature threshold in the paying
account's authorization must hash to the transaction's account address.
Otherwise, if the transaction's originating account is also the paying account,
then the sponsored flag must be unset, and the public keys and signature
threshold in the originating account's authorization must hash to the
transaction's account address.

_Signature Verification_

Regardless of which account pays the transaction fee, the signature verification
process is the same.  The number of public keys must be equal to the number of signatures,
and the number of public keys must be equal to or less than the number of required
signatures.  Calculating the signatures is an iterative process -- the _i_th
signature must be calculated from the transaction with all _i-1_ prior
public keys and signatures present.  Verifying the signatures is a matter of
verifying the `m`th signature with the `m`th public key, removing both the
signature and public key, and repeating the process for the `m-1`th signature.
If the `m-1`th public key does not match, then it will be dropped from
consideration and the `m-2`th public key will be attempted, and so forth.

If given, the paying account authorization signatures will be verified _before_ the
originating account's signatures.  That is, a transaction is sponsored by (1)
having the originator set the "sponsored" flag, (2) having the originator sign
the transaction, (3) having the sponsor set the transaction fee (below), and (4)
having the sponsor sign the transaction.

Test vectors are provided at the end of this SIP.

#### Transaction Fee

This structure describes the asset used to pay for processing this transaction.
It contains the following information:

* The fully-qualified name of the asset.  This includes the contract name and
  the asset name (if not STX).
* The quantity of the asset to send.  For non-fungible tokens, this is always
  `1`.
* A proposed exchange rate from the asset to STX (if the payment is in STX
  already, then this is `0`).

In order for this transaction to be accepted, the account
providing the payment must own a sufficient quantity of the asset
listed here.  If a miner is willing to accept
the asset as payment, then the paying account is debited the fee and the
transaction is processed.

(UNDER CONSIDERATION) If the paying account is a contract account, and the transaction fee is either
not in STX or has a transaction fee that is higher than the contract's
advertized fee, then the transaction is considered invalid and is dropped from
consideration.

The details of how the transaction fee itself is calculated are reserved for a
future SIP.  The topic is non-trivial, because the fee is calculated in part
from the computational complexity of validating and evaluating the transation's 
code body, and in part from the recent history of fees offered by other users.

#### Transaction Anchor Mode

This is a bit field that describes how the transaction is to be appended to the
Stacks blockchain.  Two modes are supported:

* **Batched** -- the transaction will be included in a block whose hash is
  anchored to the burn chain, per SIP 001.  The flag for this is `0x01`.
* **Streamed** -- the transaction will be sent via a microblock.  The flag for
  this is `0x02`.
* **Either** -- the miner gets to choose how this transaction will be appended.
  The flag for this is `0x03` (i.e. `0x01 | 0x02`).

#### Transaction Post-Conditions

This is a lossless compressed representation of a Clarity code snippit that
evaluates to a `bool`.  If the result is `'false`, the transaction aborts,
regardless of the final output of the transaction.

The post conditions are encoded as a length prefix, and a concatenation of:

* asset name (as a length-prefixed string of ASCII-characters)
* comparator code (as 1 byte)
* value (absent for non-fungible assets; 8 bytes for fungible assets)

Comparators on changes to fungible asset balances are encoded according to the following rules:

* Bit `0x80` is set if the asset is expected to decrease, and cleared if the asset is expected to increase.
* Bit `0x01` is set if the amount of change can be _equal to_ the given literal.
* Bit `0x02` is set if the amount of change can be _greater than_ the given literal.
* Bit `0x04` is set if the amount of change can be _less than_ the given literal.

These bits can be bitwise-OR'ed together to produce the following meanings:

* `0x00`: "fungible asset balance did not change"
* `0x01`: "fungible asset balance increased by an amount _equal to_ the given amount"
* `0x02`: "fungible asset balance increased by an amount _greater than_ the given amount"
* `0x03`: "fungible asset balance increased by an amount _greater than or equal to_ the given amount"
* `0x04`: "fungible asset balance increased by an amount _less than_ the given amount"
* `0x05`: "fungible asset balance increased by an amount _less than or equal to_ the given amount"
* `0x81`: "fungible asset balance decreased by an amount _equal to_ the given amount"
* `0x82`: "fungible asset balance decreased by an amount _greater than_ the given amount"
* `0x83`: "fungible asset balance decreased by an amount _greater than or equal to_ the given amount"
* `0x84`: "fungible asset balance decreased by an amount _less than_ the given amount"
* `0x85`: "fungible asset balance decreased by an amount _less than or equal to_ the given amount"

Comparators on the states of non-fungible assets are encoded according to the
following rules:

* `0x00`: "non-fungible asset is absent from this account"
* `0x01`: "non-fungible asset is present from this account"

If the comparator operates on a fungible token (including STX), then the value
will be encoded as 8 bytes.  Otherwise, no value will be necessary.

#### Transaction Code Body

This is a length-prefixed byte array that contains the Clarity code to execute,
encoded as ASCII.  Transactions with 0-byte code bodies are invalid, as are
transactions whose code bodies contain un-printable ASCII characters.

### Transaction Smart Contract Name

If this is a type-1 transaction, then the smart contract it instantiates must be
given a name.  This name must be a byte string of printable ASCII characters,
and must be unique among the set of names given to smart contracts created
by this standard account.  Moreover, it must not have the ASCII character `.` in
its name, as this is used as a delimiter for addressing functions, data
variables, and data maps in contracts.

### Blocks

Blocks are batches of transactions proposed by a single Stacks leader.  The
Stacks leader gathers transactions from the peer network (by means of a
_mempool_), selects the ones they wish to package together into the next block
("mines" them), and then announces the block to the rest of the peer network.

A block is considered valid if (1) it is well-formed, (2) it contains a valid
sequence of transactions -- i.e. each transaction's state-transitions are
permitted, and (3) it follows the rules described in this document below.

Per SIP 001, there are two kinds of blocks: anchored blocks, and streamed
microblcoks.  Each anchored block contains the following information:

* A **block header**, containing the following data:
   * A **version number** to describe how to validate the block.
   * The **cumulative tunable proof score** for this block's fork.
   * A **VRF proof** which must match the burn commitment transaction on the burn
     chain (in particular, it must hash to its VRF seed)
   * A **parent block hash**, which must be the hash of the last _anchored_ block
     that precedes this block in the fork to which this block is to be appended.
   * A **parent microblock hash**, which must be the hash of the last _stremaed_
     block that precedes this block in the fork to which this block is to be appended.
   * A **transaction Merkle root**, the root hash of a binary Merkle tree
     calculated over the sequence of transactions in this block.
   * A **state Merkle root**, the root hash of a MARF index over the state of
     the blockchain.
   * A **microblock public key**, the public key whose private
     key will be used to sign microblocks during the peer's tenure.
* A sequence of _zero or more_ transactions, all of which have the "batched" bit
  set in their anchor modes.

Each microblock contains the following information:

* A **microblock header**, containing the following data:
   * A **version number** to describe how to validate the block.
   * A **sequence number** as a hint to describe how to order a set of
     microblocks.
   * A **parent microblock hash**, which is the hash of the previous signed microblock
     in this stream.
   * A **transaction Merkle root**, the root hash of a binary Merkle tree
     calculated over this block's sequence of transactions.
   * A **signature** over the block header from the Stacks peer that produced
     it, using the private key whose public key was announced in the anchored
     block.
* A sequence of _one or more_ transactions, all of which have the "streamed" bit
  set in their anchor modes.

Note that only anchored blocks commit to the materialized state of the
blockchain.  Microblocks do not need to do this.

#### Block Validation

The hash of the anchored block's header is written to the burn chain via a commitment
transaction, per SIP 001.  When a well-formed anchored block is received from the peer
network, the peer must confirm that:

* All transactions are well-formed and have their anchor flag set.
* All transactions, when assembled into a Merkle tree, hash to the given
  transaction Merkle root.

If any of the above are false, then there is _no way_ that the block can be
valid, and it is rejected.

To _accept_ the anchored block, the peer further ensures that:

* The block header hashes to a known commitment transaction.
* The block header's parent points to the parent block header hash identified by
  the block commitment transaction.
* The block version number is supported.
* The cumulative tunable proof score is equal to the sum of all tunable proof
  scores on this fork.
* The block header's VRF proof hashes to the burn commitment transaction's VRF
  seed.

If any of these are false, the peer will cache the anchored block for some time, but not
process it until it can determine all of the above.  The peer may refresh its
view of the burn chain and/or reprocess burn chain transactions.

Once the burn chain commitment transaction is sufficiently confirmed and validated,
 then peer can decide whether or not to accept the anchored block -- if so, it will remain
part of the peer's chain history forever.  This can only
happen if all of the above are true.  If any of the above are false after
the burn commitment is confirmed, then the block will be evicted from
the block cache and it will not be processed.

#### Block Processing

Block processing is the act of calculating the next materialized view of the
blockchain, using both the anchored block and the ancestor microblcok stream
that connects it to its parent anchored block.
Processing the anchored block entails applying all of the transactions of its ancestor
microblocks, applying all of the anchored transactions,
and verifying that the cryptographic digests of the materialized view encoded
in the anchored block match the cryptographic digests calculated by applying
these transactions.

To begin _processing_ the anchored block and its parent microblock stream,
the peer must first ensure that:

* It has received all microblocks between the parent anchored block and the
  newly-arrived anchored block.
* The microblocks are well-formed.
* The microblocks are valid.

An anchored block cannot be processed until the history of zero or more microblocks that
connects it to its anchored parent are present and validated.  If a block has no
microblocks between its anchored parent and itself, its parent microblock hash
field will be all 0's.

Before processing the anchored block, its parent microblock stream must be
validated.  In addition to ensuring that the microblocks in the stream are well-formed,
the peer makes sure that:

* Each microblock's parent header hash is equal to the hash of its parent's
  header.
* Each microblock's sequence number is one greater than that of its parent.

If either of these are not true, then the leader that produced them is
_punished_.  The first invalid microblock, all descendent microblocks,
and the anchored block are _rejected_, causing the dishonest Stacks leader
to forfeit the entire block reward for their tenure -- the coinbase from the 
previous anchored block, its transaction fees, as well as the transaction fees
from the valid microblocks.  However both the parent (valid)
anchored block and valid parent microblock stream remain part of
the chain history, and may be built upon.

Even if all blocks are valid, a dishonest leader may create two or more forks in the microblock stream by
producing two different microblocks with the same sequence number and parent.
This will result in a similar punishment, as well as a reward for the leader
that reports it.  If a fork is produced in the parent microblock
stream, and the current Stacks leader sees the conflicting microblock, then
it may (1) choose its preferred fork as part of the canonical chain history,
and (2) include the conflicting header in a specially-crafted transaction in
its block or microblock stream to prove that a fork occured.  In doing so,
the dishonest parent Stacks leader forefits all of its coinbase and transaction
fees from its tenure, and the current Stacks leader receives _F_% of the
forfeited reward.  This incentivizes honest leaders to report microblock forks.

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

The microblock parent may have valid children that get _orphaned_ by the arrival
of this block.  If this is the case, then the orphaned microblocks are dropped,
and the state-transitions they encoded are not applied.  However, no extra punishment
is inflicted for doing so -- the current Stacks leader simply forefeits the
transaction fees of the microblocks they orphaned.

To process the anchored block, the peer will process the state-transitions of
each transaction iteratively.  To do so, it will first:

1. Verify that each transaction authorization is valid.  If not, then the block
   and any of its descendent microblocks will be rejected, and the leader
punished.
2. Verify that each paying account has sufficient assets to pay their advertised
   fees.  If one or more do not, then reject the block and its descendent
microblocks and punish the leader.
3. Determine the lowest _STX fee rate per computation_ offered by the first _K_% of
   the transactions, as measured by computational work (if a transaction
straddles the _K_th percentile boundary, then include it in the first _K_%).
Use this to calculate the transaction fee for each of the first _K_% of transactions,
and debit each account the requisite number of offered assets.  Note that this
debit value will be _less than or equal to_ the advertised fee rate.
4. Determine the fees for the remaining _(1 - K)%_ of the transactions, as
   measured by computational work.  For each paying account referenced, debit
the account by the fee advertised.

If a block is less than _K_% full, _and_ there are enough pending transactions
to fill it to _K_% or higher, then no correct Stacks peer will relay the block.
However, if a block is less than _K_% full and there are not enough pending
transactions, then correct Stacks peers will relay it.  This is to ensure that
a leader will pick low-fee transactions even if there are few unconfirmed
transactions available when the block is mined.  This strategy also ensures that an
underfull block mined by a dishonest leader will be orphaned.

Stacks leaders receive the _(1 - K)%_ of transaction fees exclusively, as well
as 40% of the microblock transaction fees they produce, as well as 60% of the
microblock transaction fees they validate by building upon.  The _K_% of
transaction fees from anchored blocks are distributed among the next _B_ Stacks
leaders, where _B_ is a protocol-defined constant.  In expectation, a Stacks
leader that produces _b_ out of _B_ blocks produces _b/B_ of the cumulative
tunable proof score, and will receive _b/B * K_ fraction of the transaction fees
this way.  This technique, as well as the _K_% and _(1 - K)_% fee calculations, are both
implemented at the recommendation from [1] in order to both reduce transaction
fee variance for leaders as well as give users a fairer fee market.

### Calculating the Materialized View

Once the microblock stream and anchored block transactions have been validated,
and the peer has determined that each paying account has sufficient funds
to pay their transaction fees, the peer will process the contained Clarity
code to produce the next materialized view of the
blockchain.  The peer determines that the previous leader processed them
correctly by calculating a cryptographic digest over the resulting materialized
view of the blockchain.  The digest must match the digest provided in the
anchored block.  If not, then the anchored block and its parent microblock
stream are rejected, and the previous leader is punished.

In the act of executing the transactions' Clarity code, the Stacks peer
incrementally builds up (1) a materialized view of the state of the fork to
which the blocks were appended, and (2) an authenticated index over that view.
SIP 004 describes the structure of this index, and this section describes how
this index is built.

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
_fully-qualified name_ of the smart contract to a bundle of metadata,
which contains:
   * the transaction ID that created the smart contract (which can be used to
     derive the contract account address and to query its code),
   * all functions and constants defined by this contract
   * all data variables, data maps, and tokens defined by this contract

The fully-qualified name of a smart contract is composed of the c32check-encoded
standard account address that created it, as well as an ASCII-encoded string chosen by
the standard account owner(s) when the contract is instantiated.  Note that all
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

Clarity value's are represented through a specific JSON encoding, described with the
following JSON schema:

```json
{
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "ClarityValue",
    "anyOf": [
        {   "type": "object",
            "properties": {
                "type": { "const", "bool"},
                "value": { "type", "bool }
            },
            "required": ["type", "value"],
            "additionalProperties": false
        },
        {
            "type": "object", 
            "properties": {
                "type": { "const": "i128" },
                "value": { "type": "string" }
            },
            "required": ["type", "value"],
            "additionalProperties": false
        },
        {
            "type": "object", 
            "properties": {
                "type": { "const": "u128" },
                "value": { "type": "string" }
            },
            "required": ["type", "value"],
            "additionalProperties": false
        },
        {
            "type": "object", 
            "properties": {
                "type": { "const": "buff" },
                "value": { "type": "string" }
            },
            "required": ["type", "value"],
            "additionalProperties": false
        },
        {
            "type": "object", 
            "properties": {
                "type": { "const": "principal" },
                "value": { "type": "string" }
            },
            "required": ["type", "value"],
            "additionalProperties": false
        },
        {
            "type": "object", 
            "properties": {
                "type": { "const": "contract_principal" },
                "namespace": { "type": "string" },
                "name": { "type": "string" }
            },
            "required": ["type", "name", "namespace"],
            "additionalProperties": false
        },
        {
            "type": "object", 
            "properties": {
                "type": { "enum": ["ok", "err", "some"] },
                "value": {"$ref": "ClarityValue"}
            },
            "required": ["type", "value"],
            "additionalProperties": false
        },
        {
            "type": "object", 
            "properties": {
                "type": { "const": "none" }
            },
            "required": ["type"],
            "additionalProperties": false
        },
        {
            "type": "object", 
            "properties": {
                "type": { "const": "list" },
                "entries": { "type": "array", "items": { "$ref": "ClarityValue" } }
            },
            "required": ["type", "entries"],
            "additionalProperties": false
        },
        {
            "type": "object", 
            "properties": {
                "type": { "const": "tuple" },
                "entries": {
                    "type": "object",
                    "patternProperties": {
                        "^[A-Za-z_!+=/0-9-]+": { "$ref": "ClarityValue" }
                    }
                }
            },
            "required": ["type", "entries"],
            "additionalProperties": false
        }
    ]
}
```

JSON objects are created without newlines or tab characters, with a
single space between field names and their values, a single space
between commas and subsequent entries, and a single space of padding
after each `[` or `{` character, and an additional space of padding
before each `]` or `}` character.

`u128` and `i128` values are encoded as the hex representation of the
integer, with a `-` indicator for negative `i128` values. Buffers are
hex encoded. Principals are C32CHECK encoded account addresses.

#### Clarity Type Signature Representation

Clarity type signatures are represented with the same subset of JSON encoding
as Clarity Values.

IN PROGRESS: JSON schema for Clarity type signatures.

#### Clarity Code Body Representation

Clarity code bodies are represented with the same subset of JSON encoding as Clarity
Values. Code bodies are encoded with the Clarity symbolic representation.
Clarity symbolic representations are a recursive type with three types:

* Lists: these are lists of other Clarity symbolic representations (e.g., `(+ 1 2 3)` is
  a list of `+`, `1`, `2`, and `3`)
* Atoms: these are the atomic elements of Clarity code, i.e., `+`
* AtomValues: these are atomic elements containing literal Clarity values, i.e., `1`

Example:

```json
[ "+", { "type": "i128", "value": "1" }, { "type": "i128", "value": "2" }, { "type": "i128", "value": "3" } ]
```

IN PROGRESS: JSON schema for Clarity symbolic representations.

#### Calculating the State of an Account

An account's canonical encoding as a key/value pair in the account state
is as follows:

* Key: The string "account", a period, and a c32check-encoded address.
* Value: A typed netstring constructed as the concatenation of the
  encoded-nonce, and the account's sequence of asset/quantity pairs encoded as a list of tuples.
The sequence of asset/quantity pairs is determined by the order in the chain
history into which their mapping was materialized.

Example:  `"account.SP2RZRSEQHCFPHSBHJTKNWT86W6VSK51M7BCMY06Q"` refers to standard
account `SP2RZRSEQHCFPHSBHJTKNWT86W6VSK51M7BCMY06Q`.

#### Calculating the State of a Smart Contract

A smart contract's canonical encoding as a key/value pair in the smart contract
state is as follows:

* Key: The string "smart-contract", followed by a `.`, followed by the
  c32check-encoded address of the standard account that created it,
  followed by a `.`, followed by the ASCII-encoded name of the contract.
* Value: A specifically encoded JSON object containing the folllowing data:
   * The transaction ID, encoded as a buffer
   * a list of names of data variables this contract declares, in lexical order
   * a list of data map names this contract declares, in lexical order
   * a list of fungible asset names this contract declares, in lexical order
   * a list of non-fungible asset names this contract declares, in lexical order
   * a list of functions defined by this contract, in lexical order, paired with:
     * the function type (public, private, or public-read-only)
     * the list of argument type signatures
     * the function body
   * a list of constant names defined by this contract in lexical order, paired with
     their associated Clarity values.

Example: `"smart-contract.SP2RZRSEQHCFPHSBHJTKNWT86W6VSK51M7BCMY06Q.my-contract"` refers
to a smart contract created by standard account `SP2RZRSEQHCFPHSBHJTKNWT86W6VSK51M7BCMY06Q`
called `my-contract`.

#### Calculating the State of Smart Contract Data

Smart contract data is encoded as follows:

* Key: A string composed of the following elements, joined by `::` 
  * A string denoting the data type:
    * "data-variable"
    * "data-map"
    * "fungible-token"
    * "non-fungible-token"
  * The fully qualified contract name
  * The ASCII-encoded data name (e.g., the data-map name or variable
    name)
  * In the case of a data-map, fungible token, or non-fungible-token,
    a fourth string:
    * For data maps: the encoded Clarity value of the data map key.
    * For non-fungible-tokens: the encoded Clarity value identifying
      the specific non-fungible token.
    * For fungible-tokens: the encoded Clarity principal identifying
      an account entry in the fungible token's ownership table.

* Value: The encoded Clarity Value corresponding to the keyed data:
  * For data variables and data maps, this is simply the data associated
    with the variable or a specific key.
  * For fungible-tokens, it is the balance of the particular address.
  * For non-fungible-tokens, it is the current owner of the particular
    non-fungible-token.

Example: `"data-variable.SP2RZRSEQHCFPHSBHJTKNWT86W6VSK51M7BCMY06Q.my-contract.my-var"` 
refers to a data variable called `my-var`, which was declared in a smart contract called `my-contract`,
which was in turn created by the standard account `SP2RZRSEQHCFPHSBHJTKNWT86W6VSK51M7BCMY06Q`.

### Cryptographic Commitment

The various key/value sets that make up the materialized view of the fork are
each indexed within the same MARF.  To finish validating an anchored block,
the Stacks peer will:

* Insert an account key/value pair into the MARF whenever an
  account is materialized or updated (note that this will overwrite the previous
version of this account's state in the MARF).
* Insert a smart contract key/value pair into the MARF
  whenever a smart contract is instantiated.
* Insert a data variable key/value pair into the MARF
  whenever a data variable is assigned a value (overwriting the previous value
commitment).
* Insert a data map key/value pair into the MARF whenever the
  mapping is inserted, updated, or deleted.  

Once all transactions have been processed, the root hash of the MARF
is compared to the state Merkle root hash in the anchored
block.  If they are equal, then the block is accepted and all changes in both
its transactions and its parent microblock stream are materialized.  If not,
then the block and its parent microblock stream are rejected and the previous
Stacks leader is punished.

## Test Vectors

TBD

### References

[1] Basu, Easley, O'Hara, Sirer. [Towards a Functional Fee Market for Cryptocurrencies](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=3318327)
