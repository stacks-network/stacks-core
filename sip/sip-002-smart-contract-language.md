# Abstract

In order to support applications which require validation of some
pieces of their logic, we present a smart contracting language for use
with the Stacks blockchain. This smart contracting language can be
used on the Stacks blockchain to support programatic control over
digital assets within the Stacks blockchain (e.g., BNS names, Stacks
tokens, etc.)

While application-chains may use any smart-contract language that they
like, this smart contracting language's VM will be a part of
blockstack-core, and, as such, any blockstack-core node will be able to
validate application chains using this smart contracting language with
a simple configuration change.

This smart contracting language permits static analysis of any legal
smart contract to determine runtime costs. This smart contracting
language is not only Turing-incomplete (a requirement for such static
analysis to be guaranteed successful), but readily permits other kinds
of proofs to be made about the code as well.

# Design

A smart contract is composed of two parts:

1. A data-space, which is a set of tables of data which only the
   smart contract may modify
2. A set of functions which operate within the data-space of the
   smart contract, though they may call public functions from other smart
   contracts.

Users call smart contracts' public functions by broadcasting a
transaction on the blockchain which invokes the public function.

This smart contracting language differs from most other smart
contracting languages in two important ways:

1. The language _is not_ intended to be compiled. The LISP language
   described in this document is the specification for correctness.
2. The language _is not_ Turing complete. This allows us to guarantee
   that static analysis of programs to determine properties like
   runtime cost and data usage can complete successfully.

## Specifying Contracts

A smart contract definition is specified in a LISP language with the
following limitations:

1. Recursion is illegal and there is no `lambda` function.
2. Looping may only be performed via `map`, `filter`, or `fold`
3. The only atomic types are booleans, integers, fixed length
   buffers, and principals
4. There is additional support for lists of the atomic types, however
   the only variable length lists in the language appear as function
   inputs (i.e., there is no support for list operations like append
   or join).
5. Variables may only be created via `let` binding and there
   is no support for mutating functions like `set`.
6. Defining of constants and functions are allowed for simplifying
   code using `define-private` statement. However, these are purely
   syntactic. If a definition cannot be inlined, the contract will be
   rejected as illegal. These definitions are also _private_, in that
   functions defined this way may only be called by other functions
   defined in the given smart contract.
7. Functions specified via `define-public` statements are _public_
   functions.
8. Functions specified via `define-read-only` statements are _public_
   functions and perform _no_ state mutations. Any attempts to 
   modify contract state by these functions or functions called by
   these functions will result in an error.

Public functions return a Response type result. If the function returns
an `ok` type, then the function call is considered valid, and any changes
made to the blockchain state will be materialized. If the function
returns an `err` type, it will be considered invalid, and will have _no
effect_ on the smart contract's state. So if function `foo.A` calls
`bar.B`, and `bar.B` returns an `ok`, but `foo.A` returns an `err`, no
effects from calling `foo.A` materialize--- including effects from
`bar.B`. If, however, `bar.B` returns an `err` and `foo.A` returns an `ok`,
there may be some database effects which are materialized from
`foo.A`, but _no_ effects from calling `bar.B` will materialize.

Unlike functions created by `define-public`, which may only return
Response types, functions created with `define-read-only` may return
any type.

## List Operations

* Lists may be multi-dimensional (i.e., lists may contain other lists), however each
  entry of this list must be of the same type.
* `filter` `map` and `fold` functions may only be called with user-defined functions
  (i.e., functions defined with `(define-private ...)`, `(define-read-only ...)`, or
  `(define-public ...)`) or simple native functions (e.g., `+`, `-`, `not`).
* Functions that return lists of a different size than the input size
  (e.g., `(append-item ...)`) take a required _constant_ parameter that indicates
  the maximum output size of the function. This is enforced with a runtime check.

## Inter-Contract Calls

A smart contract may call functions from other smart contracts using a
`(contract-call?)` function.

This function returns a Response type result-- the return value of the called smart
contract function. Note that if a called smart contract returns an
`err` type, it is guaranteed to not alter any smart contract state
whatsoever. Of course, any transaction fees paid for the execution
of that function will not be returned.

We distinguish 2 different types of `contract-call?`:

* Static dispatch: the callee is a known, invariant contract available
on-chain when the caller contract is being deployed. In this case, the
callee's principal is provided as first argument, followed by the name
of the method and its arguments:

```scheme
(contract-call?
    'SC3H92H297DX3YDPFHZGH90G8Z4NPH4VE8E83YWAQ.registrar
    register-name
    name-to-register)
```

This approach must always be preferred, when adequate.
It makes static analysis easier, and eliminates the
potential for reentrancy bugs when the contracts are
being published (versus when being used).

* Dynamic dispatch: the callee is passed as an argument, and typed
as a trait reference (<A>).

```scheme
(define-public (swap (token-a <can-transfer-tokens>)
                     (amount-a uint)
                     (owner-a principal)
                     (token-b <can-transfer-tokens>)
                     (amount-b uint)
                     (owner-b principal)))
     (begin
         (unwrap! (contract-call? token-a transfer-from? owner-a owner-b amount-a))
         (unwrap! (contract-call? token-b transfer-from? owner-b owner-a amount-b))))
```

Traits can either be locally defined:

```scheme
(define-trait can-transfer-tokens (
    (transfer-from? (principal principal uint) (response uint)))
```

Or imported from an existing contract:

```scheme
(use-trait can-transfer-tokens
    'SC3H92H297DX3YDPFHZGH90G8Z4NPH4VE8E83YWAQ.contract-defining-trait.can-transfer-tokens)
```

Looking at trait conformance, callee contracts have two different paths.
They can either be "compatible" with a trait by defining methods
matching some of the methods defined in a trait, or explicitely declare
conformance using the `impl-trait` statement:

```scheme
(impl-trait 'SC3H92H297DX3YDPFHZGH90G8Z4NPH4VE8E83YWAQ.contract-defining-trait.can-transfer-tokens)
```

Explicit conformance should be prefered when adequate.
It acts as a safeguard by helping the static analysis system to detect
deviations in method signatures before contract deployment.

The following limitations are imposed on contract calls:

1. On static dispatches, callee smart contracts _must_ exist at the time of creation.
2. No cycles may exist in the call graph of a smart contract. This
   prevents recursion (and re-entrancy bugs). Such structures can
   be detected with static analysis of the call graph, and will be
   rejected by the network.
3. `contract-call?` are for inter-contract calls only. Situations
   where the caller is also the callee will result in abortion of
   the ongoing transaction.

## Principals and Owner Verification

The language provides a primitive for checking whether or not the
smart contract transaction was signed by a particular
_principal_. Principals are a specific type in the smart contracting
language which represent a spending entity (roughly equivalent to a
Stacks address). The signature itself is not checked by the smart
contract, but by the VM. A smart contract function can use a globally
defined variable to obtain the current principal:

```scheme
tx-sender
```

The `tx-sender` variable does not change during inter-contract
calls. This means that if a transaction invokes a function in a given
smart contract, that function is able to make calls into other smart
contracts without that variable changing. This enables a wide variety
of applications, but it comes with some dangers for users of smart
contracts. However, as mentioned before, the static analysis
guarantees of our smart contracting language allow clients to know a
priori which functions a given smart contract will ever call.

Another global variable, `contract-caller`, _does_ change during
inter-contract calls. In particular, `contract-caller` is the contract
principal corresponding to the most recent invocation of `contract-call?`.
In the case of a "top-level" invocation, this variable is equal to `tx-sender`.

Assets in the smart contracting language and blockchain are
"owned" by objects of the principal type, meaning that any object of
the principal type may own an asset. For the case of public-key hash
and multi-signature Stacks addresses, a given principal can operate on
their assets by issuing a signed transaction on the blockchain. _Smart
contracts_ may also be principals (reprepresented by the smart
contract's identifier), however, there is no private key associated
with the smart contract, and it cannot broadcast a signed transaction
on the blockchain.

In order to allow smart contracts to operate on assets it owns, smart
contracts may use the special function:

```scheme
(as-contract (...))
```

This function will execute the closure (passed as an argument) with
the `tx-sender` and `contract-caller` set to the _contract's_
principal, rather than the current sender. It returns the return value
of the provided closure. A smart contract may use the special variable
`contract-principal` to refer to its own principal.

For example, a smart contract that implements something like a "token
faucet" could be implemented as so:

```scheme
(define-public (claim-from-faucet)
  (if (is-none? (map-get claimed-before (tuple (sender tx-sender))))
      (let ((requester tx-sender)) ;; set a local variable requester = tx-sender
        (map-insert! claimed-before (tuple (sender requester)) (tuple (claimed true)))
        (as-contract (stacks-transfer! requester 1))))
      (err 1))
```

Here, the public function `claim-from-faucet`:

1. Checks if the sender has claimed from the faucet before
2. Assigns the tx sender to a requester variable
3. Adds an entry to the tracking map
4. Uses `as-contract` to send 1 microstack

The primitive function `is-contract?` can be used to determine
whether a given principal corresponds to a smart contract.

## Stacks Transfer Primitives

To interact with Stacks balances, smart contracts may call the
`(stacks-transfer!)` function. This function will attempt to transfer
from the current principal to another principal:


```scheme
(stacks-transfer!
  to-send-amount
  recipient-principal)
```

This function itself _requires_ that the operation have been signed by
the transferring principal. The `integer` type in our smart contracting
language is an 16-byte signed integer, which allows it to specify the
maximum amount of microstacks spendable in a single Stacks transfer.

Like any other public smart contract function, this function call
returns an `ok` if the transfer was successful, and `err` otherwise.

## Data-Space Primitives

Data within a smart contract's data-space is stored within
`maps`. These stores relate a typed-tuple to another typed-tuple
(almost like a typed key-value store). As opposed to a table data
structure, a map will only associate a given key with exactly one
value. Values in a given mapping are set or fetched using:

1. `(map-get map-name key-tuple)` - This fetches the value
  associated with a given key in the map, or returns `none` if there
  is no such value.
2. `(map-set! map-name key-tuple value-tuple)` - This will set the
  value of `key-tuple` in the data map
3. `(map-insert! map-name key-tuple value-tuple)` - This will set
  the value of `key-tuple` in the data map if and only if an entry
  does not already exist.
4. `(map-delete! map-name key-tuple)` - This will delete `key-tuple`
   from the data map

We chose to use data maps as opposed to other data structures for two
reasons:

1. The simplicity of data maps allows for both a simple implementation
within the VM, and easier reasoning about functions. By inspecting a
given function definition, it is clear which maps will be modified and
even within those maps, which keys are affected by a given invocation.
2. The interface of data maps ensures that the return types of map
operations are _fixed length_, which is a requirement for static
analysis of smart contracts' runtime, costs, and other properties.

A smart contract defines the data schema of a data map with the
`define-map` call. The `define-map` function may only be called in the
top-level of the smart-contract (similar to `define-private`). This
function accepts a name for the map, and a definition of the structure
of the key and value types. Each of these is a list of `(name, type)`
pairs, and they specify the input and output type of `map-get`.
Types are either the values `'principal`, `'integer`, `'bool` or
the output of a call to `(buffer n)`, which defines an n-byte
fixed-length buffer. 

This interface, as described, disallows range-queries and
queries-by-prefix on data maps. Within a smart contract function,
you cannot iterate over an entire map.

### Record Type Syntax

To support the use of _named_ fields in keys and values, our language
allows the construction of named tuples using a function `(tuple ...)`,
e.g.,

```
(define-constant imaginary-number-a (tuple (real 1) (i 2)))
(define-constant imaginary-number-b (tuple (real 2) (i 3)))

```

This allows for creating named tuples on the fly, which is useful for
data maps where the keys and values are themselves named tuples. To
access a named value of a given tuple, the function `(get #name
tuple)` will return that item from the tuple.

### Time-shifted Evaluations

The Stacks language supports _historical_ data queries using the
`(at-block)` function:

```
(at-block 0x0101010101010101010101010101010101010101010101010101010101010101
  ; returns owner principal of name represented by integer 12013
  ;  at the time of block 0x010101...
  (map-get name-map 12013))
```

This function evaluates the supplied closure as if evaluated at the end of
the supplied block, returning the resulting value. The supplied
closure _must_ be read-only (is checked by the analysis).

The supplied block hash must correspond to a known block in the same
fork as the current block, otherwise a runtime error will occur and the
containing transaction will _fail_. Note that if the supplied block
pre-dates any of the data structures being read within the closure (i.e.,
the block is before the block that constructed a data map), a runtime
error will occur and the transaction will _fail_.

## Library Support and Syntactic Sugar

There are a number of ways that the developer experience can be
improved through the careful addition of improved syntax. For example,
while the only atomic types supported by the smart contract language
are integers, buffers, booleans, and principals, so if a developer
wishes to use a buffer to represent a fixed length string, we should
support syntax for representing a buffer literal using something like
an ASCII string. Such support should also be provided by transaction
generation libraries, where buffer arguments may be supplied strings
which are then automatically converted to buffers. There are many
possible syntactic improvements and we expect that over the course
of developing the prototype, we will have a better sense for which
of those improvements we should support. Any such synactic changes
will appear in an eventual language specification, but we believe
them to be out of scope for this proposal.

# Static Analysis

One of the design goals of our smart contracting language was the
ability to statically analyze smart contracts to obtain accurate
upper-bound estimates of transaction costs (i.e., runtime and storage
requirements) as a function of input lengths. By limiting the types
supported, the ability to recurse, and the ability to iterate, we
believe that the language as presented is amenable to such static
analysis based on initial investigations.

The essential step in demonstrating the possibility of accurate and
useful analysis of our smart contract definitions is demonstrating
that any function within the language specification has an output
length bounded by a constant factor of the input length. If we can
demonstrate this, then statically computing runtime or space
requirements involves merely associating each function in the language
specification with a way to statically determine cost as a function of
input length.

Notably, the fact that the cost functions produced by static analysis
are functions of _input length_ means the following things:

1. The cost of a cross-contract call can be "memoized", such
   that a static analyzer _does not_ need to recompute any
   static analysis on the callee when analyzing a caller.
2. The cost of a given public function on a given input size
   _is always the same_, meaning that smart contract developers
   do not need to reason about different cases in which a given
   function may cost more or less to execute.

## Bounding Function Output Length

Importantly, our smart contracting language does not allow the
creation of variable length lists: there are no `list` or
`cons` constructors, and buffer lengths must be statically
defined. Under such requirements (and given that recursion is
illegal), determining the output lengths of functions is rather
directly achievable. To see this, we'll examine trying to compute the
output lengths for the only functions allowed to iterate in the
language:

```
outputLen(map f list<t>)     := Len(list<t>) * outputLen(f t)
outputLen(filter f list<t>)  := Len(list<t>)
outputLen(fold f list<t> s)  := Len(s)
```

Many functions within the language will output values larger than the
function's input, _however_, these outputs will be bound by
statically inferable constants. For example, the data function
_map-get_ will always return an object whose size is equal
to the specified value type of the map.

A complete proof for the static runtime analysis of smart contracts
will be included with the implementation of the language.

# Deploying the Smart Contract

Smart contracts on the Stacks blockchain will be deployed directly as
source code. The goal of the smart contracting language is that the
code of the contract defines the _ground truth_ about the intended
functionality of the contract. While seemingly banal, many systems
chose instead to use a compiler to translate from a friendly
high-level language to a lower-level language deployed on the
blockchain. Such an architecture is needlessly dangerous. A bug in
such a compiler could lead to a bug in a deployed smart contract when
no such bug exists in the original source. This is problematic for
recovery --- a hard fork to "undo" any should-have-been invalid
transactions would be contentious and potentially create a rift in the
community, especially as it will not be easy to deduce which contracts
exactly were affected and for how long. In contrast, bugs in the VM
itself present a more clear case for a hard fork: the smart contract
was defined correctly, as everyone can see directly on the chain, but
illegal transactions were incorrectly marked as valid.

# Virtual Machine API

From the perspective of other components of `blockstack-core`, the
smart contracting VM will provide the following interface:

```
connect-to-database(db)

publish-contract(
  contract-source-code)

  returns: contract-identifier

execute-contract(
  contract-identifier,
  transaction-name,
  sender-principal,
  transaction-arguments)

  returns: true or false if the transaction executed successfully
```

## Invocation and Static Analysis

When processing a client transaction, a `blockstack-core` node will do
one of two things, depending on whether that transaction is a contract
function invocation, or is attempting to publish a new smart contract.

### Contract function invocation

Any transaction which invokes a smart contract will be included in the
blockchain. This is true even for transactions which are
_invalid_. This is because _validating_ an invalid transaction is not
a free operation. The only exceptions to this are transactions which
do not pay more than either a minimum fee or a storage fee
corresponding to the length of the transaction. Transactions which do
not pay a storage fee and clear the minimum transaction fee are
dropped from the mempool.

To process a function invocation, `blockstack-core` does the following:

1. Get the balance of the sender's account. If it's less than the tx fee,
then `RETURN INVALID`.
2. Otherwise, debit the user's account by the tx fee.
3. Look up the contract by hash. If it does not exist, then `RETURN
   INVALID`.
4. Look up the contract's `define-public` function and compare the
   tx's arguments against it. If the tx does not call an existing
   method, or supplies invalid arguments, then `RETURN INVALID`.
5. Look up the cost to execute the given function, and if it is greater
   than the paid tx fee, `RETURN INVALID`.
6. Execute the public function code and commit the effects of running
   the code and `RETURN OK`

### Publish contract

A transaction which creates a new smart contract must pay a fee which
funds the static analysis required to determine the cost of the new
smart contract's public functions. To process such a transaction,
`blockstack-core` will:

1. Check the sender's account balance. If zero, then `RETURN INVALID`
2. Check the tx fee against the user's balance. If it's higher, then `RETURN INVALID`
3. Debit the tx fee from the user's balance.
4. Check the syntax, calculating the fee of verifying each code
   item. If the cost of checking the next item exceeds the tx fee, or
   if the syntax is invalid, then `RETURN INVALID`.
5. Build the AST, and assign a fee for adding each AST item. If the
   cost of adding the next item to the tree exceeds the tx fee (or if
   the AST gets too big), then `RETURN INVALID`.
6. Walk the AST. Each step in the walk incurs a small fee. Do the
   following while the tx fee is higher than the total cost incurred
   by walking to the next node in the AST:
   a. If the next node calls a contract method, then verify that
      the contract exists and the method arguments match the contract's
      `define-public` signature. If not, then `RETURN INVALID`.
   b. Compute the runtime cost of each node in the AST, adding it
      to the function's cost analysis.
7. Find all `define-map` calls to find all tables that need to
   exist. Each step in this incurs a small fee.
8. Create all the tables if the cost of creating them is smaller than
   the remaining tx fee. If not, then RETURN INVALID.
9. `RETURN OK`

## Database Requirements and Transaction Accounting

The smart contract VM needs to interact with a database somewhat
directly: the effects of an `map-insert!` or `map-set!` call are
realized later in the execution of the same transaction. The database
will need to support fairly fine-grained rollbacks as some contract
calls within a transaction's execution may fail, triggering a
rollback, while the transaction execution continues and successfully
completes other database operations.

The database API provided to the smart contract VM, therefore, must be
capable of (1) quickly responding to `map-get` queries, which are
essentially simply key-value _gets_ on the materialized view of the
operation log. The operation log itself is simply a log of the
`map-insert!` and `map-set!` calls. In addition to these
operations, the smart contract VM will be making token transfer calls.
The databasse log should track those operations as well.

In order to aid in accounting for the database operations created by a
given transaction, the underlying database should store, with each
operation entry, the corresponding transaction identifier. This will
be expanded in a future SIP to require the database to store enough
information to reconstruct each block, such that the blocks can be
relayed to bootstrapping peers.

# Clarity Type System

## Types

The Clarity language uses a strong static type system. Function arguments
and database schemas require specified types, and use of types is checked
during contract launch. The type system does _not_ have a universal
super type. The type system contains the following types:

* `(tuple (key-name-0 key-type-0) (key-name-1 key-type-1) ...)` -
  a typed tuple with named fields.
* `(list max-len entry-type)` - a list of maximum length `max-len`, with
  entries of type `entry-type`
* `(response ok-type err-type)` - object used by public functions to commit
  their changes or abort. May be returned or used by other functions as
  well, however, only public functions have the commit/abort behavior.
* `(optional some-type)` - an option type for objects that can either be
  `(some value)` or `none`
* `(buff max-len)` := byte buffer or maximum length `max-len`.
* `principal` := object representing a principal (whether a contract principal
  or standard principal).
* `bool` := boolean value (`true` or `false`)
* `int`  := signed 128-bit integer
* `uint` := unsigned 128-bit integer

## Type Admission

**UnknownType**. The Clarity type system does not allow for specifying
an "unknown" type, however, in type analysis, unknown types may be
constructed and used by the analyzer. Such unknown types are used
_only_ in the admission rules for `response` and `optional` types
(i.e., the variant types).

Type admission in Clarity follows the following rules:

* Types will only admit objects of the same type, i.e., lists will only
admit lists, tuples only admit tuples, bools only admit bools.
* A tuple type `A` admits another tuple type `B` iff they have the exact same
  key names, and every key type of `A` admits the corresponding key type of `B`.
* A list type `A` admits another list type `B` iff `A.max-len >= B.max-len` and
  `A.entry-type` admits `B.entry-type`.
* A buffer type `A` admits another buffer type `B` iff `A.max-len >= B.max-len`.
* An optional type `A` admits another optional type `B` iff:
  * `A.some-type` admits `B.some-type` _OR_ `B.some-type` is an unknown type:
    this is the case if `B` only ever corresponds to `none`
* A response type `A` admits another response type `B` if one of the following is true:
  * `A.ok-type` admits `B.ok-type` _AND_ `A.err-type` admits `B.err-type`
  * `B.ok-type` is unknown _AND_ `A.err-type` admits `B.err-type`
  * `B.err-type` is unknown _AND_ `A.ok-type` admits `B.ok-type`
* Principals, bools, ints, and uints only admit types of the exact same type.

Type admission is used for determining whether an object is a legal argument for
a function, or for insertion into the database. Type admission is _also_ used
during type analysis to determine the return types of functions. In particular,
a function's return type is the least common supertype of each type returned from any
control path in the function. For example:

```
(define-private (if-types (input bool))
  (if input
     (ok 1)
     (err false)))
```

The return type of `if-types` is the least common supertype of `(ok
1)` and `(err false)` (i.e., the most restrictive type that contains
all returns). In this case, that type `(response int bool)`. Because
Clarity _does not_ have a universal supertype, it may be impossible to
determine such a type. In these cases, the functions are illegal, and
will be rejected during type analysis.

# Measuring Transaction Costs for Fee Collection

Our smart contracting language admits static analysis to determine
many properties of transactions _before_ executing those
transactions. In particular, it allows for the VM to count the total
number of runtime operations required, the maximum amount of database
writes, and the maximum number of calls to any expensive primitive
functions like database reads or hash computations. Translating that
information into transaction costs, however, requires more than simply
counting those operations. It requires translating the operations into
a single cost metric (something like gas in Ethereum). Then, clients
can set the fee rate for that metric, and pay the corresponding
transaction fee. Notably, unlike Turing-complete smart contracting
languages, any such fees are known _before_ executing the transaction,
such that clients will no longer need to estimate gas fees. They will,
however, still need to estimate fee rates (much like Bitcoin clients
do today).

Developing such a cost metric is an important task that has
significant consequences. If the metric is a bad one, it could open up
the possibility of denial-of-service attacks against nodes in the
Stacks network. We leave the development of a cost metric to another
Stacks Improvement Proposal, as we believe that such a metric should
be designed by collecting real benchmarking data from something close
to a real system (such measurements will likely be collected through
a combination of hand-crafted benchmarks and fuzzing test suites).

### Maximum Operation Costs and Object Sizes

Even with a cost metric, it is a good idea to set maximums for the
cost of an operation, and the size of objects (like
buffers). Developing good values for constants such as maximum number
of database reads or writes per transaction, maximum size of buffers,
maximum number of arguments to a tuple, maximum size of a smart
contract definition, etc. is a process much like developing a
cost metric--- this is something best done in tandem with the 
production of a prototype. However, we should note that we do intend
to set such limits.


# Example: Simple Naming System

To demonstrate the expressiveness of this smart contracting language,
let's look at an example smart contract which implements a simple
naming system with just two kinds of transactions: _preorder_ and
_register_. The requirements of the system are as follows:

1. Names may only be owned by one principal
2. A register is only allowed if there is a corresponding preorder
   with a matching hash
3. A register transaction must be signed by the same principal who
   paid for the preorder
4. A preorder must have paid at least the price of the name. Names
   are represented as integers, and any name less than 100000 costs
   1000 microstacks, while all other names cost 100 microstacks.
5. Preorder hashs are _globally_ unique.

In this simple scheme, names are represented by integers, but in
practice, a buffer would probably be used.

```scheme
(define-constant burn-address '1111111111111111111114oLvT2)
(define-private (price-function name)
  (if (< name 1e5) 1000 100))

(define-map name-map 
  { name: uint } { buyer: principal })
(define-map preorder-map
  { name-hash: (buff 160) }
  { buyer: principal, paid: uint })

(define-public (preorder 
               (name-hash (buffer 20))
               (name-price integer))
  (if (and (is-ok? (stacks-transfer!
                    name-price burn-address))
           (map-insert! preorder-map
            (tuple (name-hash name-hash))
            (tuple (paid name-price)
                   (buyer tx-sender))))
      (ok 0)
      (err 1)))

(define-public (register 
               (recipient-principal principal)
               (name integer)
               (salt integer))
  (let ((preorder-entry
          (map-get preorder-map
                         (tuple (name-hash (hash160 name salt)))))
        (name-entry 
          (map-get name-map (tuple (name name)))))
    (if (and
         ;; must be preordered
         (not (is-none? preorder-entry))
         ;; name shouldn't *already* exist
         (is-none? name-entry)
         ;; preorder must have paid enough
         (<= (price-funcion name)
             (default-to 0 (get paid preorder-entry)))
         ;; preorder must have been the current principal
         (eq? tx-sender
              (expects! (get buyer preorder-entry) (err 1)))
         (map-insert! name-table
           (tuple (name name))
           (tuple (owner recipient))))
         (ok 0)
         (err 1))))
```


Note that Blockstack PBC intends to supply a full BNS (Blockstack
Naming System) smart contract, as well as formal proofs that certain
desirable properties hold (e.g. "names are globally unique", "a
revoked name cannot be updated or transferred", "names cost stacks
based on their namespace price function", "only the principal can
reveal a name on registration", etc.).
