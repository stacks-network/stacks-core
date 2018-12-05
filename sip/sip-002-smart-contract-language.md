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
2. A set of transactions which operate within the data-space of the
   smart contract, though they may call transactions from other smart
   contracts.

This smart contracting language differs from most other smart
contracting languages in two important ways:

1. The language _is not_ intended to be compiled. The LISP language
   described in this document is the specification for correctness.
2. The language _is not_ Turing complete. This allows us to guarantee
   that static analysis of programs to determine properties like
   runtime cost and data usage can complete successfully.

## Specifying Transactions

A smart contract definition is specified in a LISP language with the
following limitations:

1. Recursion is illegal and there is no `lambda` function.
2. Looping may only be performed via `map`, `filter`, or `fold`
3. The only atomic types are booleans, integers, fixed length
   buffers, and principals
4. There is additional support for lists of the atomic types,
   however the only variable length lists in the language appear as
   transaction inputs (i.e., there is no support for list operations
   like append or join).
5. Variables may only be created via `let` binding and there
   is no support for mutating functions like `set`.
6. Defining of constants and functions are allowed for simplifying
   code. However, these are purely syntactic. If a definition cannot be
   inlined, the contract will be rejected as illegal.
7. Transactions are specified via `define-tx` statement with function
   names. Arguments to the function must specify their types.

If a transaction returns `true`, then it is considered valid, and any
changes made to the blockchain state will be materialized. If a
transaction returns `false`, the transaction will be considered
invalid, and the transaction will have _no effect_ on the smart
contract's state, except for a transaction fee debit (in the case of
on-chain transactions).

## Inter-Contract Calls

A smart contract may call functions from other smart contracts using a
`(contract-call)` function. This function accepts a function name and
the smart contract's _identifier_ as input.  A smart contract's
identifier is a hash of the smart contract's definition, represented
as a Stacks address with a specific "smart contract" version byte. The
smart contract identifier is a _principal_.

For example, to call the function `register-name` in a smart contract,
you would use:

```scheme
(contract-call
    'SC3H92H297DX3YDPFHZGH90G8Z4NPH4VE8E83YWAQ
    'register-name
    name-to-register)
```

The following limitations are imposed on contract calls:

1. No dynamic dispatch. At the time of the smart contract creation,
   any contracts being called must be specified. Future designs may
   enable this by allowing contract principals to be supplied as
   transaction arguments, however, on initial release, we believe
   dynamic invocation to be too dangerous to support.
2. Called smart contracts _must_ exist at the time of creation.
3. No cycles may exist in the call graph of a smart contract. This
   prevents recursion (and re-entrancy bugs). Such structures can
   be detected with static analysis of the call graph, and will be
   rejected by the network.

A key benefit of the static analyzability of this smart contracting
language is that _all_ transactions that can possibly be called from
the outermost transaction can be known _a priori_ so that a user can
be warned about all side effects before signing a transaction.

## Principals and Transaction Verification

The language provides a primitive for checking whether or not the
smart contract transaction was signed by a particular
_principal_. Principals are a specific type in the smart contracting
language which represent a signing entity (roughly equivalent to a
Stacks address). The signature itself is not checked by the smart
contract, but by the VM. A smart contract function can use a globally
defined variable to obtain the current transaction's signer:

```scheme
tx-sender
```

Importantly, the `tx-sender` variable does not change during
inter-contract calls. This means that if you call a transaction in a
given smart contract, that transaction is able to make calls into
other smart contracts on your behalf. This enables a wide variety of
applications, but it comes with some dangers for users of smart
contracts. However, as mentioned before, the static analysis
guarantees of our smart contracting language allow clients to know a
priori which transactions a given smart contract will ever call. Good
clients should always warn users about any potential side effects
of a given transaction.

Note that most assets in the smart contracting language and blockchain
will be "owned" by objects of the principal type, meaning that any
object of the principal type may own an asset. For the case of
public-key hash and multi-signature Stacks addresses, a given
principal can operate on their assets by issuing a signed transaction
on the blockchain. _Smart contracts_ may also be principals
(reprepresented by the smart contract's identifier), however, there is
no private key associated with the smart contract, and it cannot
broadcast a signed transaction on the blockchain. In order to allow
smart contracts to authorize transactions with the smart contract's
own principal, smart contracts may use the special function:

```scheme
(contract-send-tx (...))
```

This function will execute the commands passed as an argument with the
`tx-sender` set to the _contract's_ principal, rather than the current
sender. It returns the return value of the provided commands.

## Stacks Transaction Primitives

To interact with Stacks balances, smart contracts may call the
`(stacks-transfer!)` function. This function will attempt to transfer
from the current principal to another principal:


```scheme
(stacks-transfer!
  to-send-amount
  recipient-principal)
```

This function itself
_requires_ that the operation have been signed by the transfering
principal. The `integer` type in our smart contracting language is an
8-byte unsigned integer, which allows it to specify the maximum amount
of microstacks spendable in a single Stacks transfer.

Like any other smart contract transaction, this function call returns
true if the transfer was successful, and false otherwise.

## Data-Space Primitives

Data within a smart contract's data-space is stored within
`maps`. These stores relate a typed-tuple to another typed-tuple
(almost like a typed key-value store). As opposed to a table data
structure, a map will only associate a given key with exactly one
value. Values in a given mapping are set or fetched using:

1. `(fetch-entry map-name key-tuple)` - This fetches the value
  associated with a given key in the map, or returns `'null` if there
  is no such value.
2. `(set-entry! map-name key-tuple value-tuple)` - This will set the
  value of `key-tuple` in the data map
3. `(insert-entry! map-name key-tuple value-tuple)` - This will set
  the value of `key-tuple` in the data map if and only if an entry
  does not already exist.
4. `(delete-entry! map-name key-tuple)` - This will delete `key-tuple`
   from the data map

We chose to use data maps as opposed to other data structures for two
reasons:

1. The simplicity of data maps allows for both a simple
implementation within the VM, and easier reasoning about
transactions. By inspecting a given transaction definition, it is
clear which maps will be modified and even within those maps, which
keys are affected by a given transaction.
2. The interface of data maps ensures that the return types of map
operations are _fixed length_, which is a requirement for static
analysis of smart contracts' runtime, costs, and other properties.

A smart contract defines the data schema of a data map with the
`defmap` call. The `defmap` function may only be called in the
top-level of the smart-contract (similar to `define`). This
function accepts a name for the map, and a definition of the structure
of the key and value types. Each of these is a list of `(name, type)`
pairs, and they specify the input and output type of `fetch-entry`.
Types are either the values `'principal`, `'integer`, `'bool` or
the output of a call to `(buffer n)`, which defines an n-byte
fixed-length buffer. 

### Record Type Syntax

To support the use of _named_ fields in keys and values, our language
allows the construction of named tuples using a function `(tuple ...)`,
e.g.,

```
(define imaginary-number-a (tuple #real 1 #i 2))
(define imaginary-number-b (tuple #real 2 #i 3))

```

This allows for creating named tuples on the fly, which is useful for
data maps where the keys and values are themselves named tuples. To
access a named value of a given tuple, the function `(get #name
tuple)` will return that item from the tuple.


# Static Analysis

One of the design goals of our smart contracting language was the
ability to statically analyze smart contract transactions to get
accurate upper-bound estimates of transaction costs (i.e., runtime and
storage requirements) as a function of input lengths. By limiting the
types supported, the ability to recurse, and the ability to iterate,
we believe that the language as presented is amenable to such static
analysis based on initial investigations.

The essential step in demonstrating the possibility of
accurate and useful analysis of our smart contract definitions is
demonstrating that any function within the language specification has
an output length bounded by a constant factor of the input length. If
we can demonstrate this, then statically computing runtime or space
requirements involves merely associating each function in the language
specification with a way to statically determine cost as a function of
input length.

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
_fetch-entry_ will always return an object whose size is equal
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

## Measuring Transaction Costs for Fee Collection


# Example: Simple Naming System

To demonstrate the expressiveness of this smart contracting language,
let's look at an example smart contract which implements a simple
naming system with just two kinds of transactions: _preorder_
and _register_. The requirements of the system are as follows:

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
(define burn-address '1111111111111111111114oLvT2)
(define (price-function name)
  (if (< name 1e5) 1000 100))

(defmap name-map 
  ((name integer)) ((buyer principal)))
(defmap preorder-map
  ((name-hash (buffer 160)))
  ((buyer principal) (paid integer)))

(define-tx (preorder 
           (name-hash (buffer 20))
           (name-price integer))
  (if (stacks-transfer!
        name-price burn-address)
      (insert-entry! preorder-map
        (tuple #name-hash name-hash)
        (tuple #paid name-price
               #buyer tx-sender))
      false))

(define-tx (register 
           (recipient-principal principal)
           (name integer)
           (salt integer))
  (let ((preorder-entry
          (fetch-entry preorder-map
                         (tuple #name-hash (hash160 name salt))))
        (name-entry 
          (fetch-entry name-map (tuple #name name))))
    (if (and
         ;; must be preordered
         (not (eq? preorder-entry) 'null)
         ;; name shouldn't *already* exist
         (eq? name-entry 'null)
         ;; preorder must have paid enough
         (<= (price-funcion name) 
             (get #paid preorder-entry))
         ;; preorder must have been the current principal
         (eq? tx-sender
              (get #buyer preorder-entry)))
         (begin
           (insert-entry! name-table
             (tuple #name name)
             (tuple #owner recipient)))
         false)))
```


Note that Blockstack PBC intends to supply a full BNS (Blockstack
Naming System) smart contract, as well as formal proofs that certain
desirable properties hold (e.g. "names are globally unique", "a
revoked name cannot be updated or transferred", "names cost stacks
based on their namespace price function", "only the principal can
reveal a name on registration", etc.).
