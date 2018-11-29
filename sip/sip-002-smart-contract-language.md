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
7. Transactions are specified via `define` statement with function
   names beginning with `tx-`. Arguments to the function must specify
   their types.

If a transaction returns `true`, then it is considered valid, and any
changes made to the blockchain state will be materialized. If a
transaction returns `false`, the transaction will be considered
invalid, and the transaction will have _no effect_ on the smart
contract's state, except for a transaction fee debit (in the case of
on-chain transactions).

## Verifying Signing Principles

The language provides a primitive for checking whether or not the
smart contract transaction was signed by a particular
_principle_. Principles are a representation of a signing entity
(roughly equivalent to a Stacks address). The signature itself is
not checked by the smart contract, but by the VM. To check whether a
given principle has signed the transaction, a transaction may call

```scheme
(signed-by? principle)
```

This returns `true` or `false`. Importantly, to support inter-contract
calls, this function returns `true` if the _outermost_ transaction was
signed by the given principle. A key benefit of the static
analyzability of this smart contracting language is that _all_
transactions that can possibly be called from the outermost
transaction can be known _a priori_ so that a user can be warned about
all side effects before signing a transaction.

## Stacks Transaction Primitives

To interact with Stacks balances, smart contracts may call the
`(stacks-transfer!)` function. This function will attempt to transfer
from a given principle to another principle. This function itself
_requires_ that the operation have been signed by the transfering
principle. The `integer` type in our smart contracting language is
8-bytes, which allows it to specify the maximum amount of microstacks
spendable in a single Stacks transfer.

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
\subsection{Principals for Signature Validation}

We provide an additional primitive function \texttt{signed-by?} for
performing signature validation. This function returns true if the
given \textit{principal} signed the top-level transaction. A principal
is a string representation of an entity capable of producing a
verifiable signature. For example, in Bitcoin, principals are Bitcoin
addresses, and they could be a RIPEMD-160 hash of a public-key, or a
script-hash. We use the notion of principals to enable support at the
protocol level for many different kinds of signatories. For example,
if we want to continue to support multi-signature principals, the
protocol could support the standard Bitcoin p2sh multi-sig addresses,
and support for this would seamlessly be included in any contract.

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
chose instead to use a a compiler to translate from a a friendly
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

In this simple scheme, names are represented by integers, but in
practice, a buffer would probably be used.

```scheme
(define burn-address '1111111111111111111114oLvT2)
(define (price-function name)
  (if (< name 1e5) 1000 100))

(defmap name-map 
  ((name integer)) ((buyer principal)))
(defmap preorder-map
  ((name-hash (buffer 160)) (buyer principal))
  ((paid integer)))

(define (tx-preorder 
           (buyer-principal principle)
           (name-hash (buffer 20))
           (name-price integer))
  (if (stacks-transfer!
        buyer-principal name-price burn-address name-price)
      (insert-entry! preorder-map
        (tuple #name-hash name-hash
               #buyer buyer-principal)
        (tuple #paid name-price))
      false))

(define (tx-register 
           (buyer-principal principle)
           (recipient-principal principle)
           (name integer)
           (salt integer)
  (if (signed-by? buyer-principal)
    (let ((preorder-lookup
            (tuple #name-hash (hash160 name salt) 
                   #buyer      buyer-principal))
          (preorder-entry 
            (fetch-entry preorder-map preorder-lookup))
          (name-entry 
            (fetch-entry name-map (tuple #name name))))
      (if (and
           ;; must be preordered
           (not (eq? preorder-entry) 'null)
           ;; name shouldn't *already* exist
           (eq? name-entry 'null)
           ;; preorder must have paid enough
           (<= (price-funcion name) 
               (get #paid preorder-entry)))
          (begin
            (delete-entry! preorder-lookup)
            (insert-entry! name-table
              (tuple #name name)
              (tuple #owner recipient)))
          false))
    false)))
```
