---
layout: core
permalink: /:collection/:path.html
---
# Define functions and data maps
{:.no_toc}

Clarity includes _defines_  and native functions for creating user-defined functions. 

* TOC
{:toc}

## define and define-public functions

Functions specified via `define-public` statements are public functions. Functions without these designations, simple `define` statements, are private functions. You can run a contract's public functions directly via the `clarity-cli execute` command line directly or from other contracts. You can use the `clarity eval` or `clarity eval_raw` commands to evaluate private functions via the command line.

Public functions return a Response type result. If the function returns an `ok` type, then the function call is considered valid, and any changes made to the blockchain state will be materialized. If the function returns an `err` type, it is considered invalid, and has no effect on the smart contract's state. 

For example, consider two functions, `foo.A` and `bar.B` where the `foo.A` function calls `bar.B`, the table below shows the data materialization that results from the possible combination of return values:

<table class="uk-table">
  <tr>
    <th></th>
    <th>foo.A =&gt;</th>
    <th>bar.B</th>
    <th>Data impact that results</th>
  </tr>
  <tr>
    <th rowspan="2">Function returns</th>
    <td><code>err</code></td>
    <td><code>ok</code></td>
    <td>No changes result from either function.</td>
  </tr>
  <tr>
    <td><code>ok</code></td>
    <td><code>err</code></td>
    <td>Change from <code>foo.A</code> is possible; no changes from <code>foo.B</code> materialize.</td>
  </tr>
</table>

Defining of constants and functions are allowed for simplifying code using a define statement. However, these are purely syntactic. If a definition cannot be inlined, the contract is rejected as illegal. These definitions are also private, in that functions defined this way may only be called by other functions defined in the given smart contract.

## define-read-only functions

Functions specified via `define-read-only` statements are public. Unlike functions created by `define-public`, functions created with `define-read-only` may return any type. However, `define-read-only` statements cannot perform state mutations. Any attempts to modify contract state by these functions or functions called by these functions result in an error.

## define-map functions for data

Data within a smart contract's data-space is stored within maps. These stores relate a typed-tuple to another typed-tuple (almost like a typed key-value store). As opposed to a table data structure, a map only associates a given key with exactly one value.  A smart contract defines the data schema of a data map with the `define-map` function. 

```cl
(define-map map-name ((key-name-0 key-type-0) ...) ((val-name-0 val-type-0) ...))
```

Clarity contracts can only call the  `define-map` function in the top-level of the smart-contract (similar to `define`. This function accepts a name for the map, and a definition of the structure of the key and value types. Each of these is a list of `(name, type)` pairs. Types are either the values `'principal`, `'integer`, `'bool` or the output of one of the hash calls which is an n-byte fixed-length buffer.

To support the use of named fields in keys and values, Clarity allows the construction of tuples using a function `(tuple ((key0 expr0) (key1 expr1) ...))`, for example:

```cl
(tuple (name "blockstack") (id 1337))
```

This allows for creating named tuples on the fly, which is useful for data maps where the keys and values are themselves named tuples. To access a named value of a given tuple, the function (get #name tuple) will return that item from the tuple.

The `define-map` interface, as described, disallows range-queries and queries-by-prefix on data maps. Within a smart contract function, you cannot iterate over an entire map. Values in a given mapping are set or fetched using the following functions:

<table class="uk-table">
  <tr>
    <th>Function</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><code>(fetch-entry map-name key-tuple)</code></td>
    <td>Fetches the value associated with a given key in the map, or returns <code>'null</code> if there is none.</td>
  </tr>
  <tr>
    <td><code>(set-entry! map-name key-tuple value-tuple)</code></td>
    <td>Sets the value of key-tuple in the data map.</td>
  </tr>
  <tr>
    <td><code>(insert-entry! map-name key-tuple value-tuple)</code></td>
    <td>Sets the value of <code>key-tuple</code> in the data map if and only if an entry does not already exist.</td>
  </tr>
  <tr>
    <td><code>(delete-entry! map-name key-tuple)</code></td>
    <td>Removes the value associated with the input key for the given map.</td>
  </tr>
</table>

Data maps make reasoning about functions easier. By inspecting a given function definition, it is clear which maps will be modified and, even within those maps, which keys are affected by a given invocation. Also, the interface of data maps ensures that the return types of map operations are fixed length; Fixed length returns is a requirement for static analysis of a contract's runtime, costs, and other properties.

## List operations and functions

Lists may be multi-dimensional. However, note that runtime admission checks on typed function-parameters and data-map functions like `set-entry!` are charged based on the _maximal_ size of the multi-dimensional list.

You can call `filter` `map` and `fold` functions with user-defined functions (that is, functions defined with `(define ...)`, `(define-read-only ...)`, or `(define-public ...)`) or simple, native functions (for example, `+`, `-`, `not`).

## Intra-contract calls

A smart contract may call functions from other smart contracts using a `(contract-call!)` function:

```cl
(contract-call! contract-name function-name arg0 arg1 ...)
```

This function accepts a function name and the smart contract's name as input. For example, to call the function `token-transfer` in the smart contract, you would use:

`(contract-call! tokens token-transfer burn-address name-price))`

For intra-contract calls dynamic dispatch is not supported. When a contract is launched, any contracts it depends on (calls) must exist. Additionally, no cycles may exist in the call graph of a smart contract. This prevents recursion (and re-entrancy bugs. A static analysis of the call graph detects such structures and they are rejected by the network.

A smart contract may not modify other smart contracts' data directly; it can read data stored in those smart contracts' maps. This read ability does not alter any confidentiality guarantees of Clarity. All data in a smart contract is inherently public, andis readable through querying the underlying database in any case.

### Reading from other smart contracts

To read another contract's data, use `(fetch-contract-entry)` function. This behaves identically to `(fetch-entry)`, though it accepts a contract principal as an argument in addition to the map name:

```cl
(fetch-contract-entry
  'contract-name
  'map-name
  'key-tuple) ;; value tuple or none
```

For example, you could do this:

```cl
(fetch-contract-entry
  names
  name-map
  1)     ;;returns owner principal of name 
```

Just as with the `(contract-call)` function, the map name and contract principal arguments must be constants, specified at the time of publishing.

Finally, and importantly, the `tx-sender` variable does not change during inter-contract calls. This means that if a transaction invokes a function in a given smart contract, that function is able to make calls into other smart contracts on your behalf. This enables a wide variety of applications, but it comes with some dangers for users of smart contracts. However, the static analysis guarantees of Clarity allow clients to know a priori which functions a given smart contract will ever call. Good clients should always warn users about any potential side effects of a given transaction.

