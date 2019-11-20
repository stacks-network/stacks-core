# SIP 006 Clarity Execution Cost Assessment

## Preamble

Title: Clarity Execution Cost Assessment

Author: Aaron Blankstein <aaron@blockstack.com>

Status: Draft

Type: Standard

Created: 10/19/2019

License: BSD 2-Clause

## Abstract

This document describes the measured costs and asymptotic costs
assessed for the execution of Clarity code. This will not specify the
_constants_ associated with those asymptotic cost functions. Those
constants will necessarily be measured via benchmark harnesses and
regression analyses. Furthermore, the _analysis_ cost associated with
this code will not be covered by this proposal.

# Costs of Common Operations

### Variable Lookup

Looking up variables in Clarity incurs a non-constant cost -- the stack
depth _and_ the length of the variable name affect this cost.

The stack depth affects the lookup cost because the variable must be
checked for in each context on the stack. The variable name affects
the cost because variables are stored in a HashMap, and determining
the key associated with a variable name requires hashing that name (a
linear operation).

Cost Function:

```
(a*X+b)*Y+c
```

where a, b, and c are constants,
X := variable name length
Y := stack depth

### Function Lookup

Looking up a function in Clarity incurs a non-constant cost, which
depends on the length of the function name (for the same reason variable
lookup depends on name length). However, because functions may only
be defined in the top-level contract context, stack depth does not
affect function lookup.

Cost Function:

```
(a*X+b)
```

where a and b are constants,
X := function name length

### Name Binding

The cost of binding a name in Clarity -- in either a local or the contract
context is _linear_ in the length of the name:

```
binding_cost(X) = (a*X+b)
```

where a, b are constants,
X := the length of the bound name

### Function Application

Function application in Clarity incurs a cost in addition to the
cost of executing the function's body. This cost is the cost of
binding the arguments to their passed values, and the cost of
ensuring that those arguments are of the correct type. Type checks
and argument binding are _linear_ in the size of the arguments, and
also incur a linear cost in hashing the argument names.

The cost of applying a function is:


```
(a*X+b) + sum(binding_cost(Y), ARGS) + costEval(body)
```

where a and b are constants,
X := the cumulative size of the argument types,
ARGS := the length of the argument names,
costEval(body) := the cost of executing the body of the function

### Type Parsing

Parsing a type in Clarity incurs a linear cost in the size of the
AST describing the type:

```
type_parsing_cost(X) = (a*X+b)
```

where a, b, are constants,
X := the number of elements in the type description AST

### Function Definition

Defining a function in Clarity incurs an execution cost at the
time of contract publishing (unrelated to any analysis). This
is the cost of _parsing_ the function's signature, which is linear
in the length of the type signatures, and linear in the length of the
function name and argument names.

```
binding_cost(F) + sum(binding_cost(Y), ARGS) + sum(type_parsing_cost(Y), ARG_TYPES)
```

where
F := the length of the function name
ARGS := the length of the argument names
ARG_TYPES := the length of the argument type signatures

### Contract Storage Cost

Storing a contract incurs both a runtime cost as well as storage costs. Both of
these are _linear_ the size of the contract AST.

```
WRITE_LENGTH = a*X+b
RUNTIME_COST = c*X+d
```

where a, b, c, and d, are constants.

# Native Function Costs

## Data, Token, Contract-Calls ##

### Data Lookup Costs

Fetching data from the datastore requires hashing the key to be looked up.
That cost is linear in the key size:

```
data_hash_cost(X) = a*X+b
```

X := size of the key

### Data Fetching Costs

Fetching data from the datastore incurs a runtime cost, in addition to
any costs associated with MARF accesses (which are simply counted as the
integer number of times the MARF is accessed). That runtime cost
is _linear_ in the size of the fetched value (due to parsing).

```
read_data_cost = a*X+b
```

X := size of the fetched value.

### Data Writing Costs

Writing data from the datastore incurs a runtime cost, in addition to
any costs associated with MARF writes (which are simply counted as the
integer number of times the MARF is written). That runtime cost
is _linear_ in the size of the written value (due to data serialization).

```
write_data_cost = a*X+b
```

X := size of the stored value.

### contract-call

Contract calls incur the cost of a normal function lookup and
application, plus the cost of loading that contract into memory from
the data store (which is linear in the size of the called contract).

```
RUNTIME_COST: (a*Y+b) + func_lookup_apply_eval(X)
READ_LENGTH: Y
```

where a and b are constants,
Y := called contract size
`func_lookup_apply_eval(X)` := the cost of looking up, applying, and
evaluating the body of the function

### map-get

```
RUNTIME_COST: data_hash_cost(X+Y) + read_data_cost(Z)
READ_LENGTH:  Z
```

X := size of the map's _key_ tuple
Y := the length of the map's name
Z := the size of the map's _value_ tuple


### contract-map-get

```
RUNTIME_COST: data_hash_cost(X+Y) + read_data_cost(Z)
READ_LENGTH:  Z
```

X := size of the map's _key_ tuple
Y := the length of the map's name
Z := the size of the map's _value_ tuple

### map-set

```
RUNTIME_COST: data_hash_cost(X+Y) + write_data_cost(Z)
WRITE_LENGTH:  Z
```

X := size of the map's _key_ tuple
Y := the length of the map's name
Z := the size of the map's _value_ tuple

### map-insert

```
RUNTIME_COST: data_hash_cost(X+Y) + write_data_cost(Z)
WRITE_LENGTH:  Z
```

X := size of the map's _key_ tuple
Y := the length of the map's name
Z := the size of the map's _value_ tuple

### map-delete

```
RUNTIME_COST: data_hash_cost(X+Y) + write_data_cost(1)
WRITE_LENGTH:  1
```

X := size of the map's _key_ tuple
Y := the length of the map's name

### var-get

```
RUNTIME_COST: data_hash_cost(X) + read_data_cost(Y)
READ_LENGTH: Y
```

X := length of the variable's name
Y := the size of the variable's _value_ type

### var-set

```
RUNTIME_COST: data_hash_cost(X) + write_data_cost(Y)
WRITE_LENGTH: Y
```

X := length of the variable's name
Y := the size of the variable's _value_ type

### nft-mint

```
RUNTIME_COST: data_hash_cost(X+Y) + write_data_cost(a) + b
WRITE_LENGTH: a
```

X := length of the token name
Y := size of the NFT type

a is a constant: the size of a token owner
b is a constant cost (for tracking the asset in the assetmap)

### nft-get-owner

```
RUNTIME_COST: data_hash_cost(X+Y) + read_data_cost(a)
READ_LENGTH: a
```

X := length of the token name
Y := size of the NFT type

a is a constant: the size of a token owner


### nft-transfer

```
RUNTIME_COST: data_hash_cost(X+Y) + write_data_cost(a) + write_data_cost(a) + b
READ_LENGTH: a
WRITE_LENGTH: a
```

X := length of the token name
Y := size of the NFT type

a is a constant: the size of a token owner
b is a constant cost (for tracking the asset in the assetmap)

### ft-mint
 
Minting a token is a constant-time operation that performs a constant
number of reads and writes (to check the total supply of tokens and
incremement).

```
RUNTIME: a
READ_LENGTH: b
WRITE_LENGTH: c
```
a, b, and c are all constants.

### ft-transfer

Transfering a token is a constant-time operation that performs a constant
number of reads and writes (to check the token balances).

```
RUNTIME: a
READ_LENGTH: b
WRITE_LENGTH: c
```
a, b, and c are all constants.

### ft-get-balance

Getting a token balance is a constant-time operation that performs a
constant number of reads.

```
RUNTIME: a
READ_LENGTH: b
```
a and b are constants.

### get-block-info

```
RUNTIME: a
READ_LENGTH: b
```

a and b are constants.

## Control-Flow and Context Manipulation

### let

In addition to the cost of evaluating the body expressions of a `let`,
the cost of a `let` expression has a constant cost, plus
the cost of binding each variable in the new context (similar
to the cost of function evaluation, without the cost of type checks).


```
a + sum(binding_cost(Y), ARGS) + costEval(body)
```

where a is a constant,
ARGS := the length of the let argument names
costEval(body) := the cost of executing the body of the let

### if

```
costEval(condition) + costEval(chosenBranch)
```

where
costEval(condition) := the cost of evaluating the if condition
costEval(chosenBranch) := the cost of evaluating the chosen branch

if computed during _static analysis_, the chosen branch cost is the
`max` of the two possible branches.

## List iteration
### map

The cost of mapping a list is the cost of the function lookup,
and the cost of each iterated function application

```
a + func_lookup_cost(F) + L * apply_eval_cost(F, i)
```

where a is a constant,
`func_lookup_cost(F)` := the cost of looking up the function name F
`apply_eval_cost(F, i)` := the cost of applying and evaluating the body of F on type i
`i` := the list _item_ type
`L` := the list length

if computed during _static analysis_, L is the maximum length of the list
as specified by it's type.

### filter

The cost of filtering a list is the cost of the function lookup,
and the cost of each iterated filter application

```
a + func_lookup_cost(F) + L * apply_eval_cost(F, i)
```

where a is a constant,
`func_lookup_cost(F)` := the cost of looking up the function name F
`apply_eval_cost(F, i)` := the cost of applying and evaluating the body of F on type i
`i` := the list _item_ type
`L` := the list length

if computed during _static analysis_, L is the maximum length of the list
as specified by it's type.

### fold


The cost of folding a list is the cost of the function lookup,
and the cost of each iterated application

```
a + func_lookup_cost(F) + (L) * apply_eval_cost(F, i, j)
```

where a is a constant,
`func_lookup_cost(F)` := the cost of looking up the function name F
`apply_eval_cost(F, i, j)` := the cost of applying and evaluating the body of F on types i, j
`j` := the accumulator type
`i` := the list _item_ type
`L` := the list length

if computed during _static analysis_, L is the maximum length of the list
as specified by it's type.

### len

The cost of getting a list length is constant, because Clarity lists
store their lengths.

### list

The cost of constructing a new list is linear -- Clarity ensures that
each item in the list is of a matching type.

```
a*X+b
```

where a and b are constants,
X := the total size of all arguments to the list constructor

### tuple

The cost of constructing a new tuple is `O(nlogn)` with respect to the number of
keys in the tuple (because tuples are represented as BTrees) and linear in 
name length due to the cost of name binding.

```
a*(X*log(X)) + b + sum(binding_cost(Y), KEY_NAMES)
```

where a and b are constants,
X := the number of keys in the tuple
KEY_NAMES := the names of the keys in the tuple

### get

Reading from a tuple is `O(nlogn)` with respect to the number of
keys in the tuple (because tuples are represented as BTrees) and linear in 
name length due to the cost of equality check after lookup.

```
a*(X*log(X)) + b + c*Y
```

where a and b are constants,
X := the number of keys in the tuple
Y := the length of the looked up key

## Arithmetic and Logic Operations

### Variadic operators

The variadic operators (`+`,`-`,`/`,`*`, `and`, `or`) all have costs linear
in the _number_ of arguments supplied

```
(a*X+b)
```

where X is the number of arguments

### Binary/Unary operators

The binary and unary operators:

```
>
>=
<
<=
mod
pow
xor
not
to-int
to-uint
```

all have constant cost, because their inputs are all of fixed sizes.

### Hashing functions

The hashing functions have linear runtime costs: the larger the value being
hashed, the longer the hashing function takes.

```
(a*X+b)
```

where X is the size of the input.

