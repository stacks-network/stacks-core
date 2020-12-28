# SIP 008 Clarity Parsing and Analysis Cost Assessment

## Preamble

Title: Clarity Parsing and Analysis Cost Assessment

Author: Aaron Blankstein <aaron@blockstack.com>

Status: Draft

Type: Standard

Created: 03/05/2020

License: BSD 2-Clause

# Abstract

This document describes the measured costs and asymptotic costs
assessed for parsing Clarity code into an abstract syntax tree (AST)
and the static analysis of that Clarity code (type-checking and
read-only enforcement). This will not specify the _constants_
associated with those asymptotic cost functions. Those constants will
necessarily be measured via benchmark harnesses and regression
analyses.

# Measurements for Execution Cost

The cost of analyzing Clarity code is measured using the same 5 categories
described in SIP-006 for the measurement of execution costs:

1. Runtime cost: captures the number of cycles that a single
   processor would require to process the Clarity block. This is a
   _unitless_ metric, so it will not correspond directly to cycles,
   but rather is meant to provide a basis for comparison between
   different Clarity code blocks.
2. Data write count: captures the number of independent writes
   performed on the underlying data store (see SIP-004).
3. Data read count: captures the number of independent reads
   performed on the underlying data store.
4. Data write length: the number of bytes written to the underlying
   data store.
5. Data read length: the number of bytes read from the underlying
   data store.

Importantly, these costs are used to set a _block limit_ for each
block.  When it comes to selecting transactions for inclusion in a
block, miners are free to make their own choices based on transaction
fees, however, blocks may not exceed the _block limit_. If they do so,
the block is considered invalid by the network --- none of the block's
transactions will be materialized and the leader forfeits all rewards
from the block.

Costs for static analysis are assessed during the _type check_ pass.
The read-only and trait-checking passes perform work which is strictly
less than the work performed during type checking, and therefore, the
cost assessment can safely fold any costs that would be incurred during
those passes into the type checking pass.

# Common Analysis Metrics and Costs

## AST Parsing

The Clarity parser has a runtime that is linear with respect to the Clarity
program length.

```
a*X+b
```

where a and b are constants, and

X := the program length in bytes

## Dependency cycle detection

Clarity performs cycle detection for intra-contract dependencies (e.g.,
functions that depend on one another). This detection is linear in the
number of dependency edges in the smart contract:

```
a*X+b
```

where a and b are constants, and
X := the total number of dependency edges in the smart contract

Dependency edges are created anytime a top-level definition refers 
to another top-level definition.

## Type signature size

Types in Clarity may be described using type signatures. For example,
`(tuple (a int) (b int))` describes a tuple with two keys `a` and `b`
of type `int`. These type descriptions are used by the Clarity analysis
passes to check the type correctness of Clarity code. Clarity type signatures
have varying size, e.g., the signature `int` is smaller than the signature for a
list of integers.

The signature size of a Clarity type is defined as follows:

```
type_signature_size(x) :=
  if x = 
     int      => 1
    uint      => 1
    bool      => 1
    principal => 1
    buffer    => 2
    optional  => 1 + type_signature_size(entry_type)
    response  => 1 + type_signature_size(ok_type) + type_signature_size(err_type)
    list      => 2 + type_signature_size(entry_type)
    tuple     => 1 + 2*(count(entries)) 
                   + sum(type_signature_size for each entry)
                   + sum(len(key_name) for each entry)
```

## Type annotation

Each node in a Clarity contract's AST is annotated with the type value
for that node during the type checking analysis pass.

The runtime cost of type annotation is:

```
a + b*X
```

where a and b are constants, and X is the type signature size of the
type being annotated.

## Variable lookup

Looking up variables during static analysis incurs a non-constant cost -- the stack
depth _and_ the length of the variable name affect this cost. However,
variable names in Clarity have bounded length -- 128 characters. Therefore,
the cost assessed for variable lookups may safely be constant with respect
to name length.

The stack depth affects the lookup cost because the variable must be
checked for in each context on the stack.

Cost Function:

```
a*X+b*Y+c
```

where a, b, and c are constants,
X := stack depth
Y := the type size of the looked up variable

## Function Lookup

Looking up a function incurs a constant cost with respect
to name length (for the same reason as variable lookup). However,
because functions may only be defined in the top-level contract
context, stack depth does not affect function lookup.

Cost Function:

```
a*X + b
```

where a and b are constants,
X := the sum of the type sizes for the function signature (each argument's type size, as well
    as the function's return type)

## Name Binding

The cost of binding a name in Clarity -- in either a local or the contract
context is _constant_ with respect to the length of the name, but linear in
the size of the type signature.

```
binding_cost = a + b*X
```

where a and b are constants, and
X := the size of the bound type signature

## Type check cost

The cost of a static type check is _linear_ in the size of the type signature:

```
type_check_cost(expected, actual) :=
  a + b*X
```

where a and b are constants, and

X := `max(type_signature_size(expected), type_signature_size(actual))`

## Function Application

Static analysis of a function application in Clarity requires
type checking the function's expected arguments against the
supplied types.

The cost of applying a function is:


```
a + sum(type_check_cost(expected, actual) for each argument)
```

where a is a constant.

This is also the _entire_ cost of type analysis for most function calls
(e.g., intra-contract function calls, most simple native functions). 

## Iterating the AST

Static analysis iterates over the entire program's AST in the type checker,
the trait checker, and in the read-only checker. This cost is assessed
as a constant cost for each node visited in the AST during the type
checking pass.

# Special Function Costs

Some functions require additional work from the static analysis system.

## Functions on sequences (e.g., map, filter, fold)

Functions on sequences need to perform an additional check that the
supplied type is a list or buffer before performing the normal
argument type checking. This cost is assessed as:

```
a
```

where a is a constant.

## Functions on options/responses

Similarly to the functions on sequences, option/response functions
must perform a simple check to see if the supplied input is an option or
response before performing additional argument type checking. This cost is
assessed as:

```
a
```

## Data functions (ft balance checks, nft lookups, map-get?, ...)

Static checks on intra-contract data functions do not require database lookups
(unlike the runtime costs of these functions). Rather, these functions
incur normal type lookup (i.e., fetching the type of an NFT, data map, or data var)
and type checking costs.

## get

Checking a tuple _get_ requires accessing the tuple's signature
for the specific field. This has runtime cost:

```
a*log(N) + b
```
where a and b are constants, and

N := the number of fields in the tuple type

## tuple

Constructing a tuple requires building the tuple's BTree for
accessing fields. This has runtime cost:


```
a*N*log(N) + b
```
where a and b are constants, and

N := the number of fields in the tuple type

## use-trait

Importing a trait imposes two kinds of costs on the analysis.
First, the import requires a database read. Second, the imported
trait is included in the static analysis output -- this increases
the total storage usage and write length of the static analysis.

The costs are defined as:

```
read_count = 1
write_count = 0
runtime = a*X+b
write_length = c*X+d
read_length = c*X+d
```

where a, b, c, and d are constants, and

X := the total type size of the trait (i.e., the sum of the
    type sizes of each function signature).

## contract-call?

Checking a contract call requires a database lookup to inspect
the function signature of a prior smart contract.

The costs are defined as:

```
read_count = 1
read_length = a*X+b
runtime = c*X+d
```

where a, b, c, and d are constants, and

X := the total type size of the function signature

## let

Let bindings require the static analysis system to iterate over
each let binding and ensure that they are syntactically correct.

This imposes a runtime cost:

```
a*X + b
```
where a and b are constants, and

X := the number of entries in the let binding.


