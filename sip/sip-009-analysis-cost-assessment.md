# SIP 006 Clarity Execution Cost Assessment

## Preamble

Title: Clarity Execution Cost Assessment

Author: Aaron Blankstein <aaron@blockstack.com>

Status: Draft

Type: Standard

Created: 10/19/2019

License: BSD 2-Clause

# Abstract

This document describes the measured costs and asymptotic costs
assessed for the analysis of Clarity code. This will not specify the
_constants_ associated with those asymptotic cost functions. Those
constants will necessarily be measured via benchmark harnesses and
regression analyses.

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

# Common Analysis Metrics and Costs

## Type signature size

Types in Clarity may described using type signatures. For example,
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
a*X+b
```

where a and b are constants,
X := stack depth

## Function Lookup

Looking up a function incurs a constant cost with respect
to name length (for the same reason as variable lookup). However,
because functions may only be defined in the top-level contract
context, stack depth does not affect function lookup.

Cost Function:

```
a
```

where a is a constant.

## Name Binding

The cost of binding a name in Clarity -- in either a local or the contract
context is _constant_ with respect to the length of the name:

```
binding_cost = a
```

where a is a constant

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
