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

## Costs of Common Operations

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

where a, b, c, and d are constants,
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
