---
layout: core
permalink: /:collection/:path.html
---
# Clarity language reference

This file contains the reference for the Clarity language. 

* TOC
{:toc}

## Clarity Type System

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

## Public Functions

Functions specified via `define-public` statements are _public_
functions and these are the only types of functions which may
be called directly through signed blockchain transactions. In addition
to being callable directly from a transaction (see the Stacks wire formats
for more details on Stacks transactions), public function may be called
by other smart contracts.

Public functions _must_ return a `(response ...)` type. This is used
by Clarity to determine whether or not to materialize any changes from
the execution of the function. If a function returns an `(err ...)`
type, and mutations on the blockchain state from executing the
function (and any function that it called during execution) will be
aborted.

In addition to function defined via `define-public`, contracts may expose
read-only functions. These functions, defined via `define-read-only`, are
callable by other smart contracts, and may be queryable via public blockchain
explorers. These functions _may not_ mutate any blockchain state. Unlike normal
public functions, read-only functions may return any type.

## Contract Calls

A smart contract may call functions from other smart contracts using a
`(contract-call?)` function.

This function returns a response type result-- the return value of the
called smart contract function.

We distinguish 2 different types of `contract-call?`:

* Static dispatch: the callee is a known, invariant contract available
on-chain when the caller contract is deployed. In this case, the
callee's principal is provided as the first argument, followed by the
name of the method and its arguments:

```scheme
(contract-call?
    .registrar
    register-name
    name-to-register)
```

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
    .contract-defining-trait.can-transfer-tokens)
```

Looking at trait conformance, callee contracts have two different paths.
They can either be "compatible" with a trait by defining methods
matching some of the methods defined in a trait, or explicitely declare
conformance using the `impl-trait` statement:

```scheme
(impl-trait .contract-defining-trait.can-transfer-tokens)
```

Explicit conformance should be prefered when adequate.
It acts as a safeguard by helping the static analysis system to detect
deviations in method signatures before contract deployment.

The following limitations are imposed on contract calls:

1. On static dispatches, callee smart contracts _must_ exist at the
   time of creation.
2. No cycles may exist in the call graph of a smart contract. This
   prevents recursion (and re-entrancy bugs). Such structures can
   be detected with static analysis of the call graph, and will be
   rejected by the network.
3. `contract-call?` are for inter-contract calls only. Attempts to
   execute when the caller is also the callee will abort the
   transaction.


## Clarity function reference

{% capture function_list %}
{% for entry in site.data.clarityRef %}
{{ entry.name }}||{{ entry.signature }}||{{ entry.input_type }}||{{ entry.output_type }}||{{ entry.description }}||{{ entry.example }}
{% if forloop.last == false %}::{% endif%}
{% endfor %}
{% endcapture %}
{% assign function_array = function_list | split: '::' | sort %}	
{% for function in function_array %}
{% assign function_vals = function | split: '||' %}
### {{function_vals[0] | lstrip | rstrip}}

**Syntax**
```{{function_vals[1] | lstrip | rstrip }} ```

<table class="uk-table uk-table-small">
<tr>
<th class="uk-width-small">Input type:</th>
<td><code>{{function_vals[2] | lstrip | rstrip }}</code></td>
</tr>
<tr>
<th>Output type:</th>
<td><code>{{function_vals[3] | rstrip }}</code></td>
</tr>
</table>
{{function_vals[4]}}
<h4>Example</h4>
```scheme
{{function_vals[5] | lstrip | rstrip }}
```
<hr class="uk-divider-icon">
{% endfor %}
