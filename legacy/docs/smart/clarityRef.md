---
layout: core
permalink: /:collection/:path.html
---
# Clarity language reference

This file contains the reference for the Clarity language. 

* TOC
{:toc}

## Block Properties

The `get-block-info` function fetches property details for a block at a specified block height. For example:

```cl
(get-block-info time 10) ;; Returns 1557860301
```

Because the Clarity language is in pre-release, the block properties that are fetched are simulated properties from a SQLite database. The available property names are:

<table class="uk-table">
  <tr>
    <th>Property</th>
    <th>Definition</th>
  </tr>
  <tr>
    <td><code>header-hash</code></td>
    <td>A 32-byte buffer containing the block hash.</td>
  </tr>
  <tr>
    <td><code>burnchain-header-hash</code></td>
    <td>A 32-byte buffer that contains the hash from the proof of burn.</td>
  </tr>
  <tr>
    <td><code>vrf-seed</code></td>
    <td>A 32-byte buffer containing the Verifiable Random Function (VRF) seed value used for the block.</td>
  </tr>
  <tr>
    <td><code>time</code></td>
    <td>An integer value containing that roughly corresponds to when the block was mined. This is a Unix epoch timestamp in seconds. </td>
  </tr>
</table>


{% include warning.html content="The <code>time</code> does not increase monotonically with each block. Block times are accurate only to within two hours. See <a href='https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki' target='_blank'>BIP113</a> for more information." %}


## Supported types

This section lists the types available to smart contracts. The only atomic types supported by the Clarity are booleans, integers, fixed length buffers, and principals. 

### Int type

The integer type in the Clarity language is a 16-byte signed integer, which allows it to specify the maximum amount of microstacks spendable in a single Stacks transfer. The special `BlockHeightInt` you can obtain with the `get-block-info` function.

### Bool type

Supports values of `'true` or `'false`. 

### Buffer type

Buffer types represent fixed-length byte buffers. Currently, the only way to construct a Buffer is using string literals, for example `"alice.id"` or `hash160("bob.id")` 

All of the hash functions return buffers:

`hash160`
`sha256`
`keccak256`

The block properties `header-hash`, `burnchain-header-hash`, and `vrf-seed` are all buffers.

### List type

Clarity supports lists of the atomic types. However, the only variable length lists in the language appear as function inputs; there is no support for list operations like append or join.

### Principal type

Clarity provides this primitive for checking whether or not the smart contract transaction was signed by a particular principal. Principals represent a spending entity and are roughly equivalent to a Stacks address. The principal's signature is not checked by the smart contract, but by the virtual machine. A smart contract function can use the  globally defined `tx-sender` variable to obtain the current principal.

Smart contracts may also be principals (represented by the smart contract's identifier). However, there is no private key associated with the smart contract, and it cannot broadcast a signed transaction on the blockchain. A smart contract uses the special variable `contract-name` to refer to its own principal.

[//]: #  You can use the `is-contract?` to determine whether a given principal corresponds to a smart contract. 

### Tuple type

To support the use of named fields in keys and values, Clarity  allows the construction of named tuples using a function `(tuple ...)`, for example

```cl
(define imaginary-number-a (tuple (real 1) (i 2)))
(define imaginary-number-b (tuple (real 2) (i 3)))
```

This allows for creating named tuples on the fly, which is useful for data maps where the keys and values are themselves named tuples. Values in a given mapping are set or fetched using:

<table class="uk-table uk-table-small">
<tr>
  <th class="uk-width-small">Function</th>
  <th>Description</th>
</tr>
<tr>
  <td><code>(fetch-entry map-name key-tuple)</code></td>
  <td>Fetches the value associated with a given key in the map, or returns <code>none</code> if there is no such value.</td>
</tr>
<tr>
   <td><code>(set-entry! map-name key-tuple value-tuple)</code></td>
  <td>Sets the value of key-tuple in the data map</td>
</tr>
  <tr>
   <td><code>(insert-entry! map-name key-tuple value-tuple)</code></td>
  <td>Sets the value of key-tuple in the data map if and only if an entry does not already exist.</td>
</tr>
  <tr>
   <td><code>(delete-entry! map-name key-tuple)</code></td>
  <td>Deletes key-tuple from the data map.</td>
</tr>
</table>


To access a named value of a given tuple, the `(get name tuple)` function returns that item from the tuple.

### Optional type

Represents an optional value. This is used in place of the typical usage of "null" values in other languages, and represents a type that can either be some value or `none`. Optional types are used as the return types of data-map functions.

### Response type

Response types represent the result of a public function. Use this type to indicate and return data associated with the execution of the function. Also, the response should indicate whether the function error'ed (and therefore did not materialize any data in the database) or ran `ok` (in which case data materialized in the database).

Response types contain two subtypes -- a response type in the event of `ok` (that is, a public function returns an integer code on success) and an `err` type (that is, a function returns a buffer on error).

## Native variables

The Clarity language includes native variables you can use in your contract.

### block-height

The height of a block in the Stacks blockchain.  Block height is the number of blocks in the chain between any given block and the very first block in the blockchain. You can obtain a `block-height` via the `get-block-info` function.

### contract-name

Represents the current contract.

### tx-sender

Represents the current principal. This variable does not change during inter-contract calls. This means that if a transaction invokes a function in a given smart contract, that function is able to make calls into other smart contracts on your behalf. This enables a wide variety of applications, but it comes with some dangers for users of smart contracts. Static analysis of Clarity contracts guarantees the language allows clients to deduce which functions a given smart contract will ever call. Good clients should always warn users about any potential side effects of a given transaction.


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
```cl
{{function_vals[5] | lstrip | rstrip }}
```
<hr class="uk-divider-icon">
{% endfor %}
