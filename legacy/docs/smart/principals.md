---
layout: core
permalink: /:collection/:path.html
---
# Principals
{:.no_toc}

_Principals_ are a Clarity native type that represents a spending entity. This section discusses principals and how they are used in the Clarity.  

* TOC
{:toc}


## Principals and tx-sender

A principal is represented by a public-key hash or multi-signature Stacks address. Assets in Clarity and the Stacks blockchain are "owned" by objects of the principal type; put another way, principal object types may own an asset. 

A given principal operates on its assets by issuing a signed transaction on the Stacks blockchain. A Clarity contract can use a globally defined `tx-sender` variable to obtain the current principal.

The following user-defined function transfers an asset, in this case, tokens, between two principals:

```
(define (transfer! (sender principal) (recipient principal) (amount int))
  (if (and
        (not (eq? sender recipient))
        (debit-balance! sender amount)
        (credit-balance! recipient amount))
    'true
    'false))
```

The principal's signature is not checked by the smart contract, but by the virtual machine.


## Smart contracts as principals

Smart contracts themselves are principals and are represented by the smart contract's identifier. You create the identifier when you launch the contract, for example, the contract identifier here is `hanomine`.

```bash
clarity-cli launch hanomine /data/hano.clar /data/db
```

A smart contract may use the special variable `contract-name` to refer to its own principal.

To allow smart contracts to operate on assets it owns, smart contracts may use the special `(as-contract expr)` function. This function executes the expression (passed as an argument) with the `tx-sender` set to the contract's principal, rather than the current sender. The `as-contract` function returns the value of the provided expression.

For example, a smart contract that implements something like a "token faucet" could be implemented as so:

```cl
(define-public (claim-from-faucet)
  (if (is-none? (fetch-entry claimed-before (tuple (sender tx-sender))))
      (let ((requester tx-sender)) ;; set a local variable requester = tx-sender
        (begin
            (insert-entry! claimed-before (tuple (sender requester)) (tuple (claimed 'true)))
            (as-contract (stacks-transfer! requester 1)))))
      (err 1))
```

In this example, the public function `claim-from-faucet`:

* Checks if the sender has claimed from the faucet before.
* Assigns the tx sender to a `requester` variable.
* Adds an entry to the tracking map.
* Uses `as-contract` to send 1 microstack

Contract writers can use the primitive function `is-contract?` to determine whether a given principal corresponds to a smart contract.

Unlike other principals, there is no private key associated with a smart contract. As it lacks a private key, a Clarity smart contract cannot broadcast a signed transaction on the blockchain.
