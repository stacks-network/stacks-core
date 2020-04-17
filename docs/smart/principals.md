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

Assets in the smart contracting language and blockchain are
"owned" by objects of the principal type, meaning that any object of
the principal type may own an asset. For the case of public-key hash
and multi-signature Stacks addresses, a given principal can operate on
their assets by issuing a signed transaction on the blockchain. _Smart
contracts_ may also be principals (reprepresented by the smart
contract's identifier), however, there is no private key associated
with the smart contract, and it cannot broadcast a signed transaction
on the blockchain.

A Clarity contract can use a globally defined `tx-sender` variable to
obtain the current principal. The following example defines a transaction
type that transfers `amount` uSTX from the sender to a recipient if amount
is a multiple of 10, otherwise returning a 400 error code.

```scheme
(define-public (transfer-to-recipient! (recipient principal) (amount uint))
  (if (is-eq (mod amount 10) 0)
      (stx-transfer? amount tx-sender recipient)
      (err u400)))
```

## Smart contracts as principals

Smart contracts themselves are principals and are represented by the
smart contract's identifier -- which is the publishing address of the
contract _and_ the contract's name, e.g.:

```scheme
'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR.contract-name
```

For convenience, smart contracts may write a contract's identifier in the
form `.contract-name`, which is expanded by the Clarity interpreter into
a fully-qualified contract identifier that corresponds to the same
publishing address as the contract it appears in.

In order for a smart contract to operate on assets it owns, smart contracts
may use the special `(as-contract ...)` function. This function
executes the expression (passed as an argument) with the `tx-sender`
set to the contract's principal, rather than the current sender. The
`as-contract` function returns the value of the provided expression.

For example, a smart contract that implements something like a "token
faucet" could be implemented as so:

```scheme
(define-public (claim-from-faucet)
  (if (is-none? (fetch-entry claimed-before (tuple (sender tx-sender))))
      (let ((requester tx-sender)) ;; set a local variable requester = tx-sender
        (begin
            (insert-entry! claimed-before (tuple (sender requester)) (tuple (claimed true)))
            (as-contract (stx-transfer? u1 tx-sender requester))))
      (err 1)))
```

In this example, the public function `claim-from-faucet`:

* Checks if the sender has claimed from the faucet before.
* Assigns the tx sender to a `requester` variable.
* Adds an entry to the tracking map.
* Uses `as-contract` to send 1 microstack

Unlike other principals, there is no private key associated with a
smart contract. As it lacks a private key, a Clarity smart contract
cannot broadcast a signed transaction on the blockchain.
