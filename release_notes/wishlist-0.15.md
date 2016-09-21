Wishlist for 0.15
=================

This document lists the set of features scheduled for the 0.15 release, due in mid-September 2017.

New Features
------------

* Automatic name renewal in the clients.

Consensus-breaking Changes
--------------------------

* Revert the namespace lifetime multiplier change in 0.14.

* Adjust the price multiplier to preserve a $230 USD to 1 BTC exchange.

* Make name transfers take up to a week to complete, and make them cancellable by either the sender or recipient.  This is to limit the damage that can be done by a key compromise.

* Allow the name owner to specify a "name administrator" key that can update and renew the name, but not transfer or revoke it.

* Allow a name owner to specify a set of trusted revokers upon registration.  Each revoker owns a key, and a threshold of them (e.g. 3 of 5) can transfer the name to a new address.  After 30 days, the name will become usable again by the address's owner.  The idea is that a name owner can give some of his/her friends a revoke key, and if the owner loses their key or has it compromised, his/her friends can forcibly transfer it back.  The revoke keys are one-time-use.  The 30 day window gives the owner time to give out new revoke keys, or (if the revokers were compromised) gives the owner time to register and establish a different name.
