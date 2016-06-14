#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

import virtualchain
log = virtualchain.get_logger("blockstack-log")

# consensus hash fields (ORDER MATTERS!)
FIELDS = [
    'namespace_id',         # human-readable namespace ID
    'namespace_id_hash',    # hash(namespace_id,sender,reveal_addr) from the preorder (binds this namespace to its preorder)
    'version',              # namespace rules version

    'sender',               # the scriptPubKey hex script that identifies the preorderer
    'sender_pubkey',        # if sender is a p2pkh script, this is the public key
    'address',              # address of the sender, from the scriptPubKey
    'recipient',            # the scriptPubKey hex script that identifies the revealer.
    'recipient_address',    # the address of the revealer
    'block_number',         # block number at which this namespace was preordered
    'reveal_block',         # block number at which this namespace was revealed

    'op',                   # byte code identifying this operation to Blockstack
    'txid',                 # transaction ID at which this namespace was revealed
    'vtxindex',             # the index in the block where the tx occurs

    'lifetime',             # how long names last in this namespace (in number of blocks)
    'coeff',                # constant multiplicative coefficient on a name's price
    'base',                 # exponential base of a name's price
    'buckets',              # array that maps name length to the exponent to which to raise 'base' to
    'nonalpha_discount',    # multiplicative coefficient that drops a name's price if it has non-alpha characters 
    'no_vowel_discount',    # multiplicative coefficient that drops a name's price if it has no vowels
]

