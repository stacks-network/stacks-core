#!/usr/bin/env python2
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

import testlib 
import json
import virtualchain
import binascii

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"


def mktx( amt, tx_fee, recipient_addr, privkey, message=None ):
    """
    Make the transaction with the given fee
    """
    change_addr = virtualchain.BitcoinPrivateKey(privkey).public_key().address()
    inputs = testlib.get_unspents(change_addr)
    change = virtualchain.calculate_change_amount(inputs, amt, tx_fee)

    outputs = [
        {'script': virtualchain.make_payment_script(recipient_addr),
         'value': amt},
    ]

    if change > 0:
        # need change and tx fee
        outputs.append( 
            {'script': virtualchain.make_payment_script(change_addr),
              "value": change}
        )

    if message:
        outputs = [
            {"script": virtualchain.make_data_script(binascii.hexlify(message)),
             "value": 0} ] + outputs

    serialized_tx = testlib.serialize_tx(inputs, outputs)
    prev_outputs = [{'out_script': inp['out_script'], 'value': inp['value']} for inp in inputs]

    signed_tx = virtualchain.tx_sign_all_unsigned_inputs(privkey, prev_outputs, serialized_tx)
    return signed_tx


def scenario( wallets, **kw ):
    # send a data-bearing transaction without 'id'
    tx = mktx(5500, 5500, wallets[1].addr, wallets[0].privkey, "eg")
    if 'error' in tx:
        print tx
        return False

    res = testlib.broadcast_transaction(tx)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)

    # send a data-bearing transaction with only 'id'
    tx = mktx(5500, 5500, wallets[1].addr, wallets[0].privkey, "id")
    if 'error' in tx:
        print tx
        return False

    res = testlib.broadcast_transaction(tx)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)

    # send a data-bearing transaction with an invalid opcode after 'id'
    tx = mktx(5500, 5500, wallets[1].addr, wallets[0].privkey, "id{")
    if 'error' in tx:
        print tx
        return False

    res = testlib.broadcast_transaction(tx)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)


def check( state_engine ):
    
    return True

