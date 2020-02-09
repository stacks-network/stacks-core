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
import virtualchain
import blockstack

# activate tokens
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_3_END_BLOCK 684
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
"""

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet("e802e6b061d7d9594afef1d82037d6a3901c60f567b26c7ad8be9cfb3fd8320d01", 0),
    testlib.Wallet("f3723d91bf90657746f01fc1d85ba4db6d7d1e4f4ca2174445235efd1350f87101", 0),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
pk = wallets[-1].privkey
pk2 = wallets[-2].privkey

def scenario( wallets, **kw ):
    global pk, pk2

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    # pay for a name in a v1 namespace with Stacks
    addr = virtualchain.address_reencode(virtualchain.get_privkey_address(pk))
    addr2 = virtualchain.address_reencode(virtualchain.get_privkey_address(pk2))

    # calculate the cost of doing so
    namespace = testlib.get_state_engine().get_namespace('test')
    stacks_price = blockstack.lib.scripts.price_name_stacks('foo', namespace, testlib.get_current_block(**kw))
    btc_price = blockstack.lib.scripts.price_name('foo', namespace, testlib.get_current_block(**kw))

    print ''
    print 'price of {} in Stacks is {}'.format('foo.test', stacks_price)
    print 'price of {} in BTC is {}'.format('foo.test', btc_price)
    print ''

    testlib.blockstack_send_tokens(addr, "STACKS", stacks_price + 1, wallets[0].privkey)
    testlib.blockstack_send_tokens(addr2, "STACKS", stacks_price + 1, wallets[0].privkey)
    testlib.send_funds(wallets[0].privkey, 2*btc_price, addr)
    testlib.send_funds(wallets[0].privkey, 2*btc_price, addr2)
    testlib.next_block(**kw)

    # preorder/register using Stacks
    testlib.blockstack_name_preorder( "foo.test", pk, addr2, price={'units': 'STACKS', 'amount': stacks_price + 1})
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo.test", pk, addr2 )
    testlib.next_block( **kw )

    # renew using Stacks
    testlib.blockstack_name_renew('foo.test', pk2, price={'units': 'STACKS', 'amount': stacks_price + 1})
    testlib.next_block(**kw)


def check( state_engine ):

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        print "namespace reveal exists"
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        print "no namespace"
        return False 

    if ns['namespace_id'] != 'test':
        print "wrong namespace"
        return False 

    # not preordered
    addr = virtualchain.address_reencode(virtualchain.get_privkey_address(pk))
    addr2 = virtualchain.address_reencode(virtualchain.get_privkey_address(pk2))
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(addr), addr2 )
    if preorder is not None:
        print "preorder exists"
        return False
    
    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "name does not exist"
        return False 

    # owned by
    if name_rec['address'] != addr2 or name_rec['sender'] != virtualchain.make_payment_script(addr2):
        print "sender is wrong"
        return False 

    # paid with Stacks
    stacks_price = blockstack.lib.scripts.price_name_stacks('foo', ns, state_engine.lastblock)
    if name_rec['token_fee'] != stacks_price + 1:
        print 'paid wrong token fee'
        print 'expected {} ({}), got {} ({})'.format(stacks_price, type(stacks_price), name_rec['token_fee'], type(name_rec['token_fee']))
        return False

    if name_rec['op_fee'] > 5500:  # dust minimum
        print 'paid in BTC ({})'.format(name_rec['op_fee'])
        return False

    # renewed
    if name_rec['first_registered'] == name_rec['last_renewed']:
        print 'not renewed'
        return False

    return True
