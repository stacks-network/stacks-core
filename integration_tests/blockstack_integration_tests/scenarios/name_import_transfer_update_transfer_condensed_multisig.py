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

import testlib
import pybitcoin
import json
import virtualchain

# activate multisig
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 250
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
"""

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.MultisigWallet(2, "5JfHdMq9XnZ9mwW5H6LsfVCn9u6iGAj2FCVYtfhcHn72Tphvm5P", "5JaqLZaKD7cgkfsxSZBNiu6gaFxo1XAiTXw1mhtatipNNCtZBZG", "5KNsAkiHRDZb5Yyedxov2Fncr6CcNPV52yqJbzQ8M2W6dkg2qJp"),
    testlib.MultisigWallet(2, "5JPrkpfLT3rDf1Lgm1DpA2Cfepwf9wCtEbDx1HSEdd4J2R5YMxZ", "5JiALcfvzFsKcvLnHf7ECgLdp6FxbcAXB1GPvEYP7HeigbDCQ9E", "5KScD5XL5Hj83Yjvm3u4HD78vSYwFRyq9StTLPnrWrCTGiqTvVP"),
    testlib.MultisigWallet(2, '5JPR5iVN8KGMdU9JfzoTCsipXazUcZPRY8zp7f3g8FRff2HBaAV', '5KTTwEyATY8v12MjNdoeA1u2ZGqgjnBNcyZjk3YSkiVJWYxqBSm', '5KQ1s8UEYz3oyFRUejBvb1imMdtpoP98w6NQYGxQsSo3u6DmztZ'),
    testlib.MultisigWallet(2, '5JpAkdEJuzF8E74UptksRLiB6Bf9QnwxGQutJTRWo5EAGVZfXmY', '5Hyc4wreVpZyzcfb56Zt1ymovda2xGucGZsAwoQz34iYK6aEKhR', '5JypKiQGiaD8AN6X86xtnuQYj7nnpLvp4VfcTVdDh4yFkLewAGx'),
]

debug = False
consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    global debug

    resp = testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_name_import( "foo.test", wallets[3].addr, "11" * 20, wallets[1].privkey)
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_namespace_ready( "test", wallets[1].privkey)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # ping-ping a bit... 3 --> 4 --> 5 --> 4 --> 5 --> 4
    resp = testlib.blockstack_name_transfer( "foo.test", wallets[4].addr, True, wallets[3].privkey, safety_checks=False) 
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_transfer( "foo.test", wallets[5].addr, True, wallets[4].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_transfer( "foo.test", wallets[4].addr, True, wallets[5].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_transfer( "foo.test", wallets[5].addr, True, wallets[4].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_transfer( "foo.test", wallets[4].addr, True, wallets[5].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # update (4)
    resp = testlib.blockstack_name_update( "foo.test", "11" * 20, wallets[4].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    # ping-ping a bit... 4 --> 5 --> 4 --> 5 --> 4 --> 5
    resp = testlib.blockstack_name_transfer( "foo.test", wallets[5].addr, True, wallets[4].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_transfer( "foo.test", wallets[4].addr, True, wallets[5].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_transfer( "foo.test", wallets[5].addr, True, wallets[4].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_transfer( "foo.test", wallets[4].addr, True, wallets[5].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )
    
    resp = testlib.blockstack_name_transfer( "foo.test", wallets[5].addr, True, wallets[4].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    # now update (5)
    resp = testlib.blockstack_name_update( "foo.test", "22" * 20, wallets[5].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # update transfer
    resp = testlib.blockstack_name_transfer( "foo.test", wallets[4].addr, True, wallets[5].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_update( "foo.test", "33" * 20, wallets[4].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # update --> transfer --> transfer --> update
    resp = testlib.blockstack_name_update( "foo.test", "44" * 20, wallets[4].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_transfer( "foo.test", wallets[5].addr, True, wallets[4].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_transfer( "foo.test", wallets[4].addr, True, wallets[5].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_update( "foo.test", "55" * 20, wallets[4].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # update --> transfer --> update --> transfer
    resp = testlib.blockstack_name_update( "foo.test", "66" * 20, wallets[4].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_transfer( "foo.test", wallets[5].addr, True, wallets[4].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_update( "foo.test", "11" * 20, wallets[5].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # transfer
    resp = testlib.blockstack_name_transfer( "foo.test", wallets[4].addr, True, wallets[5].privkey, safety_checks=False)
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )



def check( state_engine ):

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        print "'test' not revealed"
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        print "'test' not found"
        return False 

    if ns['namespace_id'] != 'test':
        print "'test' not returned"
        return False 

    # not preordered
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        print "'foo.test' still preordered"
        return False
    
    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "'foo.test' not registered"
        return False 

    # updated, and data is preserved
    if name_rec['value_hash'] != '11' * 20:
        print "'foo.test' invalid value hash"
        return False 

    # transferred 
    if name_rec['address'] != wallets[4].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[4].addr):
        print "'foo.test' invalid owner"
        return False 

    return True
