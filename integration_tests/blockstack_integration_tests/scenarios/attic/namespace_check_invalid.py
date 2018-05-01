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
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 680
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 681
"""
import testlib 

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.MultisigWallet(2, "5JfHdMq9XnZ9mwW5H6LsfVCn9u6iGAj2FCVYtfhcHn72Tphvm5P", "5JaqLZaKD7cgkfsxSZBNiu6gaFxo1XAiTXw1mhtatipNNCtZBZG", "5KNsAkiHRDZb5Yyedxov2Fncr6CcNPV52yqJbzQ8M2W6dkg2qJp"),
    testlib.MultisigWallet(2, "5JPrkpfLT3rDf1Lgm1DpA2Cfepwf9wCtEbDx1HSEdd4J2R5YMxZ", "5JiALcfvzFsKcvLnHf7ECgLdp6FxbcAXB1GPvEYP7HeigbDCQ9E", "5KScD5XL5Hj83Yjvm3u4HD78vSYwFRyq9StTLPnrWrCTGiqTvVP"),
    testlib.MultisigWallet(2, '5JPR5iVN8KGMdU9JfzoTCsipXazUcZPRY8zp7f3g8FRff2HBaAV', '5KTTwEyATY8v12MjNdoeA1u2ZGqgjnBNcyZjk3YSkiVJWYxqBSm', '5KQ1s8UEYz3oyFRUejBvb1imMdtpoP98w6NQYGxQsSo3u6DmztZ'),
    testlib.MultisigWallet(2, '5JpAkdEJuzF8E74UptksRLiB6Bf9QnwxGQutJTRWo5EAGVZfXmY', '5Hyc4wreVpZyzcfb56Zt1ymovda2xGucGZsAwoQz34iYK6aEKhR', '5JypKiQGiaD8AN6X86xtnuQYj7nnpLvp4VfcTVdDh4yFkLewAGx')
]

invalid_multisig_wallets = [
    # wrong key order
    testlib.MultisigWallet(2, '5KNsAkiHRDZb5Yyedxov2Fncr6CcNPV52yqJbzQ8M2W6dkg2qJp', "5JfHdMq9XnZ9mwW5H6LsfVCn9u6iGAj2FCVYtfhcHn72Tphvm5P", "5JaqLZaKD7cgkfsxSZBNiu6gaFxo1XAiTXw1mhtatipNNCtZBZG"),

    # wrong threshold
    testlib.MultisigWallet(1, "5JfHdMq9XnZ9mwW5H6LsfVCn9u6iGAj2FCVYtfhcHn72Tphvm5P", "5JaqLZaKD7cgkfsxSZBNiu6gaFxo1XAiTXw1mhtatipNNCtZBZG", "5KNsAkiHRDZb5Yyedxov2Fncr6CcNPV52yqJbzQ8M2W6dkg2qJp"),
    testlib.MultisigWallet(3, "5JfHdMq9XnZ9mwW5H6LsfVCn9u6iGAj2FCVYtfhcHn72Tphvm5P", "5JaqLZaKD7cgkfsxSZBNiu6gaFxo1XAiTXw1mhtatipNNCtZBZG", "5KNsAkiHRDZb5Yyedxov2Fncr6CcNPV52yqJbzQ8M2W6dkg2qJp"),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):
   
    res = testlib.blockstack_cli_namespace_preorder('test', wallets[0].privkey, wallets[1].privkey)
    if 'error' in res:
        print res
        return False
    
    test_txid = res['transaction_hash']

    res = testlib.blockstack_cli_namespace_preorder('testm', wallets[5].privkey, wallets[2].privkey)
    if 'error' in res:
        print res
        return False

    testm_txid = res['transaction_hash']
    
    # should fail (wrong key)
    res = testlib.blockstack_cli_namespace_preorder('testf', wallets[3].privkey, wallets[6].privkey)
    if 'error' not in res:
        print res
        return False

    testlib.next_block(**kw)

    # should fail (wrong reveal key)
    res = testlib.blockstack_cli_namespace_reveal('test', wallets[0].privkey, wallets[2].privkey, 52595, 250, 4, "6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0", 10, 10)
    if 'error' not in res:
        print res
        return False
     
    # should fail (wrong reveal key)
    res = testlib.blockstack_cli_namespace_reveal('test', wallets[5].privkey, wallets[3].privkey, 52595, 250, 4, "6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0", 10, 10)
    if 'error' not in res:
        print res
        return False

    # should fail (wrong preorder key)
    res = testlib.blockstack_cli_namespace_reveal('test', wallets[2].privkey, wallets[1].privkey, 52595, 250, 4, "6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0", 10, 10)
    if 'error' not in res:
        print res
        return False
    
    # should fail (wrong preorder key)
    res = testlib.blockstack_cli_namespace_reveal('test', wallets[6].privkey, wallets[2].privkey, 52595, 250, 4, "6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0", 10, 10)
    if 'error' not in res:
        print res
        return False

    # should fail (wrong namespace)
    res = testlib.blockstack_cli_namespace_reveal('test2', wallets[0].privkey, wallets[1].privkey, 52595, 250, 4, "6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0", 10, 10)
    if 'error' not in res:
        print res
        return False

    # should fail (wrong namespace)
    res = testlib.blockstack_cli_namespace_reveal('test2', wallets[5].privkey, wallets[2].privkey, 52595, 250, 4, "6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0", 10, 10)
    if 'error' not in res:
        print res
        return False

    # should fail (wrong preorder txid)
    res = testlib.blockstack_cli_namespace_reveal('test', wallets[0].privkey, wallets[1].privkey, 52595, 250, 4, "6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0", 10, 10, preorder_txid=testm_txid)
    if 'error' not in res:
        print res
        return False

    # should fail (wrong preorder txid)
    res = testlib.blockstack_cli_namespace_reveal('test', wallets[5].privkey, wallets[2].privkey, 52595, 250, 4, "6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0", 10, 10, preorder_txid=test_txid)
    if 'error' not in res:
        print res
        return False

    # should all fail (wrong key order)
    for w in invalid_multisig_wallets:
        res = testlib.blockstack_cli_namespace_reveal('testm', w.privkey, wallets[2].privkey, 52595, 250, 4, "6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0", 10, 10)
        if 'error' not in res:
            print res
            return False
    
    # should succeed
    res = testlib.blockstack_cli_namespace_reveal('test', wallets[0].privkey, wallets[1].privkey, 52595, 250, 4, "6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0", 10, 10, preorder_txid=test_txid)
    if 'error' in res:
        print res
        return False
   
    # should succeed
    res = testlib.blockstack_cli_namespace_reveal('testm', wallets[5].privkey, wallets[2].privkey, 52595, 250, 4, "6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0", 10, 10, preorder_txid=testm_txid)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)

    # should fail (wrong key)
    res = testlib.blockstack_cli_namespace_ready('test', wallets[2].privkey)
    if 'error' not in res:
        print res
        return False

    # should fail (wrong key)
    res = testlib.blockstack_cli_namespace_ready('testm', wallets[1].privkey)
    if 'error' not in res:
        print res
        return False

    # should succeed
    res = testlib.blockstack_cli_namespace_ready('test', wallets[1].privkey)
    if 'error' in res:
        print res
        return False

    # should succeed
    res = testlib.blockstack_cli_namespace_ready('testm', wallets[2].privkey)
    if 'error' in res:
        print res
        return False

    testlib.next_block( **kw )


def check( state_engine ):

    # not revealed, but ready
    for nsid in ['test', 'testm']:
        ns = state_engine.get_namespace_reveal( nsid )
        if ns is not None:
            return False 

        ns = state_engine.get_namespace( nsid )
        if ns is None:
            return False 

        if ns['namespace_id'] != nsid:
            return False

    return True
