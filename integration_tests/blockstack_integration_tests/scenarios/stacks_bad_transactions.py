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

# activate STACKS phase 1
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_3_END_BLOCK 684
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_4_NAMESPACE_LIFETIME_MULTIPLIER 1
"""

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

last_block = None

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


def compile_script( opcode, payload ):
    return binascii.hexlify("id%s%s" % (opcode, binascii.unhexlify(payload)))


def compile_test(opcode, tests):
    result = {}
    for test_name, test_payload in tests.items():
        result[test_name] = compile_script( opcode, test_payload )
    return result


def scenario( wallets, **kw ):
    global last_block 

    # send a data-bearing transaction without 'id'.  we shouldn't pick it up.
    tx = mktx(5500, 5500, wallets[1].addr, wallets[0].privkey, "eg")
    if 'error' in tx:
        print tx
        return False

    res = testlib.broadcast_transaction(tx)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)

    # send a data-bearing transaction with only 'id'.  we should ignore it.
    tx = mktx(5500, 5500, wallets[1].addr, wallets[0].privkey, "id")
    if 'error' in tx:
        print tx
        return False

    res = testlib.broadcast_transaction(tx)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)

    # send a data-bearing transaction with an invalid opcode after 'id'.  we should ignore it.
    tx = mktx(5500, 5500, wallets[1].addr, wallets[0].privkey, "id{")
    if 'error' in tx:
        print tx
        return False

    res = testlib.broadcast_transaction(tx)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)

    all_tests = {}

    # lifted from nameop_parsing_stacks, minus the "valid" tests

    # namespace preorder wire format
    # 0     2   3                                      23               39                         47
    # |-----|---|--------------------------------------|----------------|--------------------------|
    # magic op  hash(ns_id,script_pubkey,reveal_addr)   consensus hash    token fee (little-endian)

    namespace_preorders = {
        "too_short": "%s%s%s" % ("11" * 20, "33" * 15, '00' * 7),
        "too_long":  "%s%s%s" % ("11" * 20, "22" * 16, '00' * 9),
        "no_stacks": "%s%s" % ("11" * 20, "22" * 16)
    }

    all_tests["*"] = compile_test( "*", namespace_preorders )

    # namespace reveal wire format
    # 0     2   3        7     8     9    10   11   12   13   14    15    16    17       18        20                        39
    # |-----|---|--------|-----|-----|----|----|----|----|----|-----|-----|-----|--------|----------|-------------------------|
    # magic  op  life    coeff. base 1-2  3-4  5-6  7-8  9-10 11-12 13-14 15-16  nonalpha  version   namespace ID
    #                                                   bucket exponents         no-vowel
    #                                                                            discounts
   
    namespace_reveals = {
        "non-b38":    "%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % ("11111111", "02", "03", "40", "41", "42", "43", "44", "45", "46", "47", "15", "0001", binascii.hexlify("Hello")),
        "period2":    "%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % ("11111111", "02", "03", "40", "41", "42", "43", "44", "45", "46", "47", "15", "0001", binascii.hexlify("He.l.lo")),
        "period":     "%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % ("11111111", "02", "03", "40", "41", "42", "43", "44", "45", "46", "47", "15", "0001", binascii.hexlify(".")),
        "no-plus":    "%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % ("11111111", "02", "03", "40", "41", "42", "43", "44", "45", "46", "47", "15", "0001", binascii.hexlify("hel+lo")),
        "null_name":  "%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % ("11111111", "02", "03", "40", "41", "42", "43", "44", "45", "46", "47", "15", "0001", binascii.hexlify("")),
        "too_long":   "%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % ("11111111", "02", "03", "40", "41", "42", "43", "44", "45", "46", "47", "15", "0001", binascii.hexlify("hellohellohellohello"))
    }

    all_tests["&"] = compile_test( "&", namespace_reveals )

    # namespace ready wire format 
    # 0     2  3  4           23
    # |-----|--|--|------------|
    # magic op  .  ns_id

    namespace_readys = {
        "non-b38":   binascii.hexlify(".Hello"),
        "period":    binascii.hexlify("."),
        "period2":   binascii.hexlify(".hel.lo"),
        "no-plus":   binascii.hexlify(".hel+lo"),
        "null_name": binascii.hexlify(""),
        "no-period": binascii.hexlify("hello"),
        "too_long":  binascii.hexlify(".hellohellohellohello")
    }

    all_tests["!"] = compile_test( "!", namespace_readys )

    # name preorder wire format
    # 0     2  3                                     23             39          47            66
    # |-----|--|--------------------------------------|--------------|-----------|-------------|
    # magic op  hash160(fqn,scriptPubkey,registerAddr) consensus hash token burn  token type
    #                                                                 (optional)   (optional)


    name_preorders = {
        "too_short": "%s%s" % ("11" * 20, "33" * 15),
        "stacks_incomplete_short":  "%s%s00" % ("11" * 20, "22" * 16),
        "stacks_incomplete_long":  "%s%s%s" % ("11" * 20, "22" * 16, '00' * 7),
        "stacks_no_token_type":  "%s%s%s" % ("11" * 20, "22" * 16, '00' * 8),
        "stacks_incomplete_token_type_short":  "%s%s%s%s" % ("11" * 20, "22" * 16, '00' * 8, binascii.hexlify('a')),
        "stacks_incomplete_token_type_long":  "%s%s%s%s" % ("11" * 20, "22" * 16, '00' * 8, binascii.hexlify('abcdefghijklmnopqr')),
        "stacks_too_long":  "%s%s%s%s" % ("11" * 20, "22" * 16, '00' * 8, binascii.hexlify('abcdefghijklmnopqrst')),
    }

    all_tests["?"] = compile_test( "?", name_preorders )

    # name register/renew wire format (pre F-day 2017) 
    # 0    2  3                             39
    # |----|--|-----------------------------|
    # magic op   name.ns_id (37 bytes)

    # name register/renew wire format (post F-day 2017)
    # 0    2  3                                  39                  59
    # |----|--|----------------------------------|-------------------|
    # magic op   name.ns_id (37 bytes, 0-padded)       value hash
    
    # With renewal payment in a token:
    # 0    2  3                                  39                  59                            67
    # |----|--|----------------------------------|-------------------|------------------------------|
    # magic op   name.ns_id (37 bytes, 0-padded)     zone file hash    tokens burned (little-endian)

    name_registrations = {
        "null_name": binascii.hexlify(""),
        "non-b38":   binascii.hexlify("Hello.test"),
        "no-namespace": binascii.hexlify("hello"),
        "null-namespace": binascii.hexlify("hello."),
        "2period":   binascii.hexlify("hello.tes.t"),
        "no-plus":   binascii.hexlify("hel+lo.test"),
        "too-long":  binascii.hexlify("hellohellohellohellohellohellohel.test"),

        "null_name_2":    binascii.hexlify("\x00" * 37 + "\x11" * 20),
        "non-b38_2":      binascii.hexlify("Hello.test" + "\x00" * 27 + "\x11" * 20),
        "no-namespace_2": binascii.hexlify("hello" + "\x00" * 32 + "\x11" * 20),
        "null-namespace_2":  binascii.hexlify("hello." + "\x00" * 31 + "\x11" * 20),
        "2period_2":      binascii.hexlify("hello.tes.t" + "\x00" * 26 + "\x11" * 20),
        "no-plus_2":      binascii.hexlify("hel+lo.test" + "\x00" * 26 + "\x11" * 20),
        "too-long_2":     binascii.hexlify("hellohellohellohellohellohellohel.test" + "\x11" * 20),
        "no_hash":      binascii.hexlify("hello.test" + "\x00" * 27),
        "hash_too_long": binascii.hexlify("hello.test" + "\x00" * 27 + "\x11" * 21),
        "padding_too_short": binascii.hexlify("hello.test" + "\x00" * 26 + "\x11" * 21),
        "op_too_short": binascii.hexlify("hello.test" + "\x00" * 26 + "\x11" * 20),

        "stacks_too_short_1": binascii.hexlify("hello.test" + '\00' * 27 + '\x11' * 20 + '\x00'),
        "stacks_too_short_7": binascii.hexlify("hello.test" + '\00' * 27 + '\x11' * 20 + '\x00' * 7),
        "stacks_too_long": binascii.hexlify("hello.test" + '\00' * 27 + '\x11' * 20 + '\x00' * 9),
    }

    all_tests[":"] = compile_test( ":", name_registrations )

    # name update wire format
    #  0     2  3                                   19                      39
    # |-----|--|-----------------------------------|-----------------------|
    # magic op  hash128(name.ns_id,consensus hash) hash160(data)
        
    name_updates = {
        "too_short":    "%s%s" % ("11" * 16, "33" * 19),
        "too_long":     "%s%s00" % ("11" * 16, "22" * 20),
    }

    all_tests["+"] = compile_test( "+", name_updates )

    # name transfer wire format 
    # 0     2  3    4                   20              36
    # |-----|--|----|-------------------|---------------|
    # magic op keep  hash128(name.ns_id) consensus hash
    #          data?

    name_transfers = {
        "too_short":    "%s%s%s" % (binascii.hexlify(">"), "11" * 16, "33" * 15),
        "too_long":     "%s%s%s00" % (binascii.hexlify(">"), "11" * 16, "22" * 16),
        "too_short2":    "%s%s%s" % (binascii.hexlify("~"), "11" * 16, "33" * 15),
        "too_long2":     "%s%s%s00" % (binascii.hexlify("~"), "11" * 16, "22" * 16),
        "invalid-opcode": "%s%s%s" % (binascii.hexlify("!"), "11" * 16, "22" * 16)
    }

    all_tests[">"] = compile_test( ">", name_transfers )

    # name revoke wire format
    # 0    2  3                             39
    # |----|--|-----------------------------|
    # magic op   name.ns_id (37 bytes)
    
    name_revokes = {
        "null_name": binascii.hexlify(""),
        "non-b38":   binascii.hexlify("Hello.test"),
        "no-namespace": binascii.hexlify("hello"),
        "null-namespace": binascii.hexlify("hello."),
        "2period":   binascii.hexlify("hello.tes.t"),
        "no-plus":   binascii.hexlify("hel+lo.test"),
        "too-long":  binascii.hexlify("hellohellohellohellohellohellohel.test")
    }

    all_tests["~"] = compile_test( "~", name_revokes )

    # name import wire format
    # 0    2  3                             39
    # |----|--|-----------------------------|
    # magic op   name.ns_id (37 bytes)
    
    name_imports = {
        "null_name": binascii.hexlify(""),
        "non-b38":   binascii.hexlify("Hello.test"),
        "no-namespace": binascii.hexlify("hello"),
        "null-namespace": binascii.hexlify("hello."),
        "2period":   binascii.hexlify("hello.tes.t"),
        "no-plus":   binascii.hexlify("hel+lo.test"),
        "too-long":  binascii.hexlify("hellohellohellohellohellohellohel.test")
    }
    
    all_tests[";"] = compile_test( ";", name_imports )

    # announce wire format 
    # 0    2  3                             23
    # |----|--|-----------------------------|
    # magic op   message hash (160-bit)
    
    announces = {
        "too-short": "11" * 19,
        "too-long": "11" * 21
    }

    all_tests["#"] = compile_test( "#", announces )

    for opcode in all_tests.keys():
        print '\n\n'
        print 'Running tests for {}'.format(opcode)
        print '\n\n'

        # queue tests
        for test_name in all_tests[opcode].keys():
            payload = all_tests[opcode][test_name]
            print '\ntest {}: {}\n'.format(test_name, payload)

            tx = mktx(5500, 5500, wallets[1].addr, wallets[0].privkey, payload.decode('hex'))

            if 'error' in tx:
                print tx
                return False

            print 'tx: {}'.format(tx)
            res = testlib.broadcast_transaction(tx)
            if 'error' in res:
                print res
                return False

        # feed through virtualchain.  they should all be rejected by the parser
        testlib.next_block(**kw)

    last_block = testlib.get_current_block(**kw)

def check( state_engine ):
   
    global last_block

    # make sure no blocks were processed
    for i in range(688, last_block):
        block_stats = virtualchain.lib.indexer.StateEngine.get_block_statistics(i)
        assert block_stats, 'No block statistics for {}'.format(i)
        if block_stats['num_parsed_ops'] > 0:
            print 'parsed {} ops in block {}\n{}'.format(block_stats['num_parsed_ops'], i, block_stats)
            return False

    return True

