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
import binascii
import sys
import base58
import keylib
import traceback
from blockstack import OPCODE_NAMES

try:
    # not in all versions...
    from blockstack import op_extract
except:
    from blockstack import db_parse, NAME_OPCODES

    def op_extract( op_name, data, senders, inputs, outputs, block_id, vtxindex, txid ):
        opcode = NAME_OPCODES.get(op_name, None)
        return db_parse( block_id, txid, vtxindex, opcode, data, senders, inputs, outputs, None )

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):
    
    # nothing to do here
    pass

def compile_script( opcode, payload ):
    return binascii.hexlify("id%s%s" % (opcode, binascii.unhexlify(payload)))

def compile_test( opcode, tests ):
    result = {}
    for test_name, test_payload in tests.items():
        result[ test_name ] = compile_script( opcode, test_payload )
    return result


def addr_to_p2wpkh(addr):
    """
    Convert a p2pkh address into a p2wpkh script
    """
    if not virtualchain.btc_is_p2pkh_address(addr):
        raise ValueError("Not a valid p2pkh address: {}".format(addr))

    hash160 = keylib.b58check_decode(addr)
    return '0014' + hash160.encode('hex')


def parse_nameop( opcode, payload, fake_pubkey, recipient=None, recipient_address=None, import_update_hash=None, burn_address=None, reveal_address=None, use_bech32=False ):

    opcode_name = OPCODE_NAMES[opcode]
    pubk = virtualchain.BitcoinPublicKey(fake_pubkey)
    address = pubk.address()
    script_pubkey = virtualchain.make_payment_script( address )
    senders = [{
        "script_pubkey": script_pubkey,
        "script_type": "pubkeyhash",
        "addresses": [ address ]
    }]

    # just enough to get the public key
    inputs = [{
        'script': 'ignored {}'.format(fake_pubkey).encode('hex')
    }]

    script = "OP_RETURN %s" % payload

    try:
        scripthex = virtualchain.make_data_script(binascii.hexlify(payload))
    except:
        if len(payload) == 0:
            scripthex = "6a"
        else:
            print 'failed on {}'.format(payload)
            raise

    outputs = [{
        'script': scripthex,
        'value': 0
    }]

    if recipient_address is not None:
        script = "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG" % binascii.hexlify( virtualchain.lib.hashing.bin_double_sha256( fake_pubkey ) )

        if use_bech32:
            scripthex = addr_to_p2wpkh(recipient_address)
        else:
            scripthex = virtualchain.make_payment_script( recipient_address )

        outputs.append( {
            'script': scripthex,
            "value": 10000000
        })

    if import_update_hash is not None:
        script = "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG" % import_update_hash

        if use_bech32:
            scripthex = '0014' + import_update_hash
        else:
            scripthex = virtualchain.make_payment_script( virtualchain.hex_hash160_to_address( import_update_hash ) )

        outputs.append( {
            "script": scripthex,
            "value": 10000000
        })

    elif burn_address is not None:

        if use_bech32:
            scripthex = addr_to_p2wpkh(burn_address)
        else:
            scripthex = virtualchain.make_payment_script( burn_address )

        outputs.append( {
            "script": scripthex,
            "value": 10000000
        })
    
    elif reveal_address is not None:
        
        if use_bech32:
            scripthex = addr_to_p2wpkh(reveal_address)
        else:
            scripthex = virtualchain.make_payment_script( reveal_address )

        outputs.append( {
            "script": scripthex,
            "value": 10000000
        })

    try:
        op = op_extract( opcode_name, payload, senders, inputs, outputs, 488501, 0, "00" * 64 )  
    except AssertionError, ae:
        # failed to parse
        return None
    
    return op


def check( state_engine ):

    all_tests = {}

    # namespace preorder wire format
    # 0     2   3                                      23               39
    # |-----|---|--------------------------------------|----------------|
    #  magic op  hash(ns_id,script_pubkey,reveal_addr)   consensus hash  

    namespace_preorders = {
        "valid":     "%s%s" % ("11" * 20, "22" * 16),
        "too_short": "%s%s" % ("11" * 20, "33" * 15),
        "too_long":  "%s%s00" % ("11" * 20, "22" * 16),
    }

    all_tests["*"] = compile_test( "*", namespace_preorders )

    # namespace reveal wire format
    # 0     2   3        7     8     9    10   11   12   13   14    15    16    17       18        20                        39
    # |-----|---|--------|-----|-----|----|----|----|----|----|-----|-----|-----|--------|----------|-------------------------|
    # magic  op  life    coeff. base 1-2  3-4  5-6  7-8  9-10 11-12 13-14 15-16  nonalpha  version   namespace ID
    #                                                   bucket exponents         no-vowel
    #                                                                            discounts
   
    namespace_reveals = {
        "valid":      "%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % ("11111111", "02", "03", "40", "41", "42", "43", "44", "45", "46", "47", "15", "0001", binascii.hexlify("hello")),
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
        "valid":     binascii.hexlify(".hello"),
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
    # 0     2  3                                              23             39
    # |-----|--|----------------------------------------------|--------------|
    # magic op  hash(name.ns_id,script_pubkey,register_addr)   consensus hash

    name_preorders = {
        "valid":     "%s%s" % ("11" * 20, "22" * 16),
        "too_short": "%s%s" % ("11" * 20, "33" * 15),
        "too_long":  "%s%s00" % ("11" * 20, "22" * 16),
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
    
    name_registrations = {
        "valid":     binascii.hexlify("hello.test"),
        "null_name": binascii.hexlify(""),
        "non-b38":   binascii.hexlify("Hello.test"),
        "no-namespace": binascii.hexlify("hello"),
        "null-namespace": binascii.hexlify("hello."),
        "2period":   binascii.hexlify("hello.tes.t"),
        "no-plus":   binascii.hexlify("hel+lo.test"),
        "too-long":  binascii.hexlify("hellohellohellohellohellohellohel.test"),

        "valid_2":        binascii.hexlify("hello.test" + "\x00" * 27 + "\x11" * 20),
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
    }

    all_tests[":"] = compile_test( ":", name_registrations )

    # name update wire format
    #  0     2  3                                   19                      39
    # |-----|--|-----------------------------------|-----------------------|
    # magic op  hash128(name.ns_id,consensus hash) hash160(data)
        
    name_updates = {
        "valid":        "%s%s" % ("11" * 16, "22" * 20),
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
        "valid":        "%s%s%s" % (binascii.hexlify(">"), "11" * 16, "22" * 16),
        "valid2":        "%s%s%s" % (binascii.hexlify("~"), "11" * 16, "22" * 16),
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
        "valid":     binascii.hexlify("hello.test"),
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
        "valid":     binascii.hexlify("hello.test"),
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
        "valid":    "11" * 20,
        "too-short": "11" * 19,
        "too-long": "11" * 21
    }

    all_tests["#"] = compile_test( "#", announces )

    fake_pubkey = wallets[0].pubkey_hex
    fake_sender = virtualchain.make_payment_script( wallets[0].addr )
    fake_recipient = virtualchain.make_payment_script( wallets[1].addr )
    fake_recipient_address = wallets[1].addr
    fake_import_update_hash = "44" * 20
    fake_burn_address = virtualchain.address_reencode('1111111111111111111114oLvT2')
    fake_reveal_address = fake_burn_address

    # only 'valid' tests should return non-NULL
    # all other tests should return None
    for opcode, tests in all_tests.items():
        print "test %s" % opcode
        for testname, testscript in tests.items():
          
            bin_testscript = binascii.unhexlify(testscript)[3:]
            print 'script: {}'.format(bin_testscript)

            burn_addr = None
            reveal_addr = None
            import_hash = None

            if opcode in ['*', '?']:
                burn_addr = fake_burn_address

            elif opcode == ';':
                import_hash = fake_import_update_hash

            elif opcode == '&':
                reveal_addr = fake_reveal_address

            # make sure this *always* fails for bech32 outputs (for transactions that can have non-nulldata outputs)
            if opcode not in ['#', '!', '+', '~']:
                try:
                    parsed_op = parse_nameop( opcode, bin_testscript, fake_pubkey, \
                            recipient=fake_recipient, recipient_address=fake_recipient_address, import_update_hash=import_hash, burn_address=burn_addr, reveal_address=reveal_addr, use_bech32=True)

                    print >> sys.stderr, 'Parsed non-standard output without an exception'
                    print parsed_op
                    return False

                except Exception:
                    pass

            parsed_op = parse_nameop( opcode, bin_testscript, fake_pubkey, \
                    recipient=fake_recipient, recipient_address=fake_recipient_address, import_update_hash=import_hash, burn_address=burn_addr, reveal_address=reveal_addr )

            if testname.startswith("valid"):
                # should work
                if parsed_op is None:
                    print >> sys.stderr, "Failed to parse %s id%s%s (%s)" % (testname, opcode, bin_testscript, binascii.hexlify(bin_testscript))
                    return False 

            else:
                # should fail
                if parsed_op is not None:
                    print >> sys.stderr, "Parsed invalid test '%s' (id%s%s)" % (testname, opcode, bin_testscript)
                    return False

    return True
