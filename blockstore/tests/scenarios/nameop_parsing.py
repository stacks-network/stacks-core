#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstore

    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore. If not, see <http://www.gnu.org/licenses/>.
""" 

import testlib
import pybitcoin
import blockstore
import binascii
import sys

parse_nameop = blockstore.virtualchain_hooks.parse_blockstore_op_data

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
    return "id%s%s" % (opcode, binascii.unhexlify(payload))

def compile_test( opcode, tests ):
    result = {}
    for test_name, test_payload in tests.items():
        result[ test_name ] = compile_script( opcode, test_payload )
    return result

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
        "valid":      "%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % ("11111111", "02", "03", "40", "41", "42", "43", "44", "45", "46", "47", "15", "6666", binascii.hexlify("hello")),
        "non-b38":    "%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % ("11111111", "02", "03", "40", "41", "42", "43", "44", "45", "46", "47", "15", "6666", binascii.hexlify("Hello")),
        "period2":    "%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % ("11111111", "02", "03", "40", "41", "42", "43", "44", "45", "46", "47", "15", "6666", binascii.hexlify("He.l.lo")),
        "period":     "%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % ("11111111", "02", "03", "40", "41", "42", "43", "44", "45", "46", "47", "15", "6666", binascii.hexlify(".")),
        "no-plus":    "%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % ("11111111", "02", "03", "40", "41", "42", "43", "44", "45", "46", "47", "15", "6666", binascii.hexlify("hel+lo")),
        "null_name":  "%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % ("11111111", "02", "03", "40", "41", "42", "43", "44", "45", "46", "47", "15", "6666", binascii.hexlify("")),
        "too_long":   "%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % ("11111111", "02", "03", "40", "41", "42", "43", "44", "45", "46", "47", "15", "6666", binascii.hexlify("hellohellohellohello"))
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

    # name register/renew wire format 
    # 0    2  3                             39
    # |----|--|-----------------------------|
    # magic op   name.ns_id (37 bytes)
    
    name_registrations = {
        "valid":     binascii.hexlify("hello.test"),
        "null_name": binascii.hexlify(""),
        "non-b38":   binascii.hexlify("Hello.test"),
        "no-namespace": binascii.hexlify("hello"),
        "null-namespace": binascii.hexlify("hello."),
        "2period":   binascii.hexlify("hello.tes.t"),
        "no-plus":   binascii.hexlify("hel+lo.test"),
        "too-long":  binascii.hexlify("hellohellohellohellohellohellohel.test")
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

    fake_sender = pybitcoin.make_pay_to_address_script( wallets[0].addr )
    fake_recipient = pybitcoin.make_pay_to_address_script( wallets[1].addr )
    fake_recipient_address = wallets[1].addr
    fake_import_update_hash = "44" * 20

    # only 'valid' tests should return non-NULL
    # all other tests should return NOne
    for opcode, tests in all_tests.items():

        for testname, testscript in tests.items():

            parsed_op = parse_nameop( opcode, testscript[3:], fake_sender, \
                    recipient=fake_recipient, recipient_address=fake_recipient_address, import_update_hash=fake_import_update_hash )

            if testname.startswith("valid"):
                # should work
                if parsed_op is None:
                    print >> sys.stderr, "Failed to parse valid id%s%s" % (opcode, binascii.hexlify(testscript[3:]))
                    return False 

            else:
                # should fail
                if parsed_op is not None:
                    print >> sys.stderr, "Parsed invalid test '%s' (id%s%s)" % (testname, opcode, binascii.hexlify(testscript[3:]))
                    return False

    return True
