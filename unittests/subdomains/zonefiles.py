#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~

    copyright: (c) 2017 by Blockstack.org

    This file is part of Blockstack-client.

    Blockstack-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

import unittest, json

from blockstack_client import zonefile
from blockstack_client import subdomains
import virtualchain.lib.ecdsalib as vc_ecdsa

import keylib

class SubdomainZonefiles(unittest.TestCase):
    def test_basic(self):
        test_zf = """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
registrar URI 10 1 "bsreg://foo.com:8234"
_subd.foo TXT "pubkey:data:echex:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,N:3,url:https://foobar.com/profile,url:https://dropbox.com/profile2,sig:data:0"
        """
        
        domain_name = "bar.id"

        zf_json = zonefile.decode_name_zonefile(domain_name, test_zf)

        self.assertEqual(zf_json['$origin'], domain_name)

        parsed_for_subdomains = subdomains.parse_zonefile_subdomains(zf_json)
        registrar, subds = parsed_for_subdomains
        self.assertEqual(len(subds), 1)
        sub = subds[0]
        for i in ["pubkey", "name", "urls", "n", "sig"]:
            self.assertIn(i, sub)
        self.assertEqual(sub["pubkey"], "data:echex:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        self.assertEqual(sub["n"], 3)
        self.assertEqual(len(sub["urls"]), 2)
        self.assertEqual(sub["urls"][0], "https://foobar.com/profile")
        self.assertEqual(sub["urls"][1], "https://dropbox.com/profile2")
        self.assertEqual(sub["sig"], "data:0")

        self.assertEqual(sub["name"], "foo")

    def test_parse_errs(self):
        zf = """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
registrar URI 10 1 "bsreg://foo.com:8234"
_subd.foo TXT "pubkey:data:echex:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,N:3,url:https://foobar.com/profile,url:https://dropbox.com/profile2,sig:data:0,url:https://another.one.com/"
        """
        domain_name = "bar.id"
        zf_json = zonefile.decode_name_zonefile(domain_name, zf)
        self.assertRaises(subdomains.ParseError, lambda: subdomains.parse_zonefile_subdomains(zf_json))

        zf = """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
registrar URI 10 1 "bsreg://foo.com:8234"
_subd.foo TXT "pubkey:data:echex:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,N:3,pubkey:data:echex:trythis,url:https://foobar.com/profile,url:https://dropbox.com/profile2,sig:data:0"
        """
        zf_json = zonefile.decode_name_zonefile(domain_name, zf)
        self.assertRaises(subdomains.ParseError, lambda: subdomains.parse_zonefile_subdomains(zf_json))

        zf = """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
registrar URI 10 1 "bsreg://foo.com:8234"
_subd.foo TXT "pubkey:data:echex:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,N:3,n:2,url:https://foobar.com/profile,url:https://dropbox.com/profile2,sig:data:0"
        """
        zf_json = zonefile.decode_name_zonefile(domain_name, zf)
        self.assertRaises(subdomains.ParseError, lambda: subdomains.parse_zonefile_subdomains(zf_json))

    def test_sigs(self):
        fake_privkey_hex = "5512612ed6ef10ea8c5f9839c63f62107c73db7306b98588a46d0cd2c3d15ea5"
        sk = keylib.ECPrivateKey(fake_privkey_hex)
        pk = sk.public_key()

        for t in ["foo", "bar", "bassoon"]:
            self.assertTrue(subdomains.verify(pk, t,
                                              subdomains.sign(sk, t)), t)

        subd_json = {
            "pubkey" : subdomains.encode_pubkey_entry(sk),
            "name" : "foo",
            "n" : 3,
            "url":"https://foobar.com/profile",
            "url":"https://dropbox.com/profile2"
        }

        packed_subdomain_record = subdomains.pack_and_sign_subdomain_record(subd_json, sk)

        self.assertTrue(
            subdomains.verify_subdomain_record(packed_subdomain_record, 
                                               subdomains.encode_pubkey_entry(sk)))
        self.assertTrue(
            subdomains.verify_subdomain_record(packed_subdomain_record, 
                                               subdomains.encode_pubkey_entry(pk)))
        self.assertRaises( NotImplementedError, lambda : subdomains.encode_pubkey_entry( fake_privkey_hex ) )
        self.assertRaises( NotImplementedError,
                           lambda : subdomains.verify_subdomain_record(packed_subdomain_record, 
                                                                       "data:pem:000"))

if __name__ == '__main__':
    unittest.main()
