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
            "urls": ["https://foobar.com/profile",
                     "https://dropbox.com/profile2"]
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
    def test_signed_transition(self):
        fake_privkey_hex = "5512612ed6ef10ea8c5f9839c63f62107c73db7306b98588a46d0cd2c3d15ea5"
        sk = keylib.ECPrivateKey(fake_privkey_hex)
        pk = sk.public_key()

        start_json = {
            "pubkey" : subdomains.encode_pubkey_entry(sk),
            "n" : 3,
            "urls":["https://foobar.com/profile",
                    "https://dropbox.com/profile2"]
        }

        next_json = {
            "pubkey" : "data:echex:0",
            "n" : 4,
            "name" : "foo",
            "urls": ["https://none.com"]
        }

        packed_record_next = subdomains.pack_and_sign_subdomain_record(next_json, sk)
        parsed_record_next = subdomains.parse_subdomain_record(
            subdomains.make_zonefile_entry("foo", packed_record_next, as_dict=True))
        self.assertTrue(
            subdomains._transition_valid(start_json, parsed_record_next, packed_record_next))

        next_json["urls"] = ["https://different.com"]
        packed_record_next_fail = subdomains.pack_and_sign_subdomain_record(next_json, sk)
        parsed_record_next_fail = subdomains.parse_subdomain_record(
            subdomains.make_zonefile_entry("foo", packed_record_next_fail, as_dict=True))

        self.assertRaises(subdomains.ParseError,
            lambda : subdomains._transition_valid(start_json, parsed_record_next_fail, packed_record_next))     

        next_json["n"] = "5"
        packed_record_next_fail = subdomains.pack_and_sign_subdomain_record(next_json, sk)
        parsed_record_next_fail = subdomains.parse_subdomain_record(
            subdomains.make_zonefile_entry("foo", packed_record_next_fail, as_dict=True))

        self.assertFalse(
            subdomains._transition_valid(start_json, parsed_record_next_fail, packed_record_next_fail))

        next_json["n"] = "4"
        packed_record_next_good = subdomains.pack_and_sign_subdomain_record(next_json, sk)
        parsed_record_next_good = subdomains.parse_subdomain_record(
            subdomains.make_zonefile_entry("foo", packed_record_next_good, as_dict=True))

        self.assertTrue(
            subdomains._transition_valid(start_json, parsed_record_next_good, packed_record_next_good))        

        sk_bad = keylib.ECPrivateKey()
        packed_record_next_fail = subdomains.pack_and_sign_subdomain_record(next_json, sk_bad)
        parsed_record_next_fail = subdomains.parse_subdomain_record(
            subdomains.make_zonefile_entry("foo", packed_record_next_fail, as_dict=True))
        self.assertFalse(
            subdomains._transition_valid(start_json, parsed_record_next_fail, packed_record_next_fail))

    def test_db_builder(self):
        history = [
            """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0"
registrar URI 10 1 "bsreg://foo.com:8234"
_subd.foo TXT "pubkey:{},N:0,url:https://foobar.com/profile,url:https://dropbox.com/profile2"
""",
            """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0"
registrar URI 10 1 "bsreg://foo.com:8234"
_subd.bar TXT "pubkey:{},N:0,url:https://foobar.com/profile,url:https://dropbox.com/profile2"
""",
            """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0"
registrar URI 10 1 "bsreg://foo.com:8234"
{}
""",
            """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0"
registrar URI 10 1 "bsreg://foo.com:8234"
{}
"""]

        foo_bar_sk = keylib.ECPrivateKey()
        bar_bar_sk = keylib.ECPrivateKey()

        history[0] = history[0].format(subdomains.encode_pubkey_entry(foo_bar_sk))
        history[1] = history[1].format(subdomains.encode_pubkey_entry(bar_bar_sk))
        history[2] = history[2].format(
            subdomains.make_zonefile_entry(
                "bar",
                subdomains.pack_and_sign_subdomain_record(
                    {"pubkey" : subdomains.encode_pubkey_entry(bar_bar_sk),
                     "n" : 1,
                     "urls" : ["https://foobar.com", "https://noodles.com"]},
                    bar_bar_sk)))
        history[3] = history[3].format(
            subdomains.make_zonefile_entry(
                "foo",
                subdomains.pack_and_sign_subdomain_record(
                    {"pubkey" : subdomains.encode_pubkey_entry(foo_bar_sk),
                     "n" : 1,
                     "urls" : ["https://foobar.com", "https://poodles.com"]},
                    foo_bar_sk)))

        subdomain_db = subdomains._build_subdomain_db("bar.id", history[:1])
        self.assertEqual(subdomain_db["foo"]["n"], 0)
        self.assertIn("https://foobar.com/profile", subdomain_db["foo"]["urls"])
        self.assertIn("https://dropbox.com/profile2", subdomain_db["foo"]["urls"])
        self.assertNotIn("bar", subdomain_db)

        subdomain_db = subdomains._build_subdomain_db("bar.id", history[:2])
        self.assertIn("bar", subdomain_db)
        self.assertEqual(subdomain_db["bar"]["n"], 0)
        self.assertIn("https://foobar.com/profile", subdomain_db["bar"]["urls"])
        self.assertIn("https://dropbox.com/profile2", subdomain_db["bar"]["urls"])

        subdomain_db = subdomains._build_subdomain_db("bar.id", history[:3])
        self.assertEqual(subdomain_db["foo"]["n"], 0)
        self.assertEqual(subdomain_db["bar"]["n"], 1)
        self.assertIn("https://foobar.com/profile", subdomain_db["foo"]["urls"])
        self.assertIn("https://dropbox.com/profile2", subdomain_db["foo"]["urls"])
        self.assertNotIn("https://foobar.com/profile", subdomain_db["bar"]["urls"])
        self.assertNotIn("https://dropbox.com/profile2", subdomain_db["bar"]["urls"])

        subdomain_db = subdomains._build_subdomain_db("bar.id", history)
        self.assertEqual(subdomain_db["foo"]["n"], 1)
        self.assertEqual(subdomain_db["bar"]["n"], 1)
        self.assertNotIn("https://foobar.com/profile", subdomain_db["foo"]["urls"])
        self.assertNotIn("https://dropbox.com/profile2", subdomain_db["foo"]["urls"])
        self.assertIn("https://foobar.com", subdomain_db["bar"]["urls"])
        self.assertIn("https://noodles.com", subdomain_db["bar"]["urls"])
        self.assertIn("https://foobar.com", subdomain_db["foo"]["urls"])
        self.assertIn("https://poodles.com", subdomain_db["foo"]["urls"])

    def lets_resolve(self):
        pass

if __name__ == '__main__':
    unittest.main()
