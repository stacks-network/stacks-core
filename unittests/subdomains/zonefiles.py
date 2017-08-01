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
from blockstack_client import user as user_db
from blockstack_client import subdomains
import virtualchain.lib.ecdsalib as vc_ecdsa

from subdomain_registrar import util as subdomain_util

import jsonschema
from blockstack_client.schemas import USER_ZONEFILE_SCHEMA
import keylib
import blockstack_zones

class SubdomainZonefiles(unittest.TestCase):
    def test_basic(self):
        test_zf = """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
registrar URI 10 1 "bsreg://foo.com:8234"
foo TXT "pk={}" "seqn=3" "parts=0"
        """


        fake_privkey_hex = "5512612ed6ef10ea8c5f9839c63f62107c73db7306b98588a46d0cd2c3d15ea5"
        sk = keylib.ECPrivateKey(fake_privkey_hex)
        pk = sk.public_key()
        
        test_zf = test_zf.format(subdomains.encode_pubkey_entry(pk))

        domain_name = "bar.id"

        zf_json = zonefile.decode_name_zonefile(domain_name, test_zf)

        self.assertEqual(zf_json['$origin'], domain_name)

        subds = subdomains.parse_zonefile_subdomains(zf_json)
        self.assertEqual(len(subds), 1)
        sub = subds[0]
        self.assertEqual(sub.n, 3)
        self.assertEqual(sub.sig, None)

        self.assertEqual(sub.name, "foo")

    def test_parse_errs(self):
        zf = """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
registrar URI 10 1 "bsreg://foo.com:8234"
foo TXT should_not_parse
        """
        domain_name = "bar.id"
        zf_json = zonefile.decode_name_zonefile(domain_name, zf)
        self.assertEqual(len(subdomains.parse_zonefile_subdomains(zf_json)), 0)

        zf = """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
registrar URI 10 1 "bsreg://foo.com:8234"
foo TXT "pk={}" "seqn=3" "should_not_parse"
        """
        zf_json = zonefile.decode_name_zonefile(domain_name, zf)
        self.assertEqual(len(subdomains.parse_zonefile_subdomains(zf_json)), 0)

    def test_sigs(self):
        fake_privkey_hex = "5512612ed6ef10ea8c5f9839c63f62107c73db7306b98588a46d0cd2c3d15ea5"
        sk = keylib.ECPrivateKey(fake_privkey_hex)
        pk = sk.public_key()

        for t in ["foo", "bar", "bassoon"]:
            self.assertTrue(subdomains.verify(pk, t,
                                              subdomains.sign(sk, t)), t)

        subdomain = subdomains.Subdomain("foo", subdomains.encode_pubkey_entry(sk), 3, "")

        user_zf = {
            '$origin': 'foo',
            '$ttl': 3600,
            'txt' : [], 'uri' : []
        }

        user_zf['uri'].append(zonefile.url_to_uri_record("https://foo_foo.com/profile.json"))
        jsonschema.validate(user_zf, USER_ZONEFILE_SCHEMA)

        subdomain.zonefile_str = blockstack_zones.make_zone_file(user_zf)

        subdomain.add_signature(sk)

        self.assertTrue(subdomain.verify_signature(pk))

        parsed_zf = zonefile.decode_name_zonefile(subdomain.name, subdomain.zonefile_str)
        urls = user_db.user_zonefile_urls(parsed_zf)

        self.assertEqual(len(urls), 1)
        self.assertIn("https://foo_foo.com/profile.json", urls)

        self.assertRaises( NotImplementedError, lambda : subdomains.encode_pubkey_entry( fake_privkey_hex ) )

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

        subdomain1 = subdomains.Subdomain("foo", subdomains.encode_pubkey_entry(sk), 3, "")
        subdomain2 = subdomains.Subdomain("bar", subdomains.encode_pubkey_entry(sk), 4, "")

        subdomain2.add_signature(sk)
        self.assertTrue(
            subdomains._transition_valid(subdomain1, subdomain2))

    def test_db_builder(self):
        history = [
            """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0"
registrar URI 10 1 "bsreg://foo.com:8234"
foo TXT "pk={}" "seqn=0" "parts=0"
""",
            """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0"
registrar URI 10 1 "bsreg://foo.com:8234"
bar TXT "pk={}" "seqn=0" "parts=0"
""",
]

        foo_bar_sk = keylib.ECPrivateKey()
        bar_bar_sk = keylib.ECPrivateKey()

        history[0] = history[0].format(subdomains.encode_pubkey_entry(foo_bar_sk))
        history[1] = history[1].format(subdomains.encode_pubkey_entry(bar_bar_sk))

        domain_name = "bar.id"

        empty_zf = """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0"
registrar URI 10 1 "bsreg://foo.com:8234"
"""

        zf_json = zonefile.decode_name_zonefile(domain_name, empty_zf)
        self.assertEqual(zf_json['$origin'], domain_name)

        sub1 = subdomains.Subdomain("foo", subdomains.encode_pubkey_entry(foo_bar_sk), 1, "")
        sub2 = subdomains.Subdomain("bar", subdomains.encode_pubkey_entry(bar_bar_sk), 1, "")
        sub1.add_signature(foo_bar_sk)
        sub2.add_signature(bar_bar_sk)

        subdomain_util._extend_with_subdomain(zf_json, sub2)

        history.append(blockstack_zones.make_zone_file(zf_json))

        zf_json = zonefile.decode_name_zonefile(domain_name, empty_zf)
        subdomain_util._extend_with_subdomain(zf_json, sub1)

        history.append(blockstack_zones.make_zone_file(zf_json))

        subdomain_db = subdomains._build_subdomain_db("bar.id", history[:1])
        self.assertIn("foo", subdomain_db, "Contents actually: {}".format(subdomain_db.keys()))
        self.assertEqual(subdomain_db["foo"].n, 0)
        self.assertNotIn("bar", subdomain_db)

        subdomain_db = subdomains._build_subdomain_db("bar.id", history[:2])
        self.assertIn("bar", subdomain_db)
        self.assertEqual(subdomain_db["bar"].n, 0)

        subdomain_db = subdomains._build_subdomain_db("bar.id", history[:3])
        self.assertEqual(subdomain_db["foo"].n, 0)
        self.assertEqual(subdomain_db["bar"].n, 1)

        subdomain_db = subdomains._build_subdomain_db("bar.id", history)
        self.assertEqual(subdomain_db["foo"].n, 1)
        self.assertEqual(subdomain_db["bar"].n, 1)

    def test_db_builder_bad_transitions(self):
        history = [
            """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0"
registrar URI 10 1 "bsreg://foo.com:8234"
foo TXT "pk={}" "seqn=0" "parts=0"
""",
            """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0"
registrar URI 10 1 "bsreg://foo.com:8234"
bar TXT "pk={}" "seqn=0" "parts=0"
""",
]

        foo_bar_sk = keylib.ECPrivateKey()
        bar_bar_sk = keylib.ECPrivateKey()

        history[0] = history[0].format(subdomains.encode_pubkey_entry(foo_bar_sk))
        history[1] = history[1].format(subdomains.encode_pubkey_entry(bar_bar_sk))

        domain_name = "bar.id"

        empty_zf = """$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0"
registrar URI 10 1 "bsreg://foo.com:8234"
"""

        zf_json = zonefile.decode_name_zonefile(domain_name, empty_zf)
        self.assertEqual(zf_json['$origin'], domain_name)

        # bad transition n=0 -> n=0
        sub1 = subdomains.Subdomain("foo", subdomains.encode_pubkey_entry(foo_bar_sk), 0, "")

        subdomain_util._extend_with_subdomain(zf_json, sub1)

        history.append(blockstack_zones.make_zone_file(zf_json))

        # bad transition bad sig.
        zf_json = zonefile.decode_name_zonefile(domain_name, empty_zf)
        self.assertEqual(zf_json['$origin'], domain_name)

        sub2 = subdomains.Subdomain("foo", subdomains.encode_pubkey_entry(bar_bar_sk), 1, "")
        subdomain_util._extend_with_subdomain(zf_json, sub2)
        history.append(blockstack_zones.make_zone_file(zf_json))

        subdomain_db = subdomains._build_subdomain_db("bar.id", history[:1])
        self.assertEqual(subdomain_db["foo"].n, 0)
        self.assertNotIn("bar", subdomain_db)

        subdomain_db = subdomains._build_subdomain_db("bar.id", history[:2])
        self.assertIn("bar", subdomain_db)
        self.assertEqual(subdomain_db["bar"].n, 0)

        subdomain_db = subdomains._build_subdomain_db("bar.id", history[:3])
        self.assertEqual(subdomain_db["foo"].n, 0)
        self.assertEqual(subdomain_db["bar"].n, 0)

        # handle repeated zonefile

        subdomain_db = subdomains._build_subdomain_db("bar.id", history[:3])
        self.assertEqual(subdomain_db["foo"].n, 0)
        self.assertEqual(subdomain_db["bar"].n, 0)
        subdomains._build_subdomain_db("bar.id", history[:3], subdomain_db = subdomain_db)
        self.assertEqual(subdomain_db["foo"].n, 0)
        self.assertEqual(subdomain_db["bar"].n, 0)        

    def test_large_zonefile(self):
        empty_zf = """$ORIGIN registrar.id
        $TTL 3600
        pubkey TXT "pubkey:data:0"
        registrar URI 10 1 "bsreg://foo.com:8234"
        """
        domain_name = "registrar.id"
        zf_js = zonefile.decode_name_zonefile(domain_name, empty_zf)
        #for i in range(0, 200):


if __name__ == '__main__':
    unittest.main()
