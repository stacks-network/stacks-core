"""
    Blockstack Core
    ~~~~~

    copyright: (c) 2017 by Blockstack.org

This file is part of Blockstack Core.

    Blockstack Core is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack Core is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Search. If not, see <http://www.gnu.org/licenses/>.
"""

import os, sys, re, json, time
import unittest
import requests
import argparse
import binascii
import traceback
import jsontokens

from binascii import hexlify

import blockstack.lib.schemas as schemas
import blockstack.lib.storage

BASE_URL = 'http://localhost:5000'

DEFAULT_WALLET_ADDRESS = "1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP"

class FakeResponseObj:
    def __init__(self):
        self.status_code = 600
        self.data = ""

class ForwardingClient:
    def __init__(self, base_url):
        self.base_url = base_url
    def get(self, endpoint, headers = {}):
        resp = requests.get(self.base_url + endpoint, headers = headers)
        ret_obj = FakeResponseObj()
        ret_obj.status_code = resp.status_code
        ret_obj.data = resp.text
        return ret_obj
    def post(self, endpoint, data, headers = {}):
        resp = requests.post(self.base_url + endpoint,
                             data = data, headers = headers)
        ret_obj = FakeResponseObj()
        ret_obj.status_code = resp.status_code
        ret_obj.data = resp.text
        return ret_obj

class APITestCase(unittest.TestCase):
    def __init__(self, methodName):
        super(APITestCase, self).__init__(methodName)
        self.app = ForwardingClient("http://localhost:6270")

    def get_request(self, endpoint, headers={}, status_code=200,
                    no_json = False):
        t_start = time.time()
        resp = self.app.get(endpoint, headers = headers)
        t_end = time.time()
        print("\nget {} time: {}s".format(endpoint, t_end - t_start))
        if not resp.status_code == status_code:
            print("Bad status code: {} => {} ".format(endpoint, resp.status_code))
            print("REQUEST ===> {} + {} <===".format(endpoint, headers))
            print("RESPONSE ===>\n {} \n<===".format(resp.data))

        self.assertEqual(resp.status_code, status_code)
        if no_json:
            return resp.data

        try:
            data = json.loads(resp.data)
            return data
        except Exception as e:
            if status_code != 200:
                return {}
            raise e

    def post_request(self, endpoint, payload, headers={}, status_code=200):
        t_start = time.time()
        resp = self.app.post(endpoint, data = json.dumps(payload), headers = headers)
        t_end = time.time()
        print("\npost {} time: {}s".format(endpoint, t_end - t_start))
        if not resp.status_code == status_code:
            print("{} => {} ".format(endpoint, resp.status_code))

        self.assertEqual(resp.status_code, status_code)
        try:
            data = json.loads(resp.data)
            return data
        except Exception as e:
            if status_code != 200:
                return {}
            traceback.print_exc()
            raise e

def check_data(cls, data, required_keys={}):
    for k in required_keys:
        cls.assertIn(k, data)
        if type(required_keys[k]) == dict:
            check_data(cls, data[k], required_keys = required_keys[k])
        if type(required_keys[k]) == str:
            cls.assertRegexpMatches(data[k], required_keys[k])
        if type(required_keys[k]) == int:
            cls.assertGreaterEqual(data[k], required_keys[k])


class PingTest(APITestCase):
    def test_ping(self):
        data = self.get_request("/v1/ping",
                                headers = {} , status_code=200)

        self.assertTrue(data['status'] == 'alive')
        self.assertTrue('version' in data)

    def test_node_ping(self):
        data = self.get_request("/v1/node/ping",
                                headers = {} , status_code=200)

        self.assertTrue(data['status'] == 'alive')
        self.assertTrue('version' in data)


class LookupUsersTest(APITestCase):
    def test_found_user_lookup(self):
        base_url = '/v1/names/{}'
        url = base_url.format('muneeb.id')
        data = self.get_request(url, headers = {}, status_code=200)

        self.assertTrue(data['status'] == 'registered')

        to_check = {'address': schemas.OP_ADDRESS_PATTERN,
                    'zonefile_hash' : schemas.OP_ZONEFILE_HASH_PATTERN,
                    'last_txid' : schemas.OP_TXID_PATTERN}
        check_data(self, data, to_check)

        url = base_url.format('muneeb')
        data = self.get_request(url, headers = {}, status_code=400)

    def test_get_all_names(self):
        data = self.get_request("/v1/names?page=0",
                                headers = {} , status_code=200)
        self.assertEqual(len(data), 100, "Paginated name length != 100")
        data = self.get_request("/v1/names",
                                headers = {} , status_code=400)
        data = self.get_request("/v1/names?page=10000",
                                headers = {} , status_code=200)

    def test_get_subdomain_names(self):
        data = self.get_request("/v1/subdomains?page=0",
                                headers = {} , status_code=200)
        self.assertEqual(len(data), 100, "Paginated name length != 100")
        data = self.get_request("/v1/subdomains",
                                headers = {} , status_code=400)
        data = self.get_request("/v1/subdomains?page=10000",
                                headers = {} , status_code=200)
        data = self.get_request("/v1/blockchains/bitcoin/subdomains_count",
                                headers = {} , status_code=200)
        self.assertIn('names_count', data)

class Zonefiles(APITestCase):
    def test_get_zonefile(self):
        zf_url = '/v1/names/{}/zonefile'
        zf_hash_url = '/v1/names/{}/zonefile/{}'
        user = 'muneeb.id'

        zf_data = self.get_request(zf_url.format(user),
                                   headers = {}, status_code = 200)
        self.assertIn('zonefile', zf_data)

        zf_hash = blockstack.lib.storage.get_zonefile_data_hash(zf_data['zonefile'])
        zf_data_historic_lookup = self.get_request(zf_hash_url.format(user, zf_hash),
                                                   headers = {}, status_code = 200)
        self.assertEqual(zf_data_historic_lookup['zonefile'],
                         zf_data['zonefile'])


class NameHistoryTest(APITestCase):
    def build_url(self, username):
        return '/v1/names/{}/history'.format(username)

    def check_history_block(self, blocks):
        self.assertEqual(len(blocks), 1)
        block = blocks[0]
        self.assertRegexpMatches(block['address'], schemas.OP_ADDRESS_PATTERN)
        self.assertTrue(block['opcode'].startswith('NAME'))

    def test_found_user_lookup(self):
        usernames = 'muneeb.id'
        data = self.get_request(self.build_url(usernames),
                                headers = {}, status_code=200)

        self.assertTrue(len(data.keys()) > 2)
        for block_key, block_data in data.items():
            self.check_history_block(block_data)


class NamesOwnedTest(APITestCase):
    def build_url(self, addr):
        return '/v1/addresses/bitcoin/{}'.format(addr)
    def test_check_names(self):
        addrs_to_check = ["1J3PUxY5uDShUnHRrMyU6yKtoHEUPhKULs"]
        names_to_check = ["muneeb.id"]
        for addr, name in zip(addrs_to_check, names_to_check):
            data = self.get_request(self.build_url(addr),
                                    headers = {}, status_code = 200)
            self.assertTrue(len(data["names"]) > 0)
            self.assertIn(name, data["names"])


class NamespaceTest(APITestCase):
    def test_id_space(self):
        data = self.get_request("/v1/namespaces",
                                headers = {} , status_code=200)
        self.assertIn('id', data)

        data = self.get_request('/v1/namespaces/id', headers = {}, status_code = 200)
        to_check = {
            "address": schemas.OP_ADDRESS_PATTERN,
            "block_number": 0,
            "history": True,
            "namespace_id": True,
            "op": True,
            "op_fee": 0,
            "preorder_hash": schemas.OP_HEX_PATTERN,
            "ready_block": 0,
            "reveal_block": 0,
            "sender": schemas.OP_HEX_PATTERN,
            "sender_pubkey": schemas.OP_PUBKEY_PATTERN,
            "txid": schemas.OP_TXID_PATTERN
        }

        check_data(self, data, to_check)

    def test_id_space_names(self):
        data = self.get_request("/v1/namespaces/id/names?page=0",
                                headers = {} , status_code=200)
        self.assertEqual(len(data), 100, "Paginated name length != 100")
        data = self.get_request("/v1/namespaces/id/names",
                                headers = {} , status_code=400)



class Prices(APITestCase):
    def test_id_price(self):
        price_url = "/v1/prices/names/{}"
        data = self.get_request(price_url.format("muneeb.id"),
                                headers = {} , status_code=200)
        json_keys = data.keys()
        self.assertIn('name_price', json_keys)

    def test_ns_price(self):
        data = self.get_request("/v1/prices/namespaces/id",
                                headers = {} , status_code=200)
        check_data(self, data, {'satoshis':0})

class BlockChains(APITestCase):
    def test_consensus(self):
        data = self.get_request("/v1/blockchains/bitcoin/consensus",
                                headers = {} , status_code=200)
        self.assertRegexpMatches(data['consensus_hash'], schemas.OP_CONSENSUS_HASH_PATTERN)
    def no_test_name_history(self):
        """ this is currently an unimplemented endpoint """
        data = self.get_request("/v1/blockchains/bitcoin/names/muneeb.id/history",
                                headers = {} , status_code=405)
    
    def test_operations(self):
        data = self.get_request("/v1/blockchains/bitcoin/operations/456383",
                                headers = {} , status_code=200)

        to_check = {"address" : schemas.OP_ADDRESS_PATTERN,
                    "block_number" : 0,
                    "consensus_hash": schemas.OP_CONSENSUS_HASH_PATTERN,
                    "first_registered": 0,
                    "op" : True,
                    "txid": schemas.OP_HEX_PATTERN,
                    "value_hash": schemas.OP_HEX_PATTERN}
        check_data(self, data[0], to_check)



def test_main(args = []):
    test_classes = [PingTest, LookupUsersTest, NamespaceTest, BlockChains,
                    Prices, NamesOwnedTest, NameHistoryTest, Zonefiles]

    test_map = {}
    for t in test_classes:
        test_map[t.__name__] = t

    test_runner = unittest.TextTestRunner(verbosity=2).run

    if "--xunit-path" in args:
        ainx = args.index("--xunit-path")
        del args[ainx]
        from xmlrunner import XMLTestRunner
        test_runner = XMLTestRunner(output=args[ainx]).run
        del args[ainx]

    if len(args) == 1 and args[0] == "--list":
        print("Tests supported: ")
        for testname in test_map.keys():
            print(testname)
        return

    if len(args) == 0 or args[0] == "--all":
        args = [ testname for testname in test_map.keys() ]

    test_suite = unittest.TestSuite()
    for test_name in args:
        test_suite.addTest( unittest.TestLoader().loadTestsFromTestCase(test_map[test_name]) )
    result = test_runner( test_suite )
    if result: # test_support.run_unittest returns None
        if result.wasSuccessful():
            sys.exit(0)
        else:
            sys.exit(1)

if __name__ == '__main__':
    test_main(sys.argv[1:])
