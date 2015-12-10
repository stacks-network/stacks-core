#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore-client
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

This file is part of Blockstore-client.

    Blockstore-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Blockstore-client. If not, see <http://www.gnu.org/licenses/>.
"""

import os
import sys
import json
import unittest

from blockstore_client import client
from blockstore_client.utils import print_result as pprint
from blockstore_client.config import BLOCKSTORED_SERVER, BLOCKSTORED_PORT

# start session
client.session(server_host=BLOCKSTORED_SERVER, server_port=BLOCKSTORED_PORT)

test_names = ["muneeb.id", "fredwilson.id"]


class BlockstoreClientTest(unittest.TestCase):

    def tearDown(self):
        pass

    def test_ping(self):
        """ Check ping
        """

        resp = client.ping()

        self.assertDictContainsSubset({'status': 'alive'}, resp)

    def test_getinfo(self):
        """ Check getinfo
        """

        resp = client.getinfo()
        pprint(resp)

        if 'blocks' not in resp:
            raise ValueError('blocks not in response')

        self.assertIsInstance(resp, dict, msg="Not json")

    def test_lookup(self):
        """ Check lookup
        """

        for fqu in test_names:
            resp = client.get_name_blockchain_record(fqu)

            if 'value_hash' not in resp:
                raise ValueError('value_hash not in response')

            self.assertIsInstance(resp, dict, msg="Not json")

    def test_name_cost(self):
        """ Check name cost
        """

        resp = client.get_name_cost(test_names[0])

        if 'satoshis' not in resp:
            raise ValueError('satoshis not in response')

        self.assertIsInstance(resp, dict, msg="Not json")

if __name__ == '__main__':

    unittest.main()
