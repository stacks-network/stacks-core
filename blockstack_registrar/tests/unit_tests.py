#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

This file is part of Registrar.

    Registrar is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Registrar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Registrar. If not, see <http://www.gnu.org/licenses/>.
"""

import os
import sys
import json
import unittest

from basicrpc import Proxy
from pymongo import MongoClient

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")
sys.path.insert(0, parent_dir)

from registrar.nameops import usernameRegistered
from registrar.nameops import get_dht_profile

from registrar.network import get_bs_client, get_dht_client


test_users = ['muneeb.id', 'fredwilson.id']


def get_db():

    MONGODB_URI = os.environ['MONGODB_URI']
    remote_db = MongoClient(MONGODB_URI).get_default_database()

    return remote_db.user


class RegistrarTestCase(unittest.TestCase):

    def tearDown(self):
        pass

    def test_db_connectivity(self):
        """ Check connection to databases
        """

        users = get_db()
        count = users.count()

        self.assertGreater(count, 100, msg="Cannot connect to DB")

    def test_blockstore_connectivity(self):
        """ Check connection to blockstore node
        """

        client = get_bs_client()
        resp = client.ping()[0]

        self.assertDictContainsSubset({'status': 'alive'}, resp)

    def test_dht_connectivity(self):
        """ Check connection to DHT
        """

        client = get_dht_client()
        resp = client.ping()[0]

        self.assertDictContainsSubset({'status': 'alive'}, resp)

    def test_username_registered(self):
        """ Check if username is registered on blockchain
        """

        for fqu in test_users:

            resp = usernameRegistered(fqu)

            self.assertTrue(resp, msg="Username not registered")

    def test_profile_data(self):
        """ Check if:
            1) correct profile data is associated with username
            2) data can be fetched from DHT
        """

        for fqu in test_users:

            profile = get_dht_profile(fqu)

            profile = json.loads(profile)

            self.assertIsInstance(profile, dict, msg="Profile not found")

if __name__ == '__main__':

    unittest.main()
