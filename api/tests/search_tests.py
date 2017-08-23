"""
    Blockstack Core
    ~~~~~

    copyright: (c) 2014-2017 by Blockstack Inc.
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

import os
import sys
import json
import unittest

import api
from api.search.db import namespace

SEARCH_URL = "/search?query={}"
SEARCH_TEST_USERS = ['muneeb', 'fredwilson', 'judecn', 'albertwenger']

class SearchTestCase(unittest.TestCase):

    def setUp(self):
        self.client = api.app.test_client()
        self.test_users = SEARCH_TEST_USERS


    def do_search(self, userq):
        url = SEARCH_URL.format(userq)
        r = self.client.get(url)
        return json.loads(r.data)

    def test_namespace_state(self):
        """ Check if namespace was correctly fetched """
        for entry in namespace.find():
            self.assertIsNotNone(entry['username'])
            if entry['username'] not in self.test_users:
                continue
            self.assertIsNotNone(entry['profile'],
                                 msg="Error in fetching profile of entry: {}".format(entry))

    def test_find_user(self):
        for u in self.test_users[1:]:
            data = self.do_search(u)
            self.assertTrue(len(data['results']) > 0)
            self.assertIn(u, data['results'][0]['username'])
            self.assertIn("profile", data['results'][0].keys())

    def test_find_subdomain(self):
        for u in ["Thomas Hobbes"]:
            data = self.do_search(u)
            self.assertTrue(len(data['results']) > 0)

if __name__ == "__main__":
    unittest.main()
