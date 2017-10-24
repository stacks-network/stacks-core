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

import os
import sys
import requests
import json
import unittest

import api

PROFILE_URL = "/v1/users/{}"

class ResolverTestCase(unittest.TestCase):

    def setUp(self):
        self.client = api.app.test_client()

    def get_profile(self, username):
        url = PROFILE_URL.format(username)
        r = self.client.get(url)
        return json.loads(r.data)


    def test_valid_profiles(self):
        """ Check valid profiles
        """

        usernames = [ 'muneeb', 'fredwilson', 'davidlee']
        for username in usernames:
            reply = self.get_profile(username)
            profile = reply[username]['profile']
            public_key = reply[username]['public_key']
            verifications = reply[username]['verifications']
            self.assertIsInstance(profile, dict, msg="data not properly formatted")
            self.assertIn('name', profile, msg="name not in data")
            self.assertGreater(len(verifications), 0, msg="no verifications found")
            self.assertIsInstance(public_key, (str, unicode, NoneType), msg='invalid public key')

    def test_invalid_profiles(self):
        """ Check invalid profiles
        """

        usernames = ['ben']
        for username in usernames:
            reply = self.get_profile(username)[username]
            self.assertIn('error', reply, msg="resolver didn't give error on invalid profile: {}".format(reply))

    def test_invalid_profiles(self):
        """ Check unregistered usernames
        """
        usernames = ['gfegef7ev79efv9ev23t4fv']
        for username in usernames:
            reply = self.get_profile(username)[username]
            self.assertIn('error', reply, msg="resolver didn't give error on unregistered profile: {}".format(reply))

if __name__ == "__main__":
    unittest.main()
