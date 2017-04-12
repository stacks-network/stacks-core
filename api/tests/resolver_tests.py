#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Resolver
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import os
import sys
import requests
import json
import unittest

import api

PROFILE_URL = "/v2/users/{}"

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

        usernames = ['fredwilson', 'davidlee']
        for username in usernames:
            reply = self.get_profile(username)
            profile = reply[username]['profile']
            verifications = reply[username]['verifications']
            self.assertIsInstance(profile, dict, msg="data not properly formatted")
            self.assertIn('name', profile, msg="name not in data")
            self.assertGreater(len(verifications), 0, msg="no varifications found")

    def test_invalid_profiles(self):
        """ Check invalid profiles
        """

        usernames = ['ben']
        for username in usernames:
            reply = self.get_profile(username)[username]
            self.assertIn('error', reply, msg="resolver didn't give error on invalid profile")

    def test_invalid_profiles(self):
        """ Check unregistered usernames
        """
        usernames = ['gfegef7ev79efv9ev23t4fv']
        for username in usernames:
            reply = self.get_profile(username)
            self.assertIn('error', reply, msg="resolver didn't give error on unregistered profile")
