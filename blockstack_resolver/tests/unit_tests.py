#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import requests

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

import unittest

BASE_URL = 'http://0.0.0.0:5000'
VERSION = '1'


def build_url(api_endpoint):

    return BASE_URL + '/v' + VERSION + '/' + api_endpoint


def get_passcard(passname):

    headers = {'Content-type': 'application/json'}

    url = build_url('users/' + passname)

    r = requests.get(url, headers=headers)

    return r.json()

class ResolverTestCase(unittest.TestCase):

    def test_connectivity(self):
        """ Check connection to resolver
        """
        
        html = ''


        try:
            reply = requests.get(BASE_URL)
            html = reply.text
        except Exception as e:
            pass

        self.assertIn('Welcome to this resolver', html, msg="resolver is not online")

    def test_valid_passcards(self):
        """ Check valid passcards
        """

        passnames = ['fredwilson', 'davidlee']
        
        for passname in passnames:
    
            reply = get_passcard(passname)

            passcard = reply[passname]['profile']

            verifications = reply[passname]['verifications']

            self.assertIsInstance(passcard, dict, msg="data not properly formatted")

            self.assertIn('name', passcard, msg="name not in data")

            self.assertGreater(len(verifications), 0, msg="no varifications found")
    

    def test_invalid_passcards(self):
        """ Check invalid passcards
        """

        passnames = ['ben']

        for passname in passnames:
    
            reply = get_passcard(passname)[passname]

            self.assertIn('error', reply, msg="resolver didn't give error on invalid passcard")


    def test_invalid_passcards(self):
        """ Check unregistered passnames
        """

        passnames = ['gfegef7ev79efv9ev23t4fv']
   
        for passname in passnames:
    
            reply = get_passcard(passname)

            self.assertIn('error', reply, msg="resolver didn't give error on unregistered passcard")


if __name__ == '__main__':

    unittest.main()