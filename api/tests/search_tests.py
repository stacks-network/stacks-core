#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Search
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

This file is part of Search.

    Search is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Search is distributed in the hope that it will be useful,
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

from pymongo import MongoClient

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")
sys.path.insert(0, parent_dir)

from search.db_index import namespace

test_users = ['muneeb.id', 'fredwilson.id']


class SearchTestCase(unittest.TestCase):

    def tearDown(self):
        pass

    def test_namespace_state(self):
        """ Check if namespace was correctly fetched
        """

        for entry in namespace.find():

            self.assertIsNotNone(entry['profile'], msg="Error in fetching profile")


if __name__ == '__main__':

    unittest.main()
