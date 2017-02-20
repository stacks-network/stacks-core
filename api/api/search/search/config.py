#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Search
    ~~~~~

    copyright: (c) 2014-2017 by Blockstack Inc.
    copyright: (c) 2017 by Blockstack.org

This file is part of Blockstack.

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

import os

DEBUG = True

MEMCACHED_ENABLED = True
LUCENE_ENABLED = False

DEFAULT_PORT = 5000
DEFAULT_HOST = '127.0.0.1'

BULK_INSERT_LIMIT = 1000
DEFAULT_LIMIT = 50
MEMCACHED_TIMEOUT = 6 * 60 * 60


RESOLVER_URL = 'http://resolver.onename.com'
ALL_USERS_ENDPOINT = '/v2/users'

BLOCKCHAIN_DATA_FILENAME = "data/blockchain_data.json"
PROFILE_DATA_FILENAME = "data/profile_data.json"

current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")
BLOCKCHAIN_DATA_FILE = os.path.join(parent_dir, BLOCKCHAIN_DATA_FILENAME)
PROFILE_DATA_FILE = os.path.join(parent_dir, PROFILE_DATA_FILENAME)

SUPPORTED_PROOFS = ['twitter', 'facebook', 'github', 'domain']

try:
    # to overrite things like MEMCACHED_ENABLED
    from config_local import *
except:
    pass
