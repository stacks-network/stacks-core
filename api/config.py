#!/usr/bin/env python2
# -*- coding: utf-8 -*-
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
    along with Blockstack Core. If not, see <http://www.gnu.org/licenses/>.
"""

import os
import re

DEBUG = True

DEFAULT_PORT = 5000
DEFAULT_HOST = '0.0.0.0'

MAX_PROFILE_LIMIT = (8 * 1024) - 50  # roughly 8kb max limit

EMAIL_REGREX = r'[^@]+@[^@]+\.[^@]+'

DEFAULT_NAMESPACE = "id"

PUBLIC_NODE = True

BASE_API_URL = "http://localhost:6270"
PUBLIC_NODE_URL = 'https://core.blockstack.org'
SEARCH_NODE_URL = 'https://search.blockstack.org'
BLOCKSTACKD_IP = 'localhost'
BLOCKSTACKD_PORT = 6264
DHT_MIRROR_IP = '52.20.98.85'
DHT_MIRROR_PORT = 6266

RECENT_BLOCKS = 100
VALID_BLOCKS = 36000
REFRESH_BLOCKS = 25

DEFAULT_NAMESPACE = "id"

# For the resolver endpoint
NAMES_FILENAME = "names.json"
NEW_NAMES_FILENAME = 'new_names.json'
CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))
NAMES_FILE = os.path.join(CURRENT_DIR, NAMES_FILENAME)
NEW_NAMES_FILE = os.path.join(CURRENT_DIR, NEW_NAMES_FILENAME)

# For search endpoint
SEARCH_API_ENDPOINT_ENABLED = True
SEARCH_BLOCKCHAIN_DATA_FILE = "/var/blockstack-search/blockchain_data.json"
SEARCH_PROFILE_DATA_FILE = "/var/blockstack-search/profile_data.json"
SEARCH_LAST_INDEX_DATA_FILE = "/var/blockstack-search/last_indexed.json"
SEARCH_LOCKFILE = "/var/blockstack-search/indexer_lockfile.json"
SEARCH_BULK_INSERT_LIMIT = 1000
SEARCH_DEFAULT_LIMIT = 50
SEARCH_LUCENE_ENABLED = False
SEARCH_SUPPORTED_PROOFS = ['twitter', 'facebook', 'github', 'domain']


# Memcache settings
MEMCACHED_USERNAME = None
MEMCACHED_PASSWORD = None

MEMCACHED_TIMEOUT = 12 * 60 * 60
USERSTATS_TIMEOUT = 60 * 60
MEMCACHED_ENABLED = False

MEMCACHED_PORT = 11211
MEMCACHED_SERVER = '127.0.0.1'
MEMCACHED_SERVERS = ['127.0.0.1:11211']

if 'DYNO' in os.environ:
    DEBUG = False
    # heroku configs go here
else:
    DEBUG = True
    APP_URL = 'localhost:5000'
