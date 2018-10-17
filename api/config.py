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

# str2bool is a convinence function
def str2bool(s):
    if s == 'True':
        return True
    elif s == 'False':
        return False
    else:
        raise ValueError("Cannot covert {} to a bool".format(s))

# MAX_PROFILE_LIMIT determines the max profile size that the node will index
MAX_PROFILE_LIMIT = int(os.getenv('MAX_PROFILE_LIMIT','8142'))           # (8 * 1024) - 50 or roughly 8kb limit

# DEFAULT_CACHE_TIMEOUT determines the
DEFAULT_CACHE_TIMEOUT = int(os.getenv('DEFAULT_CACHE_TIMEOUT','43200'))  # 12 hours in seconds

# DEBUG increases logging verbosity
DEBUG = str2bool(os.getenv('DEBUG','False'))

# DEFAULT_PORT sets the port that the process will run on
DEFAULT_PORT = int(os.getenv('DEFAULT_PORT', '5000'))

# DEFAULT_HOST sets the host for the flask app
DEFAULT_HOST = os.getenv('DEFAULT_HOST','localhost')

# PUBLIC_NODE disables posts to the API to prevent malicous use
PUBLIC_NODE = str2bool(os.getenv('PUBLIC_NODE','False'))

# MONGODB_URI contains the connection string to use for connecting to mongo
MONGODB_URI = os.getenv('MONGODB_URI', "mongodb://localhost")

# BASE_API_URL sets the blockstack api connection string
BASE_API_URL = os.getenv('BASE_API_URL', "http://localhost:6270")

# INDEXER_API_URL sets the blockstack indexer daemon connection string (used only for testing at the moment)
BASE_INDEXER_API_URL = os.getenv('BASE_INDEXER_API_URL', 'http://localhost:6264')

# PUBLIC_NODE_URL controls the what hostname is returned to clients
PUBLIC_NODE_URL = os.getenv('PUBLIC_NODE_URL', 'https://core.example.org')

# SEARCH_NODE_URL sets the search API connection string
SEARCH_NODE_URL = os.getenv('SEARCH_NODE_URL', 'https://search.example.org')

# SEARCH_DEFAULT_LIMIT sets the number of returns per call
SEARCH_DEFAULT_LIMIT = int(os.getenv('SEARCH_DEFAULT_LIMIT', '50'))

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
SEARCH_SUPPORTED_PROOFS = ['twitter', 'facebook', 'github', 'domain']
