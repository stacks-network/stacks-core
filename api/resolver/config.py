# -*- coding: utf-8 -*-
"""
    Resolver
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import os

import logging
log = logging.getLogger()

DEBUG = False

DEFAULT_PORT = 5000
DEFAULT_HOST = '0.0.0.0'
MEMCACHED_PORT = 11211
MEMCACHED_SERVER = '127.0.0.1'

RECENT_BLOCKS = 100
VALID_BLOCKS = 36000
REFRESH_BLOCKS = 25

DEFAULT_NAMESPACE = "id"

NAMES_FILENAME = "names.json"
NEW_NAMES_FILENAME = 'new_names.json'
CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))
NAMES_FILE = os.path.join(CURRENT_DIR, NAMES_FILENAME)
NEW_NAMES_FILE = os.path.join(CURRENT_DIR, NEW_NAMES_FILENAME)

DEBUG = True

MEMCACHED_USERNAME = None
MEMCACHED_PASSWORD = None

BLOCKSTACKD_IP = 'localhost'
BLOCKSTACKD_PORT = 6264
DHT_MIRROR_IP = '52.20.98.85'
DHT_MIRROR_PORT = 6266

MEMCACHED_TIMEOUT = 12 * 60 * 60
USERSTATS_TIMEOUT = 60 * 60
MEMCACHED_ENABLED = False

MEMCACHED_SERVERS = ['127.0.0.1:11211']

API_USERNAME = 'default'
API_PASSWORD = 'default'