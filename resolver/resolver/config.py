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

try:
    from config_local import *
except:

    log.debug('config_local.py not found, using default settings')

    MEMCACHED_TIMEOUT = 12 * 60 * 60
    USERSTATS_TIMEOUT = 60 * 60
    MEMCACHED_ENABLED = False

    try:
        MEMCACHED_USERNAME = os.environ['MEMCACHEDCLOUD_USERNAME']
        MEMCACHED_PASSWORD = os.environ['MEMCACHEDCLOUD_PASSWORD']
    except:
        try:
            MEMCACHED_USERNAME = os.environ['MEMCACHIER_USERNAME']
            MEMCACHED_PASSWORD = os.environ['MEMCACHIER_PASSWORD']
        except:
            MEMCACHED_USERNAME = None
            MEMCACHED_PASSWORD = None

    try:
        MEMCACHED_SERVERS = os.environ['MEMCACHEDCLOUD_SERVERS'].split(',')
    except:
        try:
            MEMCACHED_SERVERS = os.environ['MEMCACHIER_SERVERS'].split(',')
        except:
            memcached_server = MEMCACHED_SERVER + ':' + str(MEMCACHED_PORT)
            MEMCACHED_SERVERS = [memcached_server]

    try:
        BLOCKSTACKD_IP = os.environ['BLOCKSTACKD_IP']
        BLOCKSTACKD_PORT = os.environ['BLOCKSTACKD_PORT']
        DHT_MIRROR_IP = os.environ['DHT_MIRROR_IP']
        DHT_MIRROR_PORT = os.environ['DHT_MIRROR_PORT']
    except:
        log.debug("Blockstack-server or DHT-mirror not configured properly")
        exit(1)

    # if password protecting the resolver
    try:
        API_USERNAME = os.environ['API_USERNAME']
        API_PASSWORD = os.environ['API_PASSWORD']
    except:
        API_USERNAME = API_PASSWORD = ''
