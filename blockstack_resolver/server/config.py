# -*- coding: utf-8 -*-
"""
    Openname-resolver
    ~~~~~

    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

import os
from commontools import log

DEBUG = True

DEFAULT_PORT = 5000
DEFAULT_HOST = '0.0.0.0'
DEFAULT_MEMCACHED_PORT = 11211
DEFAULT_MEMCACHED_SERVER = '127.0.0.1'

MEMCACHED_TIMEOUT = 15 * 60
MEMCACHED_ENABLED = True

try:
    from config_local import *
except:

    log.debug('config_local.py not found, using default settings')

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
            memcached_server = DEFAULT_MEMCACHED_SERVER + ':' + str(DEFAULT_MEMCACHED_PORT)
            MEMCACHED_SERVERS = [memcached_server]

    # --------------------------------------------------
    NAMECOIND_USE_HTTPS = True

    try:
        NAMECOIND_SERVER = os.environ['NAMECOIND_SERVER']
        NAMECOIND_PORT = os.environ['NAMECOIND_PORT']
        NAMECOIND_USER = os.environ['NAMECOIND_USER']
        NAMECOIND_PASSWD = os.environ['NAMECOIND_PASSWD']
    except:
        log.debug("Namecoind not configured properly")
        exit(1)

    # --------------------------------------------------
    try:
        API_USERNAME = os.environ['API_USERNAME']
        API_PASSWORD = os.environ['API_PASSWORD']
    except:
        API_USERNAME = API_PASSWORD = ''
