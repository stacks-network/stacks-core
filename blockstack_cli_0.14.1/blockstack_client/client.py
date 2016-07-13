#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack-client.

    Blockstack-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

import argparse
import sys
import json
import traceback
import types
import socket
import uuid
import os
import importlib
import pprint
import random
import time
import copy
import blockstack_profiles
import urllib

from proxy import *
from spv import SPVClient
import storage

import pybitcoin
import bitcoin
import binascii
from utilitybelt import is_hex

from config import get_logger, DEBUG, MAX_RPC_LEN, find_missing, BLOCKSTACKD_SERVER, \
    BLOCKSTACKD_PORT, BLOCKSTACK_METADATA_DIR, BLOCKSTACK_DEFAULT_STORAGE_DRIVERS, \
    FIRST_BLOCK_MAINNET, NAME_OPCODES, OPFIELDS, CONFIG_DIR, SPV_HEADERS_PATH, BLOCKCHAIN_ID_MAGIC, \
    NAME_PREORDER, NAME_REGISTRATION, NAME_UPDATE, NAME_TRANSFER, NAMESPACE_PREORDER, NAME_IMPORT, \
    USER_ZONEFILE_TTL, CONFIG_PATH, get_config, CONFIG_PATH

log = get_logger()

import virtualchain

from wallet import * 

# ancillary storage providers
STORAGE_IMPL = None
ANALYTICS_KEY = None

def session(conf=None, config_path=CONFIG_PATH, server_host=None, server_port=None,
            storage_drivers=None, metadata_dir=None, spv_headers_path=None, set_global=False):

    """
    Create a blockstack session:
    * validate the configuration
    * load all storage drivers
    * initialize all storage drivers
    * load an API proxy to blockstack

    conf's fields override specific keyword arguments.

    Returns the API proxy object.
    """

    if conf is None and config_path is not None:
        conf = get_config(config_path)

    if conf is not None:
        if server_host is None:
            server_host = conf['server']
        if server_port is None:
            server_port = conf['port']
        if storage_drivers is None:
            storage_drivers = conf['storage_drivers']
        if metadata_dir is None:
            metadata_dir = conf['metadata']
        if spv_headers_path is None:
            spv_headers_path = conf['blockchain_headers']

    if storage_drivers is None:
        log.error("No storage driver(s) defined in the config file.  Please set 'storage=' to a comma-separated list of drivers")
        sys.exit(1)

    # create proxy
    proxy = BlockstackRPCClient(server_host, server_port)

    # load all storage drivers
    for storage_driver in storage_drivers.split(","):
        storage_impl = load_storage(storage_driver)
        if storage_impl is None:
            log.error("Failed to load storage driver '%s'" % (storage_driver))
            sys.exit(1)

        rc = register_storage(storage_impl, conf)
        if not rc:
            log.error("Failed to initialize storage driver '%s'" % (storage_driver))
            sys.exit(1)

    # initialize SPV
    SPVClient.init(spv_headers_path)
    proxy.spv_headers_path = spv_headers_path
    proxy.conf = conf

    if set_global:
        set_default_proxy( proxy )

    return proxy


def load_storage(module_name):
    """
    Load a storage implementation, given its module name.
    """

    try:
        storage_impl = importlib.import_module("blockstack_storage_drivers.%s" % module_name)
        name = storage_impl.__name__.split(".")[-1]
        storage_impl.__name__ = name
        log.debug("Loaded storage driver '%s'" % name)
    except ImportError, ie:
        raise Exception("Failed to import blockstack_storage_drivers.%s.  Please verify that it is installed and is accessible via your PYTHONPATH" % module_name)

    return storage_impl


def register_storage(storage_impl, conf):
    """
    Register a storage implementation.
    """
    rc = storage.register_storage(storage_impl)
    if rc:
        rc = storage_impl.storage_init(conf)

    return rc


def get_analytics_key( uuid, proxy=None ):
    """
    Get the analytics key from the blockstack server
    """
    if proxy is None:
        proxy = get_default_proxy()

    key = None
    if os.environ.get("BLOCKSTACK_TEST_ANALYTICS_KEY", None) is not None:
        key = {'analytics_key': os.environ.get("BLOCKSTACK_TEST_ANALYTICS_KEY")}

    else:
        try:
            key = proxy.get_analytics_key( uuid )
        except Exception, e:
            log.debug("Failed to get analytics key")
            return None

    if 'error' in key:
        log.debug("Failed to fetch analytics key: %s" % key['error'])
        return None 

    if 'analytics_key' not in key.keys():
        log.debug("No analytics key returned")
        return None

    return key['analytics_key']


def analytics_event( event_type, event_payload, config_path=CONFIG_PATH, proxy=None ):
    """
    Log an analytics event
    Return True if logged
    Return False if not
    """
    global ANALYTICS_KEY

    try:
        import mixpanel 
    except:
        log.debug("mixpanel is not installed; no analytics will be reported")
        return False

    conf = get_config(path=config_path)
    if conf is None:
        log.debug("Failed to load config")
        return False

    if not conf['anonymous_statistics']:
        return False
   
    u = conf['uuid']
    if ANALYTICS_KEY is None:
        ANALYTICS_KEY = get_analytics_key( u )
        if ANALYTICS_KEY is None:
            return False

    # log the event
    log.debug("Track event '%s': %s" % (event_type, event_payload))
    mp = mixpanel.Mixpanel(ANALYTICS_KEY)
    mp.track( u, event_type, event_payload )
    mp.track( u, "Perform action", {} )
    return True


def analytics_user_register( u, config_path=CONFIG_PATH, proxy=None ):
    """
    Register a user with the analytics service
    """
    global ANALYTICS_KEY

    try:
        import mixpanel 
    except:
        log.debug("mixpanel is not installed; no analytics will be reported")
        return False

    conf = get_config(path=config_path)
    if conf is None:
        log.debug("Failed to load config")
        return False

    if not conf['anonymous_statistics']:
        return False
    
    if ANALYTICS_KEY is None:
        ANALYTICS_KEY = get_analytics_key( u )
        if ANALYTICS_KEY is None:
            return False

    # register the user 
    log.debug("Register user '%s'" % u)
    mp = mixpanel.Mixpanel(ANALYTICS_KEY)
    mp.people_set_once(u, {})
    return True


def analytics_user_update( payload, proxy=None ):
    """
    Update a user's info on the analytics service
    """
    global ANALYTICS_KEY

    try:
        import mixpanel 
    except:
        log.debug("mixpanel is not installed; no analytics will be reported")
        return False

    conf = get_config(config_path)
    if conf is None:
        log.debug("Failed to load config")
        return False

    if not conf['anonymous_statistics']:
        return False
    
    u = conf['uuid']
    if ANALYTICS_KEY is None:
        ANALYTICS_KEY = get_analytics_key( u )
        if ANALYTICS_KEY is None:
            return False

    # update the user 
    log.debug("Update user '%s'" % u)
    mp = mixpanel.Mixpanel(ANALYTICS_KEY)
    mp.people_append( u, payload )
    return True
