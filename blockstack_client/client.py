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
import zone_file
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
    USER_ZONEFILE_TTL, CONFIG_PATH

log = get_logger()

import virtualchain

from wallet import * 

# ancillary storage providers
STORAGE_IMPL = None

def session(conf=None, server_host=BLOCKSTACKD_SERVER, server_port=BLOCKSTACKD_PORT,
            storage_drivers=BLOCKSTACK_DEFAULT_STORAGE_DRIVERS,
            metadata_dir=BLOCKSTACK_METADATA_DIR, spv_headers_path=SPV_HEADERS_PATH, set_global=False):

    """
    Create a blockstack session:
    * validate the configuration
    * load all storage drivers
    * initialize all storage drivers
    * load an API proxy to blockstack

    conf's fields override specific keyword arguments.

    Returns the API proxy object.
    """

    if conf is not None:

        missing = find_missing(conf)
        if len(missing) > 0:
            log.error("Missing blockstack configuration fields: %s" % (", ".join(missing)))
            sys.exit(1)

        server_host = conf['server']
        server_port = conf['port']
        storage_drivers = conf['storage_drivers']
        metadata_dir = conf['metadata']

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

        rc = register_storage(storage_impl)
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
    except ImportError, ie:
        raise Exception("Failed to import blockstack_storage_drivers.%s.  Please verify that it is installed and is accessible via your PYTHONPATH" % module_name)

    return storage_impl


def register_storage(storage_impl):
    """
    Register a storage implementation.
    """
    rc = storage.register_storage(storage_impl)
    if rc:
        rc = storage_impl.storage_init()

    return rc

