#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore-client
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

    This file is part of Blockstore-client.

    Blockstore-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore-client.  If not, see <http://www.gnu.org/licenses/>.
"""

import logging
import os
from ConfigParser import SafeConfigParser
import traceback

BLOCKSTORED_PORT = 6264
BLOCKSTORED_SERVER = "127.0.0.1"
BLOCKSTORE_METADATA_DIR = os.path.expanduser("~/.blockstore-client/metadata")
BLOCKSTORE_DEFAULT_STORAGE_DRIVERS = "dht"

DEBUG = True
VERSION = '0.0.7'
MAX_RPC_LEN = 1024 * 1024 * 1024

CONFIG_PATH = os.path.expanduser("~/.blockstore-client/blockstore-client.ini")

if not globals().has_key('log'):
    log = logging.getLogger()
    log.setLevel(logging.DEBUG if DEBUG else logging.INFO)
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if DEBUG else logging.INFO)
    log_format = ('[%(levelname)s] [%(module)s:%(lineno)d] %(message)s' if DEBUG else '%(message)s')
    formatter = logging.Formatter(log_format)
    console.setFormatter(formatter)
    # log.addHandler(console)


def make_default_config( path=CONFIG_PATH ):
    """
    Make a new config file with sane defaults.
    Return True on success
    Return False on failure
    """
    global CONFIG_PATH, BLOCKSTORED_SERVER, BLOCKSTORED_PORT

    # try to create
    dirname = os.path.dirname( path )
    if not os.path.isdir( dirname ):
        try:
            os.makedirs( dirname )
        except:
            traceback.print_exc()
            log.error("Failed to make configuration directory '%s'." % path)
            return False

        parser = SafeConfigParser()
        parser.set('blockstore-client', 'server', BLOCKSTORED_SERVER)
        parser.set('blockstore-client', 'port', BLOCKSTORED_PORT)
        parser.set('blockstore-client', 'metadata', BLOCKSTORE_METADATA_DIR)
        parser.set('blockstred-client', 'storage_drivers', BLOCKSTORE_DEFAULT_STORAGE_DRIVERS )

        try:
            with open(path, "w") as f:
                parser.write(f)

        except:
            traceback.print_exc()
            log.error("Failed to write default configuration file to '%s'." % path)
            return False

    return True


def find_missing( conf ):
    """
    Find and return the list of missing configuration keys.
    """

    missing = []
    for k in ['server', 'port', 'metadata', 'storage_drivers']:
        if k not in conf.keys():
            missing.append( k )

    return missing


def get_config( path=CONFIG_PATH ):

    """
    Read our config file.
    Create an empty one with sane defaults if it does not exist.

    Return our configuration (as a dict) on success.
    Return None on error
    """

    global BLOCKSTORED_SERVER, BLOCKSTORED_PORT

    if not os.path.exists( path ):
        rc = make_default_config()
        if not rc:
            log.error("No configuration file loaded from '%s'.  Cannot proceed." % path)
            return None

    # defaults
    config = {
        "server": BLOCKSTORED_SERVER,
        "port": BLOCKSTORED_PORT,
        "storage_drivers": BLOCKSTORE_DEFAULT_STORAGE_DRIVERS,
        "metadata": BLOCKSTORE_METADATA_DIR
    }


    parser = SafeConfigParser()

    try:
        parser.read(path)
    except Exception, e:
        log.exception(e)
        return None

    if parser.has_section("blockstore-client"):

        # blockstored
        if parser.has_option("blockstore-client", "server"):
            config['server'] = parser.get("blockstore-client", "server")

        if parser.has_option("blockstore-client", "port"):
            try:
                config['port'] = int(parser.get("blockstore-client", "port"))
            except:
                log.error("Invalid 'port=' setting.  Please use an integer")

        if parser.has_option("blockstore-client", "storage"):
            config['storage_drivers'] = parser.get("blockstore-client", "storage")

        if parser.has_option("blockstore-client", "metadata"):
            config['metadata'] = parser.get("blockstore-client", "metadata")

    if not os.path.isdir(config['metadata']):
        if config['metadata'].startswith( os.path.expanduser("~/.blockstore-client") ):
            try:
                os.makedirs( config['metadata'] )
            except:
                log.error("Failed to make directory '%s'" % (config['metadata']))
                return None

        else:
            log.error("Directory '%s' does not exist" % (config['metadata']))
            return None

    return config
