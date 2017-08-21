#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2017 by Blockstack.org

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

import json
import os
import sys
import time
import jsontokens
import urllib
import virtualchain
import posixpath
import uuid
import errno
import hashlib
import jsontokens
import collections
import threading
import functools
import traceback
import sqlite3

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")
if not parent_dir in sys.path:
    sys.path.insert(0, parent_dir)

from keylib import *

import virtualchain
from virtualchain.lib.ecdsalib import *

from logger import get_logger
from proxy import get_default_proxy
from config import get_config, get_local_device_id
from constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, DEFAULT_DEVICE_ID, CONFIG_PATH
from schemas import *
from storage import sign_data_payload, make_data_tombstone, make_fq_data_id, sign_data_tombstone, parse_data_tombstone, verify_data_tombstone, parse_fq_data_id, hash_data_payload, sign_data_payload, serialize_mutable_data

from write_log import write_log_replicate_thread, write_log_notify, write_log_init

log = get_logger('gaia-control')

GAIA_RUNNING = False
WRITE_LOG_THREAD = None

class WriteLogThread(threading.Thread):
    def __init__(self):
        super(WriteLogThread, self).__init__()

    def run(self):
        write_log_replicate_thread()

    def signal_stop(self):
        write_log_notify()


def is_gaia_running():
    return GAIA_RUNNING


def gaia_start(config_path=CONFIG_PATH):
    """
    Start up Gaia threads and state
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    global WRITE_LOG_THREAD, GAIA_RUNNING

    try:
        con = write_log_init(config_path=config_path)
        con.close()
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        return {'error': 'Failed to initialize write log'}

    GAIA_RUNNING = True
    WRITE_LOG_THREAD = WriteLogThread()
    WRITE_LOG_THREAD.start()

    return {'status': True}
    

def gaia_stop():
    """
    Stop Gaia threads
    """
    global WRITE_LOG_THREAD, GAIA_RUNNING

    GAIA_RUNNING = False
    WRITE_LOG_THREAD.signal_stop()


