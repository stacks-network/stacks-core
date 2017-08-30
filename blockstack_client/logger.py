#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function

"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

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
    along with Blockstack-client.  If not, see <http://www.gnu.org/licenses/>.
"""
import os
import itertools
import logging
import traceback
import uuid
import urllib2
import copy
import time
import shutil
import requests

from ConfigParser import SafeConfigParser

import virtualchain
from .constants import (
    DEBUG,
    LOG_NETWORK_PORT,
    get_secret,
    CONFIG_PATH,
    BLOCKSTACK_TEST)


class NetworkLogFormatter( logging.Formatter ):
    """
    Log formatter for network endpoints, such as Blockstack Portal
    """
    level_names = {
        logging.DEBUG: 'DEBUG',
        logging.INFO: 'INFO',
        logging.WARN: 'WARN',
        logging.ERROR: 'ERROR',
        logging.FATAL: 'FATAL'
    }

    def format(self, record):
        msg = record.msg
        if msg is None:
            msg = ' '

        data = {
            'time': int(time.time()),
            'level': NetworkLogFormatter.level_names.get(record.levelno, 'TRACE'),
            'category': os.path.basename(record.pathname),
            'message': record.msg,
        }
        return data



class NetworkLogHandler( logging.Handler ):
    """
    Log handler for network endpoints, such as Blockstack Portal
    """
    def config(self, url, authorization):
        self.authorization = authorization
        self.url = url

    def emit(self, record):
        log_entry = self.format(record)
        headers = {
            'Authorization': self.authorization
        }

        try:
            requests.post(self.url, json=log_entry, headers=headers, timeout=1.0)
        except Exception as e:
            pass


def get_network_log_handler(api_password=None, name=None, scheme="http", host="localhost", port=LOG_NETWORK_PORT):
    """
    Get a log handler to sending messages over the network.
    """

    level = logging.CRITICAL
    if DEBUG:
        logging.disable(logging.NOTSET)
        level = logging.DEBUG

    if name is None:
        name = "<unknown>"

    if api_password is None:
        api_password = get_secret("BLOCKSTACK_API_PASSWORD")
    
    if api_password is None:

        # extract...
        p = SafeConfigParser()
        try:
            p.read(CONFIG_PATH)
        except:
            return None

        try:
            if p.has_section('blockstack-client'):
                if p.get('blockstack-client', 'api_password') is not None:
                    api_password = p.get('blockstack_client', 'api_password')
        except:
            return None

    if not api_password:
        return None

    url = "{}://{}:{}".format(scheme, host, port)
    authorization = 'bearer {}'.format(api_password)
    network = NetworkLogHandler()
    network.config(url, authorization)
    network.setLevel( level )
    formatter = NetworkLogFormatter()
    network.setFormatter(formatter)
    network.propagate = False

    return network


def get_logger(name="blockstack-client", debug=DEBUG):
    logger = virtualchain.get_logger(name)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    if not BLOCKSTACK_TEST:
        network_logger = get_network_log_handler(name=name)
        if network_logger:
            logger.addHandler(network_logger)

    return logger

