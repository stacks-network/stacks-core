# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

This file is part of Registrar.

    Registrar is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Registrar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Registrar. If not, see <http://www.gnu.org/licenses/>.
"""

import json
import logging
import pylibmc

from time import time
from pymongo import MongoClient
from basicrpc import Proxy

from registrar.config import AWSDB_URI
from registrar.config import MAIN_SERVER
from registrar.config import DEFAULT_HOST, MEMCACHED_PORT, MEMCACHED_TIMEOUT

from registrar.config import DEFAULT_NAMESPACE
from registrar.config import BLOCKSTORED_SERVER, BLOCKSTORED_PORT
from registrar.config import DHT_MIRROR, DHT_MIRROR_PORT

mc = pylibmc.Client([DEFAULT_HOST + ':' + MEMCACHED_PORT], binary=True)
log = logging.getLogger()

aws_db = MongoClient(AWSDB_URI)['registrar']
register_queue = aws_db.queue


def get_blockchain_record(username):

    client = Proxy(BLOCKSTORED_SERVER, BLOCKSTORED_PORT)
    resp = client.lookup(username + "." + DEFAULT_NAMESPACE)
    return resp[0]


def get_dht_profile(username):

    resp = get_blockchain_record(username)

    profile_hash = resp['value_hash']

    dht_mirror = Proxy(DHT_MIRROR, DHT_MIRROR_PORT)
    resp = dht_mirror.get(profile_hash)
    return resp[0]['value']


def register_name(username, profile, server=MAIN_SERVER):

    reply = {}

    # check if already in register queue (name_new)
    check_queue = register_queue.find_one({"username": username})

    if check_queue is not None:
        reply['message'] = "ERROR: " + "already in register queue: %s" % username
    else:

        # register functionality here

        # save this data to Mongodb...
        register_queue.insert(reply)

    log.debug(reply)
    log.debug('-' * 5)

    return reply


def update_name(username, profile, new_address=None):

    reply = {}

    cache_reply = mc.get("name_update_" + str(username))

    if cache_reply is None:

        # update name func here
        pass
    else:
        reply['message'] = "ERROR: " + "recently sent name_update: %s" % username

    log.debug(reply)
    log.debug('-' * 5)


def process_user(username, profile, server=MAIN_SERVER, new_address=None):

    master_key = 'u/' + username

    if namecoind.check_registration(key1):

        # if name is registered
        log.debug("name update: %s", username)
        #update_name()

    else:
        # if not registered
        log.debug("name new: %s", username)
        #register_name()
