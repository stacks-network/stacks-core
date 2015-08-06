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

# 520 is the real limit
# hardcoded here instead of some config file
VALUE_MAX_LIMIT = 512

import json

from commontools import utf8len, log

# -----------------------------------
from pymongo import MongoClient
from config import AWSDB_URI
aws_db = MongoClient(AWSDB_URI)['blockdata']
register_queue = aws_db.queue

from pybitcoin.rpc.namecoind_client import NamecoindClient
from pybitcoin.rpc.namecoind_cluster import get_server

from .config import MAIN_SERVER, LOAD_SERVERS
from .config import NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD
from .config import NAMECOIND_WALLET_PASSPHRASE, NAMECOIND_SERVER
from .config import NAMECOIND_USE_HTTPS
from .config import DEFAULT_HOST, MEMCACHED_PORT, MEMCACHED_TIMEOUT

from coinrpc import namecoind

import pylibmc
from time import time
mc = pylibmc.Client([DEFAULT_HOST + ':' + MEMCACHED_PORT], binary=True)


def register_name(key, value, server=NAMECOIND_SERVER, username=None):

    reply = {}

    # check if already in register queue (name_new)
    check_queue = register_queue.find_one({"key": key})

    if check_queue is not None:
        reply['message'] = "ERROR: " + "already in register queue: " + str(key)
    else:

        namecoind = NamecoindClient(server, NAMECOIND_PORT, NAMECOIND_USER,
                                    NAMECOIND_PASSWD, NAMECOIND_USE_HTTPS,
                                    NAMECOIND_WALLET_PASSPHRASE)

        try:
            info = namecoind.name_new(key, json.dumps(value))

            reply['txid'] = info[0]
            reply['rand'] = info[1]

        except:
            log.debug(info)
            reply['message'] = info
            return reply

        reply['key'] = key
        reply['value'] = json.dumps(value)

        reply['tx_sent'] = False
        reply['server'] = server

        if username is not None:
            reply['username'] = username

        # save this data to Mongodb...
        register_queue.insert(reply)

        # reply[_id] is causing a json encode error
        del reply['_id']

    log.debug(reply)
    log.debug('-' * 5)

    return reply


def get_namecoind(key):

    server = NAMECOIND_SERVER

    serverinfo = get_server(key, MAIN_SERVER, LOAD_SERVERS)

    if 'registered' in serverinfo and serverinfo['registered']:
        server = serverinfo['server']

    log.debug(server)
    log.debug(key)

    namecoind = NamecoindClient(server, NAMECOIND_PORT, NAMECOIND_USER,
                                NAMECOIND_PASSWD, NAMECOIND_USE_HTTPS,
                                NAMECOIND_WALLET_PASSPHRASE)

    return namecoind


def update_name(key, value):

    reply = {}

    cache_reply = mc.get("name_update_" + str(key))

    if cache_reply is None:

        namecoind = get_namecoind(key)

        info = namecoind.name_update(key, json.dumps(value))

        if 'code' in info:
            reply = info
        else:
            reply['tx'] = info
            mc.set("name_update_" + str(key), "in_memory", int(time() + MEMCACHED_TIMEOUT))

    else:
        reply['message'] = "ERROR: " + "recently sent name_update: " + str(key)

    log.debug(reply)
    log.debug('-' * 5)


def _max_size(username):
    return VALUE_MAX_LIMIT - len('next: i-' + username + '000000')


def _get_key(key_counter, username):
    return 'i/' + username.lower() + '-' + str(key_counter)


def _splitter(remaining, username):

    split = {}
    maxsize = _max_size(username)

    if utf8len(json.dumps(remaining)) < maxsize:
        return remaining, None
    else:
        for key in remaining.keys():

            if utf8len(json.dumps(remaining[key])) > maxsize:
                # include the size of key in (key, value) maxsize as well
                temp = {}
                temp[key] = 'extra-space-here'

                maxsize_value = maxsize - utf8len(json.dumps(temp))
                remaining[key] = remaining[key][:maxsize_value]

            # some foreign languages have a bug in size reduction
            # check again, and display error
            if utf8len(json.dumps(remaining[key])) > maxsize:
                remaining[key] = 'Error: value too large'

            split[key] = remaining[key]

            if utf8len(json.dumps(split)) > maxsize:
                del split[key]
            else:
                del remaining[key]

        return split, remaining


def slice_profile(username, profile):
    '''if a next key is already registered, returns next one
    '''

    keys = []
    values = []

    key = 'u/' + username.lower()
    keys.append(key)

    split, remaining = _splitter(profile, username)
    values.append(split)

    key_counter = 000000
    counter = 0

    while(remaining is not None):

        key_counter += 1
        key = _get_key(key_counter, username)

        while(1):

            if namecoind.check_registration(key):
                key_counter += 1
                key = _get_key(key_counter, username)
            else:
                break

        split, remaining = _splitter(remaining, username)

        keys.append(key)
        values.append(split)

        values[counter]['next'] = key
        counter += 1

    return keys, values


def slice_profile_update(username, profile):
    '''returns keys without checking if they're already registered
    '''

    keys = []
    values = []

    key = 'u/' + username.lower()
    keys.append(key)

    split, remaining = _splitter(profile, username)
    values.append(split)

    key_counter = 0
    counter = 0

    while(remaining is not None):

        key_counter += 1
        key = _get_key(key_counter, username)

        split, remaining = _splitter(remaining, username)
        keys.append(key)
        values.append(split)

        values[counter]['next'] = key
        counter += 1

    return keys, values


def process_user(username, profile, server=NAMECOIND_SERVER):

    master_key = 'u/' + username

    if namecoind.check_registration(master_key):
        keys, values = slice_profile_update(username, profile)
    else:
        keys, values = slice_profile(username, profile)

    index = 0
    key1 = keys[index]
    value1 = values[index]

    if namecoind.check_registration(key1):

        # if name is registered
        log.debug("name update: %s", key1)
        log.debug("size: %s", utf8len(json.dumps(value1)))
        update_name(key1, value1)

    else:
        # if not registered
        log.debug("name new: %s", key1)
        log.debug("size: %s", utf8len(json.dumps(value1)))
        register_name(key1, value1, server, username)

    process_additional_keys(keys, values, server, username)


def process_additional_keys(keys, values, server, username):

    # register/update remaining keys
    size = len(keys)
    index = 1
    while index < size:
        next_key = keys[index]
        next_value = values[index]

        log.debug(utf8len(json.dumps(next_value)))

        if namecoind.check_registration(next_key):
            log.debug("name update: " + next_key)
            update_name(next_key, next_value)
        else:
            log.debug("name new: " + next_key)
            register_name(next_key, next_value, server, username)

        index += 1
