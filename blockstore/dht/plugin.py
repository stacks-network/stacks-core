#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstore

    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore. If not, see <http://www.gnu.org/licenses/>.
"""

# this module contains a plugin that makes the DHT useful as ancillary storage
# TODO: find a way to initialize the DHT and local plugin state

import os
import sys
import traceback

# current_dir =  os.path.abspath(os.path.dirname(__file__))
# sys.path.insert(0, current_dir)

from kademlia.network import Server

from twisted.python import log
from twisted.internet.error import ConnectionRefusedError
from twisted.internet import reactor
from txjsonrpc.netstring.jsonrpc import Proxy

from blockstore.storage import mutable_data_route, mutable_data_route_parse
from blcokstore.storage import mutable_data_parse, UnhandledURLException

from txjsonrpc.netstring import jsonrpc
from twisted.application import service, internet

from kademlia.network import Server

from blockstore.parsing import json_stable_serialize

import types
import re
import pybitcoin


DHT_SERVER_PORT = 6265  # blockstored default to port 6264

DEFAULT_DHT_SERVERS = [('dht.openname.org', DHT_SERVER_PORT),
                       ('dht.onename.com', DHT_SERVER_PORT),
                       ('dht.halfmoonlabs.com', DHT_SERVER_PORT),
                       ('127.0.0.1', DHT_SERVER_PORT)]

# 3 years
STORAGE_TTL = 3 * 60 * 60 * 24 * 365

NONE_VALUE = "(null)"


# client to the DHT
dht_server = None
dht_blockchain_index = None


def dht_data_hash(data):
    """
    Calculate a key from the data.
    """

    return pybitcoin.hash.hex_hash160(data)


def dht_url(data_hash):
    """
    Generate a route URL for the DHT, given the data's key.
    """
    return "dht:" + str(data_hash)


def dht_url_parse(data_url):
    """
    Givne a DHT url, get the hash.
    Raise an exception if it can't be parsed.
    """
    # sanity check...
    if type(data_url) not in [types.StringType, types.UnicodeType]:
        raise Exception("Not a valid URL")

    if not data_url.startswith("dht:"):
        raise Exception("Not a valid URL: invalid scheme in '%s'" % data_url)

    data_hash = data_url[4:]
    if len(data_hash) == 0:
        raise Exception("Not a valid URL: empty hash in '%s'" % data_url)

    if re.match(r"^[a-fA-F0-9]+$", data_hash) is None:
        raise Exception("Not a valid URL: invalid hash in '%s'" % data_url)

    return data_hash


def dht_init(blockchain_index):
    """
    Establish our connection to the DHT, and give
    it the requisite state it needs (i.e. the index
    over the blockchain).
    """

    global dht_server
    global dht_blockchain_index

    dht_blockchain_index = blockchain_index

    dht_server = Server(storage=BlockStorage())
    dht_server.listen(DHT_SERVER_PORT)
    bootstrap_servers = hostname_to_ip(DEFAULT_DHT_SERVERS)
    dht_server.bootstrap(bootstrap_servers)


def dht_get_key(data_key):
    """
    Given a key (a hash of data), go fetch the data.
    """

    global dht_server
    if dht_server is None:
        raise Exception("DHT is not initialized")

    value = dht_server.get(data_key)

    if value == NONE_VALUE:
        return None
    else:
        return value


def dht_put_data(data_key, data_value):
    """
    Given a key and value, put it into the DHT.
    """
    global dht_server
    if dht_server is None:
        raise Exceptoin("DHT is not initialized")

    if data_value is None:
        data_value = NONE_VALUE

    return dht_server.set(data_key, data_value)


def dht_get_route(data_id):
    """
    Given a data ID, go fetch the route to the data.
    """

    global dht_server
    if dht_server is None:
        raise Exception("DHT is not initialized")

    data_id_hash = dht_data_hash(data_id)
    return dht_get_key(data_id_hash)


def dht_put_route(name, data_id, data, nonce, signature):
    """
    Given the name, data ID, data, data nonce, and signature,
    store a route.
    """

    # in the DHT, there is no URL. Just a hash.
    data_id_hash = dht_data_hash(data_id)
    data_url = dht_url(data_id_hash)

    route = mutable_data_route(data_id, [data_url])
    route_json = json_stable_serialize(route)
    return dht_put_data(data_id_hash, route_json)


# ---------------------------------------------------------
# Begin plugin implementation
# ---------------------------------------------------------

def get_immutable_handler(key):
    """
    DHT implementation of the get_immutable_handler API call.
    Given the hash of the data, return the data.
    Return None if not found.
    """
    return dht_get_key(key)


def get_route_handler(data_id):
    """
    DHT implementation of the get_route_handler API call.
    Given the unchanging ID of the data, return the route to the data.
    Return None if not found.
    """
    return dht_get_route(data_id)


def get_mutable_handler(data_url):
    """
    DHT implementation of the get_mutable_handler API call.
    Given a route URL to data, return the data itself.
    If we can't handle this URL, raise UnhandledURLException.
    Return the data if found.
    Return None if not.
    """
    try:
        data_key = dht_url_parse(data_url)
    except:
        raise UnhandledURLException(data_url)

    return dht_get_key(data_key)


def put_immutable_handler(name, key, data, signature):
    """
    DHT implmentation of the put_immutable_handler API call.
    Given the name of the user, the key to the data, the data itself,
    and the writer's signature over the data, put the data into the
    storage system.
    Return True on success; False on failure.
    """

    # TODO: the DHT in use at OneName should check to see that the user exists,
    # and can write this data.

    return dht_put_data(key, data)


def put_mutable_handler(name, data_id, data, nonce, signature):
    """
    DHT implementation of the put_mutable_handler API call.
    Given the name of the user, the unchanging ID for the data, the
    data itself, a nonce representing this version of the data, and
    the writer's signature over (data_id + data + nonce), put
    the data into storage.
    Return True on success; False on failure.
    """

    # TODO: the DHT in use at OneName should check to see that the user exists,
    # and can write this data.

    # put a route, and then the data

    try:
        rc = dht_put_route(name, data_id, data, nonce, signature)

        if not rc:
            return False

    except Exception, e:
        traceback.print_exc()
        return False

    try:
        rc = dht_put_data(dht_data_hash(data), data)
    except Exception, e:
        traceback.print_exc()
        return False

    return True


def delete_immutable_handler(name, key, signature):
    """
    DHT implementation of the delete_immutable_handler API call.
    Given the name of the user, the key for the data, and the
    writer's signature over the key, remove data from the
    DHT.
    Return True on success; False if not.
    """

    # TODO: the DHT in use at OneName should check to see that the user exists,
    # and can delete the data.

    return dht_put_data(key, None)


def delete_mutable_handler(name, data_id, signature):
    """
    DHT implementation of the delete_mutable_handler API call.
    Given the name of the user, the unchanging data ID for the data,
    and the writer's signature over the data_id, remove data from
    the DHT.
    Return True on success; False if not.
    """

    # TODO: the DHT in use at OneName should check to see that the user exists,
    # and can delete the data.

    # put a null route to the data.

    try:
        rc = dht_put_route(name, data_id, None, None, signature)

        if not rc:
            return False

    except Exception, e:
        traceback.print_exc()
        return False

    return True
