#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

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

import os
import sys
import traceback

import types
import re
import pybitcoin
import socket
from basicrpc import Proxy

""" this module contains the plugin to blockstack that makes the DHT useful as
    ancillary storage. This depends on the blockstore server package, since it
    includes the DHT node implementation.
"""

DHT_SERVER_PORT = 6265  # blockstored default to port 6264
MIRROR_TCP_PORT = 6266

DEFAULT_DHT_SERVERS = [('dht.blockstack.org', DHT_SERVER_PORT),
                       ('dht.onename.com', DHT_SERVER_PORT),
                       ('dht.halfmoonlabs.com', DHT_SERVER_PORT),
                       ('127.0.0.1', DHT_SERVER_PORT)]

DEFAULT_MIRROR = 'mirror.blockstack.org'

# 3 years
STORAGE_TTL = 3 * 60 * 60 * 24 * 365

NONE_VALUE = "(null)"


def hostname_to_ip(servers):
    """ Given (hostname, port) return (ip_address, port)
    """

    reply = []

    for server, port in servers:
        ip_address = socket.gethostbyname(server)
        reply.append((ip_address, port))

    return reply

# client to the DHT
dht_server = None


def dht_data_hash(data):
    """
    Calculate a key from the data.
    """
    return pybitcoin.hash.hex_hash160(data)


def dht_init(local_server=False):
    """
    Establish our connection to the DHT, and give
    it the requisite state it needs (i.e. an API
    proxy to blockstore)
    """

    global dht_server

    if local_server:
        dht_server = Proxy(DEFAULT_DHT_SERVERS[0], DHT_SERVER_PORT)
    else:
        dht_server = Proxy(DEFAULT_MIRROR, MIRROR_TCP_PORT)

    return True


def get_dht_client(local_server=False):
    """
    Get a new connection to DHT
    """
    if local_server:
        return Proxy(DEFAULT_DHT_SERVERS[0], DHT_SERVER_PORT)
    else:
        return Proxy(DEFAULT_MIRROR, MIRROR_TCP_PORT)


def dht_get_key(data_key):
    """
    Given a key (a hash of data), go fetch the data.
    """

    dht_client = get_dht_client()

    ret = dht_client.get(data_key)
    if ret is not None:
        if type(ret) == types.ListType:
            ret = ret[0]

        if type(ret) == types.DictType and ret.has_key("value"):
            ret = ret["value"]

    return ret


def dht_put_data(data_key, data_value):
    """
    Given a key and value, put it into the DHT.
    """
    dht_client = get_dht_client()
    return dht_client.set(data_key, data_value)


# ---------------------------------------------------------
# Begin plugin implementation
# ---------------------------------------------------------

def storage_init():
    """
    DHT implementation of the storage_init API call.
    Given the blockstore API proxy, set up any persistent state.
    Return True on success
    Return False on error
    """
    return dht_init()


def make_mutable_url(data_id):
    """
    DHT implementation of the make_mutable_url API call.
    Given the ID of the data, generate a URL that
    can be used to route reads and writes to the data.

    Return a string.
    """
    return "dht:" + pybitcoin.hash.hex_hash160(data_id)


def get_immutable_handler(key):
    """
    DHT implementation of the get_immutable_handler API call.
    Given the hash of the data, return the data.
    Return None if not found.
    """
    return dht_get_key(key)


def get_mutable_handler(data_id):
    """
    DHT implementation of the get_mutable_handler API call.
    Given a route URL to data, return the data itself.
    If we can't handle this URL, raise UnhandledURLException.
    Return the data if found.
    Return None if not.
    """
    return dht_get_key(dht_data_hash(data_id))


def put_immutable_handler(key, data, txid):
    """
    DHT implmentation of the put_immutable_handler API call.
    Given the hash of the data (key), the serialized data itself,
    and the transaction ID in the blockchain that contains the data's hash,
    put the data into the storage system.
    Return True on success; False on failure.
    """

    # TODO: the DHT in use at Onename should check to see that the user exists
    # and can write this data.

    return dht_put_data(key, data)


def put_mutable_handler(data_id, nonce, signature, data_json):
    """
    DHT implementation of the put_mutable_handler API call.
    Given the the unchanging ID for the data, a nonce representing
    this version of the data, the writer's signature over hash(data_id + data + nonce),
    and the serialized JSON representing all of the above plus the data, put
    the serialized JSON into storage.
    Return True on success; False on failure.
    """

    # TODO: the DHT in use at Onename should check to see that the user exists,
    # and can write this data.

    try:
        rc = dht_put_data(dht_data_hash(data_id), data_json)
    except Exception, e:
        traceback.print_exc()
        return False

    return True


def delete_immutable_handler(key, txid):
    """
    DHT implementation of the delete_immutable_handler API call.
    Given the hash of the data and transaction ID of the update
    that deleted the data, remove data from the DHT.
    Return True on success; False if not.
    """

    # TODO: the DHT in use at Onename should check to see that the user exists,
    # and can delete the data.

    return dht_put_data(key, None)


def delete_mutable_handler(data_id, signature):
    """
    DHT implementation of the delete_mutable_handler API call.
    Given the unchanging data ID for the data and the writer's
    signature over the hash of the data_id, remove data from the DHT.
    Return True on success; False if not.
    """

    # TODO: the DHT in use at Onename should check to see that the user exists,
    # and can delete the data.

    # put a null route to the data.
    try:
        rc = dht_put_data(dht_data_hash(data_id), None)
        if not rc:
            return False

    except Exception, e:
        traceback.print_exc()
        return False

    return True


if __name__ == "__main__":
    """
    Unit tests.
    """

    import pybitcoin
    import json

    # hack around absolute paths
    current_dir = os.path.abspath(os.path.dirname(__file__))
    sys.path.insert(0, current_dir)

    current_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    sys.path.insert(0, current_dir)

    from parsing import json_stable_serialize
    from storage import mutable_data_parse, mutable_data

    test_data = [
      ["my_first_datum",        "hello world",                              1, "unused", None],
      ["/my/second/datum",      "hello world 2",                            2, "unused", None],
      ["user_profile",          '{"name":{"formatted":"judecn"},"v":"2"}',  3, "unused", None],
      ["empty_string",          "",                                         4, "unused", None],
    ]

    def hash_data(d):
        return pybitcoin.hash.hex_hash160(d)

    rc = storage_init()
    if not rc:
        raise Exception("Failed to initialize")

    # put_immutable_handler
    print "put_immutable_handler"
    for i in xrange(0, len(test_data)):

        d_id, d, n, s, url = test_data[i]

        rc = put_immutable_handler(hash_data(d), d, "unused")
        if not rc:
            raise Exception("put_immutable_handler('%s') failed" % d)

    # put_mutable_handler
    print "put_mutable_handler"
    for i in xrange(0, len(test_data)):

        d_id, d, n, s, url = test_data[i]

        data_url = make_mutable_url(d_id)

        data = mutable_data(d_id, d, n, sig=s)

        data_json = json_stable_serialize(data)

        rc = put_mutable_handler(d_id, n, "unused", data_json)

        if not rc:
            raise Exception("put_mutable_handler('%s', '%s') failed" % (d_id, d))

        test_data[i][4] = data_url

    # get_immutable_handler
    print "get_immutable_handler"
    for i in xrange(0, len(test_data)):

        d_id, d, n, s, url = test_data[i]

        rd = get_immutable_handler(hash_data(d))

        if rd != d:
            raise Exception("get_mutable_handler('%s'): '%s' != '%s'" % (hash_data(d), d, rd))

    # get_mutable_handler
    print "get_mutable_handler"
    for i in xrange(0, len(test_data)):

        d_id, d, n, s, url = test_data[i]

        rd_json = get_mutable_handler(url)
        rd = mutable_data_parse(rd_json)

        if rd is None:
            raise Exception("Failed to parse mutable data '%s'" % rd_json)

        if rd['id'] != d_id:
            raise Exception("Data ID mismatch: '%s' != '%s'" % (rd['id'], d_id))

        if rd['nonce'] != n:
            raise Exception("Nonce mismatch: '%s' != '%s'" % (rd['nonce'], n))

        if rd['data'] != d:
            raise Exception("Data mismatch: '%s' != '%s'" % (rd['data'], d))

    # delete_immutable_handler
    print "delete_immutable_handler"
    for i in xrange(0, len(test_data)):

        d_id, d, n, s, url = test_data[i]

        rc = delete_immutable_handler(hash_data(d), "unused")

        if not rc:
            raise Exception("delete_immutable_handler('%s' (%s)) failed" % (hash_data(d), d))

    # delete_mutable_handler
    print "delete_mutable_handler"

    for i in xrange(0, len(test_data)):

        d_id, d, n, s, url = test_data[i]

        rc = delete_mutable_handler(d_id, "unused")

        if not rc:
            raise Exception("delete_mutable_handler('%s') failed" % d_id)
