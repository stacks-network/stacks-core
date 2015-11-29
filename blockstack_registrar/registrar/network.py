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
from basicrpc import Proxy
from blockstore_client import client as bs_client

from .config import BLOCKSTORED_IP, BLOCKSTORED_PORT
from .config import DHT_MIRROR_IP, DHT_MIRROR_PORT
from .utils import get_hash

# direct client, using Proxy
#bs_client = Proxy(BLOCKSTORED_IP, BLOCKSTORED_PORT)
dht_client = Proxy(DHT_MIRROR_IP, DHT_MIRROR_PORT)

# start session using blockstore_client
bs_client.session(server_host=BLOCKSTORED_IP, server_port=BLOCKSTORED_PORT)


def get_bs_client():

    # return Proxy(BLOCKSTORED_IP, BLOCKSTORED_PORT)
    return bs_client


def get_dht_client():

    return Proxy(DHT_MIRROR_IP, DHT_MIRROR_PORT)


def get_blockchain_record(fqu):

    data = {}

    try:
        resp = bs_client.get_name_blockchain_record(fqu)
    except Exception as e:
        data['error'] = e
        return data

    return resp


def get_dht_profile(fqu):

    resp = get_blockchain_record(fqu)

    if resp is None:
        return None

    profile_hash = resp['value_hash']

    profile = None

    dht_client = get_dht_client()

    try:
        resp = dht_client.get(profile_hash)
        profile = resp[0]['value']
    except Exception as e:
        print "Error DHT get: (%s, %s)" % (fqu, profile_hash)

    return profile


def write_dht_profile(profile):

    resp = None
    dht_client = get_dht_client()

    key = get_hash(profile)
    value = json.dumps(profile, sort_keys=True)

    print "DHT write (%s, %s)" % (key, value)

    try:
        resp = dht_client.set(key, value)
        pretty_print(resp)
    except Exception as e:
        print e

    return resp
