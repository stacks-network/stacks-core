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

from basicrpc import Proxy

from registrar.config import BLOCKSTORED_IP, BLOCKSTORED_PORT
from registrar.config import DHT_MIRROR_IP, DHT_MIRROR_PORT
from registrar.config import DEFAULT_NAMESPACE

bs_client = Proxy(BLOCKSTORED_IP, BLOCKSTORED_PORT)
dht_client = Proxy(DHT_MIRROR_IP, DHT_MIRROR_PORT)


def get_blockchain_record(username):

    resp = bs_client.lookup(username + "." + DEFAULT_NAMESPACE)
    return resp[0]


def get_dht_profile(username):

    resp = get_blockchain_record(username)

    if resp is None:
        return None

    profile_hash = resp['value_hash']

    profile = None

    try:
        resp = dht_client.get(profile_hash)
        profile = resp[0]['value']
    except Exception as e:
        print "Error: %s" % username
        print e

    return profile
