#!/usr/bin/env python
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

import os
import json

from pymongo import MongoClient
from basicrpc import Proxy

from .nameops import get_blockchain_record
from .nameops import get_dht_profile

from .config import DEFAULT_NAMESPACE
from .config import BLOCKSTORED_SERVER, BLOCKSTORED_PORT
from .config import DHT_MIRROR, DHT_MIRROR_PORT
from .config import IGNORE_USERNAMES
from .config import MONGODB_URI, INDEXDB_URI
from .config import BTC_PRIV_KEY

from .utils import get_hash

from registrar.db import state_diff, users


def refresh_profile(username):

    update_user = state_diff.find_one({"username": username})

    print get_hash(update_user['profile'])

    user = users.find_one({"username": username})

    profile_hash = get_hash(user['profile'])
    btc_address = update_user['btc_address']
    fqu = username + ".id"

    c = Proxy('54.82.121.156', 6264)
    print c.name_import(fqu, btc_address, profile_hash, PRIVKEY)


def get_latest_diff():

    for user in state_diff.find():

        username = user['username']

        if username == 'fboya':
            print user


if __name__ == '__main__':

    username = 'clone355'

    refresh_profile(username)
    #get_latest_diff()

    c = Proxy('54.82.121.156', 6264)

    print c.lookup(username + ".id")
    #print c.ping()

    #name_import(username, btc_address, profile_hash, privkey_str)