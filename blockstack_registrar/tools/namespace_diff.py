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
from pybitcoin import hex_hash160, address_to_new_cryptocurrency

try:
    MONGODB_URI = os.environ['MONGODB_URI']
except:
    MONGODB_URI = None

try:
    INDEXDB_URI = os.environ['INDEXDB_URI']
except:
    INDEXDB_URI = None

from registrar.nameops import get_dht_profile

from registrar.config import DEFAULT_NAMESPACE
from registrar.config import BLOCKSTORED_SERVER, BLOCKSTORED_PORT
from registrar.config import DHT_MIRROR, DHT_MIRROR_PORT
from registrar.config import IGNORE_USERNAMES

remote_db = MongoClient(MONGODB_URI).get_default_database()
users = remote_db.user
registrations = remote_db.user_registration


c = MongoClient(INDEXDB_URI)
state_diff = c['namespace'].state_diff


def get_hash(profile):

    if type(profile) is not dict:
        try:
            # print "WARNING: converting to json"
            profile = json.loads(profile)
        except:
            print "WARNING: not valid json"

    return hex_hash160(json.dumps(profile, sort_keys=True))


def insert_state_diff(username, profile, nmc_address):

    check_btc_diff = state_diff.find_one({"username": username})

    if check_btc_diff is None:
        new_entry = {}
        new_entry['username'] = username
        new_entry['btc_address'] = address_to_new_cryptocurrency(nmc_address, 0)
        new_entry['profile'] = profile
        new_entry['profile_hash'] = get_hash(profile)

        print "inserting in diff: %s" % username
        state_diff.insert(new_entry)
    else:
        print "already in diff: %s" % username


def populate_diff_db():

    counter = 0
    for new_user in registrations.find():

        user_id = new_user['user_id']
        user = users.find_one({"_id": user_id})

        if user is None:
            continue

        if not user['username_activated']:
            continue

        username = user['username']

        if username in IGNORE_USERNAMES:
            continue

        blockstore_client = Proxy(BLOCKSTORED_SERVER, BLOCKSTORED_PORT)
        blockstore_resp = blockstore_client.lookup(username + "." + DEFAULT_NAMESPACE)
        blockstore_resp = blockstore_resp[0]

        if blockstore_resp is None:
            print username
            insert_state_diff(username, user['profile'], str(user['namecoin_address']))
            counter += 1

    print counter


def cleanup_diff_db():

    for entry in state_diff.find():

        username = entry['username']
        profile = get_dht_profile(username)
        dht_profile_hash = get_hash(profile)

        check_user = users.find_one({"username": username})
        try:
            db_profile_hash = get_hash(check_user['profile'])
        except:
            db_profile_hash = None
            print "ERROR: %s" % username

        if dht_profile_hash == db_profile_hash:
            print "registered: %s" % username
            state_diff.remove({"username": username})


def get_latest_diff():

    for user in state_diff.find():
        print user['username']

if __name__ == '__main__':

    cleanup_diff_db()
    #get_latest_diff()
    #populate_diff_db()
