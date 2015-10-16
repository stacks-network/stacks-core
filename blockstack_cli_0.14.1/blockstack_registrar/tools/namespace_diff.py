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

from pybitcoin import address_to_new_cryptocurrency

from registrar.network import get_blockchain_record
from registrar.network import get_dht_profile
from registrar.network import bs_client

from registrar.config import DEFAULT_NAMESPACE
from registrar.config import IGNORE_USERNAMES
from registrar.db import users, registrations, state_diff

from registrar.utils import get_hash


def insert_state_diff(username, profile, nmc_address):

    check_diff = state_diff.find_one({"username": username})

    if check_diff is None:
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

        resp = bs_client.lookup(username + "." + DEFAULT_NAMESPACE)
        resp = resp[0]

        if resp is None:
            insert_state_diff(username, user['profile'], str(user['namecoin_address']))
            counter += 1

    print counter


def cleanup_diff_db():

    for entry in state_diff.find():

        username = entry['username']
        profile = get_dht_profile(username)

        if profile is None:
            #print "Not registered: %s" % username
            continue

        dht_profile_hash = get_hash(profile)

        check_user = users.find_one({"username": username})
        try:
            db_profile_hash = get_hash(check_user['profile'])
        except:
            db_profile_hash = None
            print "ERROR: %s not in DB" % username

        if dht_profile_hash == db_profile_hash:
            print "registered: %s" % username
            state_diff.remove({"username": username})
        else:
            print "profile hash doesn't match: %s" % username


def process_name_updates(list_usernames):

    for username in list_usernames:
        if check_ownership(username):

            user = users.find_one({"username": username})
            insert_state_diff(username, user['profile'], str(user['namecoin_address']))


def get_latest_diff():

    for user in state_diff.find():

        username = user['username']

        if username == 'fred':
            print user


if __name__ == '__main__':

    print check_ownership('fboya')
    #cleanup_diff_db()
    #get_latest_diff()
    #populate_diff_db()
