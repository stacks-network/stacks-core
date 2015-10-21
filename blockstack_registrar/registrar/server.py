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
import sys
import json

from pymongo import MongoClient
from basicrpc import Proxy

from .nameops import get_blockchain_record, get_dht_profile
from .nameops import usernameRegistered, check_ownership
from .nameops import write_dht_profile

from .config import DEFAULT_NAMESPACE
from .config import IGNORE_USERNAMES
from .config import BTC_PRIV_KEY
from .config import DHT_IGNORE

from .utils import get_hash, check_banned_email, nmc_to_btc_address

from .network import get_bs_client, get_dht_client
from .db import state_diff, users, registrations, updates
from .db import get_db_user_from_id
from .db import register_queue, update_queue

from time import sleep


def register_user(user, fqu):

    bs_client = get_bs_client()

    check_queue = register_queue.find_one({"fqu": fqu})

    if check_queue is not None:
        print "Already in queue"
        return

    if usernameRegistered(fqu):
        print "Already registered %s" % fqu
        return

    profile_hash = get_hash(user['profile'])
    btc_address = nmc_to_btc_address(user['namecoin_address'])

    print "Registering (%s, %s, %s)" % (fqu, btc_address, profile_hash)

    try:
        resp = bs_client.name_import(fqu, btc_address, profile_hash, BTC_PRIV_KEY)
        resp = resp[0]
    except Exception as e:
        print e
        return

    if 'transaction_hash' in resp:
        new_entry = {}
        new_entry["fqu"] = fqu
        new_entry['transaction_hash'] = resp['transaction_hash']
        new_entry['profile_hash'] = profile_hash
        new_entry['profile'] = user['profile']
        new_entry['btc_address'] = btc_address
        register_queue.save(new_entry)
    else:
        print "Error registering: %s" % fqu
        print resp

    sleep(3)


def update_user(user, fqu):

    bs_client = get_bs_client()

    check_queue = update_queue.find_one({"fqu": fqu})

    if check_queue is not None:
        print "Already in queue: %s" % fqu
        return

    profile_hash = get_hash(user['profile'])
    btc_address = nmc_to_btc_address(user['namecoin_address'])

    if not check_ownership(fqu, btc_address):
        print "Don't own this name"
        return

    print "Updating (%s, %s, %s)" % (fqu, btc_address, profile_hash)

    try:
        resp = bs_client.name_import(fqu, btc_address, profile_hash, BTC_PRIV_KEY)
        resp = resp[0]
    except Exception as e:
        print e
        return

    if 'transaction_hash' in resp:
        new_entry = {}
        new_entry["fqu"] = fqu
        new_entry['transaction_hash'] = resp['transaction_hash']
        new_entry['profile_hash'] = profile_hash
        new_entry['profile'] = user['profile']
        new_entry['btc_address'] = btc_address
        update_queue.save(new_entry)
    else:
        print "Error updating: %s" % fqu
        print resp

    sleep(3)


def cleanup_queue(queue):

    for entry in queue.find():

        if entry['fqu'] in DHT_IGNORE:
            continue

        if usernameRegistered(entry['fqu']):
            print "registered on blockchain: %s" % entry['fqu']

            record = get_blockchain_record(entry['fqu'])

            if record['value_hash'] == entry['profile_hash']:

                profile = get_dht_profile(entry['fqu'])

                if profile is None:
                    print "data not in DHT"
                    write_dht_profile(entry['profile'])

                else:
                    if get_hash(profile) == entry['profile_hash']:
                        print "data in DHT"
                        print "removing from queue: %s" % entry['fqu']
                        queue.remove({"fqu": entry['fqu']})

            else:

                print "blockchain hash is different than write attempt, try again"
                #queue.remove({"fqu": entry['fqu']})


def get_latest_diff():

    for user in state_diff.find():

        username = user['username']

        if username == 'fboya':
            print user


def register_new_users(spam_protection=False):

    for new_user in registrations.find():

        user = get_db_user_from_id(new_user)

        if user is None:
            continue

        # for spam protection
        if check_banned_email(user['email']):
            if spam_protection:
                #users.remove({"email": user['email']})
                print "Deleting spam %s, %s" % (user['email'], user['username'])
                continue
            else:
                print "Need to delete %s, %s" % (user['email'], user['username'])
                continue

        bs_client = get_bs_client()

        fqu = user['username'] + "." + DEFAULT_NAMESPACE

        if usernameRegistered(fqu):
            print "Already registered %s" % fqu

            resp = get_blockchain_record(fqu)

            if resp['value_hash'] == get_hash(user['profile']):
                registrations.remove({"user_id": new_user['user_id']})
                print "removing registration"
            else:
                print "Latest profile not on blockchain, need to update"
                update_user(user, fqu)

        else:

            print "Not registered: %s" % fqu
            register_user(user, fqu)


def update_users_bulk():

    for new_user in updates.find():

        user = get_db_user_from_id(new_user)

        if user is None:
            continue

        bs_client = get_bs_client()

        fqu = user['username'] + "." + DEFAULT_NAMESPACE

        if usernameRegistered(fqu):

            resp = get_blockchain_record(fqu)

            if 'error' in resp:
                print fqu, resp
                continue

            if resp['value_hash'] == get_hash(user['profile']):
                print "profile match, removing: %s" % fqu
                updates.remove({"user_id": new_user['user_id']})
            else:
                btc_address = nmc_to_btc_address(user['namecoin_address'])
                if check_ownership(fqu, btc_address):
                    update_user(user, fqu)
                else:
                    print "cannot update (wrong owner): %s " % fqu
                    updates.remove({"user_id": new_user['user_id']})
        else:

            print "Not registered: %s" % fqu


if __name__ == '__main__':

    try:
        command = sys.argv[1]
    except:
        print "Options are register, update, clean"
        exit(0)

    if command == "register":
        register_new_users()
    elif command == "update":
        update_users_bulk()
    elif command == "clean":
        cleanup_queue(update_queue)
        cleanup_queue(register_queue)
