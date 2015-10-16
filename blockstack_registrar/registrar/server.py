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

from .network import get_blockchain_record, get_dht_profile
from .network import bs_client, dht_client

from .config import DEFAULT_NAMESPACE
from .config import IGNORE_USERNAMES
from .config import BTC_PRIV_KEY

from .utils import get_hash, check_banned_email, nmc_to_btc_address

from .db import state_diff, users, registrations, register_queue

from time import sleep


def register_user(user):

    fqu = user['username'] + "." + DEFAULT_NAMESPACE

    resp = bs_client.lookup(fqu)
    resp = resp[0]

    if resp is None:
        print "Not registered: %s" % fqu
    else:
        print "Already registered %s" % fqu
        return

    profile_hash = get_hash(user['profile'])
    btc_address = nmc_to_btc_address(user['namecoin_address'])

    print profile_hash
    print btc_address
    print fqu

    resp = bs_client.name_import(fqu, btc_address, profile_hash, BTC_PRIV_KEY)
    resp = resp[0]

    if 'transaction_hash' in resp:
        new_entry = {}
        new_entry["fqu"] = fqu
        new_entry['transaction_hash'] = resp['transaction_hash']
        new_entry['profile_hash'] = profile_hash
        new_entry['btc_address'] = btc_address
    else:
        print "Error registering: %s" % fqu
        print resp

    sleep(3)


def get_latest_diff():

    for user in state_diff.find():

        username = user['username']

        if username == 'fboya':
            print user


def register_new_users(spam_protection=False):

    for new_user in registrations.find():

        user_id = new_user['user_id']
        user = users.find_one({"_id": user_id})

        if user is None:
            continue

        if not user['username_activated']:
            continue

        # for spam protection
        if check_banned_email(user['email']):
            if spam_protection:
                #users.remove({"email": user['email']})
                print "Deleting spam %s, %s" % (user['email'], user['username'])
            else:
                print "Need to delete %s, %s" % (user['email'], user['username'])

        register_user(user)


if __name__ == '__main__':

    username = 'clone355'

    print bs_client.lookup('waydans.id')
    #register_new_users()
    #refresh_profile(username)
    #get_latest_diff()

    #c = Proxy('54.82.121.156', 6264)

    #print c.lookup(username + ".id")
    #print c.ping()

    #name_import(username, btc_address, profile_hash, privkey_str)