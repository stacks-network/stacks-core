#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
# -----------------------

import json

from blockdata.register import process_user

from time import sleep

from coinrpc import namecoind

from commontools import get_json

from pymongo import MongoClient
from config import MONGODB_URI, OLD_DB

remote_db = MongoClient(MONGODB_URI).get_default_database()
users = remote_db.user

old_db = MongoClient(OLD_DB).get_default_database()
old_users = old_db.user

from blockdata.renew_names import get_expiring_names, get_expired_names
from blockdata.loadbalancer import load_balance    

# -----------------------------------
if __name__ == '__main__':

    expired_users = get_expired_names('u/')

    #ignore_users = ['frm','rfd','meng','bjorn']
    ignore_users = ['go']

    counter = 0

    tx_sent = MAX_PENDING_TX

    for i in expired_users:

        counter += 1

        if counter % 5 == 0:
            load_balance()

        if tx_sent >= MAX_PENDING_TX:
            tx_sent = 0
            print "check for pending tx"
            while pending_transactions():
                print "pending transactions, sleeping ..."
                sleep(60 * 5)

        username = i['name'].lstrip('u/')

        if username in ignore_users:
            continue

        new_user = users.find_one({'username':username})

        if new_user is not None:
            print username + " in new DB"

            profile = get_json(new_user['profile'])
            try:
                process_user(username, profile)
            except Exception as e:
                print e
            tx_sent += 1
            print '-' * 5
            continue

        old_user = old_users.find_one({'username': username})
        if  old_user is not None:
            print username + " in old DB"
            profile = get_json(old_user['profile'])

            try:
                process_user(username, profile)
                tx_sent += 1
            except Exception as e:
                print e

            continue

        print username + " not our user"
        print '-' * 5