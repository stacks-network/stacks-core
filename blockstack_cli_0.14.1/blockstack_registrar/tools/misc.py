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
import requests

from registrar.config import MONGODB_URI, OLD_DB, AWSDB_URI

from registrar.nameops import process_user, update_name, register_name

from pymongo import MongoClient
from bson.objectid import ObjectId

from .bip38 import bip38_decrypt

import datetime
import hashlib
from time import sleep

# from tools.sweep_btc import sweep_btc

FRONTEND_SECRET = os.environ['FRONTEND_SECRET']


from pybitcoin import BitcoinKeypair, NamecoinKeypair

from pybitcoin.rpc import namecoind
from pybitcoin.rpc.namecoind_client import NamecoindClient
from registrar.config import NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD
from registrar.config import NAMECOIND_USE_HTTPS, NAMECOIND_SERVER
from registrar.config import NAMECOIND_WALLET_PASSPHRASE
from registrar.config import NAMECOIND_UPDATE_SERVER
from commontools import get_json, log

from registrar.config import SERVER_FLEET
from pybitcoin.rpc.namecoind_cluster import pending_transactions

remote_client = MongoClient(MONGODB_URI)

remote_db = remote_client.get_default_database()
users = remote_db.user
registrations = remote_db.user_registration
updates = remote_db.profile_update
transfer = remote_db.name_transfer

aws_db = MongoClient(AWSDB_URI)['blockdata']
skip_users = aws_db.skip_users
pending_users = aws_db.pending_users

old_client = MongoClient(OLD_DB)
old_db = old_client.get_default_database()
old_users = old_db.user

reservation = remote_db.username_reservation


def print_user(user):
    for key, value in user.iteritems():
        print key + " : " + str(value)


def check_pending_tx():

    counter_total = 0

    for server in SERVER_FLEET:
        print server
        try:
            count = int(pending_transactions(server))
            print count
            counter_total += count
        except Exception as e:
            print e

    return counter_total


def cleanup_user(username):

    user = users.find_one({"username": username})

    user_id = user['_id']

    cleanup_user = updates.find_one({"user_id": user_id})

    if cleanup_user is not None:
        print "cleaning update: " + user["username"]
        updates.remove(cleanup_user)

    cleanup_user = transfer.find_one({"user_id": user_id})

    if cleanup_user is not None:
        print "cleaning transfer: " + user["username"]
        transfer.remove(cleanup_user)

    cleanup_user = registrations.find_one({"user_id": user_id})

    if cleanup_user is not None:
        print "cleaning register: " + user["username"]
        registrations.remove(cleanup_user)


def process_manually_alias(username, alias):

    user = users.find_one({'username': username})
    process_user(alias, user['profile'])


def process_manually(username):

    user = users.find_one({'username': username})
    process_user(user['username'], user['profile'])
    # cleanup_user(username)


def process_manually_old(username):

    user = old_users.find_one({'username': username})
    process_user(user['username'], json.loads(user['profile']))


def make_alias(alias, target):

    value = {}
    value['next'] = 'u/' + target

    process_user(alias, value)


def find_via_email(email):

    user = users.find_one({'email': email})
    print_user(user)


def find_via_username(username):

    user = users.find_one({'username': username})
    print_user(user)


def find_old_user(username):

    user = old_users.find_one({'username': username})
    print_user(user)


def import_user(username):

    for transfer_user in transfer.find():

        user_id = transfer_user['user_id']
        new_user = users.find_one({"_id": user_id})

        if new_user is None:
            continue

        if new_user['username'] == username:
            old_user = old_users.find_one({'username': new_user['username']})
            print username
        else:
            continue

        old_nmc_address = old_user['namecoin_address']

        wif_pk = bip38_decrypt(str(transfer_user['encrypted_private_key']), FRONTEND_SECRET)

        keypair = NamecoinKeypair.from_private_key(wif_pk)

        if old_nmc_address == keypair.address():
            print old_nmc_address
            #print namecoind.importprivkey(keypair.wif_pk())


def import_update(userobj):

    user_id = userobj['user_id']
    update_user = users.find_one({"_id": user_id})

    if update_user is None:
        return

    nmc_address = update_user['namecoin_address']

    wif_pk = bip38_decrypt(str(userobj['encrypted_private_key']), FRONTEND_SECRET)

    keypair = NamecoinKeypair.from_private_key(wif_pk)

    namecoind = NamecoindClient(NAMECOIND_UPDATE_SERVER, NAMECOIND_PORT, NAMECOIND_USER,
                                NAMECOIND_PASSWD, NAMECOIND_USE_HTTPS,
                                NAMECOIND_WALLET_PASSPHRASE)

    if nmc_address == keypair.address():
        print update_user['username']
        print nmc_address
        print namecoind.importprivkey(keypair.wif_pk())


def pending_transactions():

    reply = namecoind.listtransactions("", 10000)

    counter = 0

    for i in reply:
        if i['confirmations'] == 0:
            counter += 1

        if counter == MAX_PENDING_TX:
            return True

    return False


def send_update(expiring_users):

    for i in expiring_users:
        key = i['name']
        try:
            value = json.loads(i['value'])
        except:
            value = i['value']

        if 'message' in value:

            value['message'] = value['message'].replace(
                'This OneName username', 'This username')

            print key
            print value
            print '-' * 5

            try:
                update_name(key,value)
                sleep(5)
            except Exception as e:
                print e


def get_emails(expiring_users):

    emails = []

    for i in expiring_users:
        username = i["name"].lstrip("u/")
        reply = old_users.find_one({"username": username})

        if reply is not None and 'email' in reply:
            emails.append(reply['email'])

    print len(emails)

    from collections import Counter

    counter = Counter(emails)

    temp = counter.most_common()

    fout = open('expiring_emails.txt', 'w')

    for i in temp:

        fout.write(str(i[0]) + ", " + str(i[1]) + '\n')

    fout.close()


def transfer_key(key, nmc_address):

    from pybitcoin.rpc.namecoind_cluster import get_server

    serverinfo = get_server(key)

    server = None

    if 'registered' in serverinfo and serverinfo['registered']:
        server = serverinfo['server']

    if server is None:
        print "Don't own this key"
        return

    namecoind = NamecoindClient(server, NAMECOIND_PORT, NAMECOIND_USER,
                                NAMECOIND_PASSWD, NAMECOIND_USE_HTTPS,
                                NAMECOIND_WALLET_PASSPHRASE)

    print namecoind.name_transfer(key, nmc_address)


def get_blockchain_profile(username):

    BASE_URL = 'http://resolver.onename.com/v1/users/'

    profile = None

    try:
        r = requests.get(BASE_URL + username, timeout=3)
        profile = json.loads(r.text)
    except Exception as e:
        print e
        log.error("User doesn't seem to exist.")

    return profile


def get_db_profile(username):

    try:
        user = users.find_one({"username": username})
        profile = get_json(user["profile"])

    except Exception as e:
        profile = None
        log.error("couldn't connect to database")

    return profile


def profile_on_blockchain(username):

    if len(username) == 34:
        return True

    if 'clone' in username or 'stormtrooper' in username:
        return True

    block_profile = get_blockchain_profile(username)
    db_profile = get_db_profile(username)

    block_profile = json.dumps(block_profile, sort_keys=True)
    db_profile = json.dumps(db_profile, sort_keys=True)

    if len(block_profile) == len(db_profile):
        # check hash for only profiles where length is the same
        if hashlib.md5(
           block_profile).hexdigest() == hashlib.md5(db_profile).hexdigest():
            return True
        else:
            return False
    else:
        return False


def change_email(old_email, new_email):
    user = users.find_one({'email': old_email})
    user['email'] = new_email
    users.save(user)


def change_username(old_username, new_username):
    user = users.find_one({'username': old_username})
    user['username'] = new_username
    users.save(user)


def change_profile(username, profile):

    user = users.find_one({'username': username})
    user['profile'] = profile
    users.save(user)


def run_analytics():

    start_time = '2014-10-21T20:58:28'  # 202000 block
    end_time = '2014-10-28T20:23:11'  # 203000 block

    from datetime import datetime
    import time

    start_time = datetime.strptime(start_time, '%Y-%m-%dT%H:%M:%S')
    start_time = time.mktime(start_time.timetuple())

    end_time = datetime.strptime(end_time, '%Y-%m-%dT%H:%M:%S')
    end_time = time.mktime(end_time.timetuple())

    counter = 0

    for user in users.find():

        register_time = user['created_at']

        register_time = time.mktime(register_time.timetuple())

        if register_time > start_time and register_time < end_time:
            print register_time
            counter += 1


def delete_account(username):

    change_profile(username, {})
    process_manually(username)
    user = users.find_one({'username': username})
    users.remove(user)
