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
import requests
from time import sleep

from pymongo import MongoClient

from pybitcoin import hex_hash160, address_to_new_cryptocurrency
from pybitcoin import BitcoinPrivateKey, NamecoinPrivateKey
from pybitcoin.rpc import NamecoindClient
from pybitcoin.rpc.namecoind_cluster import check_address

from registrar.nameops import process_user, update_name, register_name
from registrar.nameops import get_namecoind
from registrar.transfer import transfer_name, nameTransferred, transfer_key

from tools.bip38 import bip38_encrypt

from registrar.config import NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD
from registrar.config import NAMECOIND_USE_HTTPS, NAMECOIND_SERVER
from registrar.config import NAMECOIND_WALLET_PASSPHRASE
from registrar.config import MONGODB_URI, OLD_DB, AWSDB_URI, MONGOLAB_URI
from registrar.config import FRONTEND_SECRET


from tools.misc import process_manually
from tools.sweep_btc import sweep_btc
from tools.misc import import_update
from tools.crypto_tools import aes_encrypt, aes_decrypt, get_addresses_from_privkey
from tools.namespace_state import get_hash
from tools.namespace_diff import insert_state_diff as insert_btc_diff

from registrar.config import SERVER_FLEET
from pybitcoin.rpc.namecoind_cluster import pending_transactions

namecoind = NamecoindClient(NAMECOIND_SERVER, NAMECOIND_PORT,
                            NAMECOIND_USER, NAMECOIND_PASSWD,
                            NAMECOIND_WALLET_PASSPHRASE, NAMECOIND_USE_HTTPS)

SECRET_KEY = os.environ['SECRET_KEY']

# -----------------------------------
remote_db = MongoClient(MONGODB_URI).get_default_database()
users = remote_db.user
registrations = remote_db.user_registration
updates = remote_db.profile_update
transfer = remote_db.name_transfer

old_db = MongoClient(OLD_DB).get_default_database()
old_users = old_db.user

aws_db = MongoClient(AWSDB_URI)['blockdata']
skip_users = aws_db.skip_users
pending_users = aws_db.pending_users

c = MongoClient()
migration_db = c['migration']
migration_users = migration_db.migration_users

namespace_db = c['namespace']
nmc_state = namespace_db.nmc_state
registrar_state = namespace_db.registrar_state
btc_state = namespace_db.btc_state
btc_state_diff = namespace_db.btc_state_diff
btc_state_diff_2 = namespace_db.btc_state_diff_2


def update_migration_users():

    for user in migration_users.find():

        resp = namecoind.name_show('u/' + user['username'])

        if 'address' in resp:
            nmc_address = resp['address']

            if nmc_address != user['nmc_address']:

                try:
                    process_user(user['username'], user['profile'], new_address=user['nmc_address'])
                except Exception as e:
                    print e


def add_migration_user(username, profile):

    check_entry = migration_users.find_one({"username": username})

    if check_entry is not None:
        print "already in migration DB"
        return

    new_entry = {}
    new_entry['username'] = username
    new_entry['profile'] = profile
    new_entry['profile_hash'] = get_hash(profile)
    privkey = BitcoinPrivateKey()
    hex_privkey = privkey.to_hex()
    new_entry['encrypted_privkey'] = aes_encrypt(hex_privkey, SECRET_KEY)

    #hex_privkey_test = aes_decrypt(new_entry['encrypted_privkey'], SECRET_KEY)
    #print hex_privkey
    #print hex_privkey_test

    nmc_address, btc_address = get_addresses_from_privkey(hex_privkey)

    new_entry['nmc_address'] = nmc_address
    new_entry['btc_address'] = btc_address
    print new_entry

    migration_users.save(new_entry)


def test_migration_user(check_user):

    for entry in migration_users.find():

        if entry['username'] != check_user:
            continue

        hex_privkey = aes_decrypt(entry['encrypted_privkey'], SECRET_KEY)
        nmc_privkey = NamecoinPrivateKey(hex_privkey)
        btc_privkey = BitcoinPrivateKey(hex_privkey)
        print hex_privkey
        print nmc_privkey.to_wif()
        print get_addresses_from_privkey(hex_privkey)

        #encrypted_privkey = aes_encrypt(entry['hex_privkey'], SECRET_KEY)


def add_users_from_db(list_of_users_to_add):

    for username in list_of_users_to_add:
        print username
        user = users.find_one({"username": username})

        if user is None:
            user = old_users.find_one({"username": username})

        add_migration_user(user['username'], user['profile'])


def sleep_while_pending_tx():

    while(1):
        total_pending_tx = check_pending_tx()

        if total_pending_tx > 200:
            print "pending tx, sleeping"
            sleep(60)
        else:
            print "resuming"
            break


def transfer_registrar_users():

    counter = 0

    for user in users.find(timeout=False):

        registrar_entry = registrar_state.find_one({"username": user['username']})

        if registrar_entry is None:
            #print "not in registrar state %s" % user['username']
            continue

        if 'needsTransfer' in registrar_entry and registrar_entry['needsTransfer'] is True:

            profile = user['profile']

            try:
                transfer_key(user['username'], user['namecoin_address'], live=True, server=registrar_entry['server'])
                #transfer_key(user['username'], user['namecoin_address'], live=True)
            except Exception as e:
                print e
                print user['username']

        counter += 1

        if counter % 100 == 0:
            sleep_while_pending_tx()

    print counter


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


def test_btc_migration(blockstore_db_file, check_username, namespace):

    btc_migration = open(blockstore_db_file, 'r').read()
    btc_migration = json.loads(btc_migration)

    btc_registrations = btc_migration['registrations']

    for entry in btc_registrations:
        username = entry

        if username != (check_username + "." + namespace):
            continue

        profile_hash = btc_registrations[username]['value_hash']
        owner_address = btc_registrations[username]['address']

        print username
        print owner_address
        print '-' * 5

    entry = migration_users.find_one({"username": check_username})
    print entry['btc_address']

    hex_privkey = aes_decrypt(entry['encrypted_privkey'], SECRET_KEY)
    nmc_address, btc_address = get_addresses_from_privkey(hex_privkey)
    print btc_address
    print nmc_address


def clean_registration(username):

    check_user = users.find_one({"username": username})

    print check_user['namecoin_address']

    return

    check_register = registrations.find_one({"user_id": check_user['_id']})

    if check_register is not None:
        registrations.remove(check_register)
        print "cleaning: %s" % username


def calculate_diff():

    ban_users = []

    counter = 0

    for check_user in old_users.find():

        username = check_user["username"]
        check_new_user = users.find_one({"username": username})
        check_btc = btc_state.find_one({"username": username})
        check_btc_diff = btc_state_diff.find_one({"username": username})

        if check_btc is None and check_btc_diff is None and check_new_user is None:

            if len(username) == 34 or len(username) == 33:
                continue

            if 'stormtrooper' in username or 'clone' in username:
                continue

            if username in ban_users:
                continue

            namecoind = NamecoindClient()

            try:
                resp = namecoind.name_show('u/' + username)
            except Exception as e:
                print username
                print e
                continue

            if 'code' in resp:
                print "not registered: %s" % username
                continue

            try:
                resp_value = resp['value']

                if 'message' in resp_value:
                    print "reserved: %s" % username
                    continue
            except Exception as e:
                print e

            try:
                current_nmc_address = resp['address']
            except Exception as e:
                print resp
                continue

            if current_nmc_address == check_user['namecoin_address']:
                print "transferred new user: %s" % username
                insert_btc_diff(username, check_user['profile'], str(check_user['namecoin_address']))
            else:
                namecoind = get_namecoind('u/' + username)

                try:
                    resp = namecoind.validateaddress(current_nmc_address)
                except Exception as e:
                    print e
                    continue

                if 'ismine' in resp and resp['ismine'] is True:

                    profile = check_user['profile']
                    if type(profile) is not dict:
                        profile = json.loads(profile)

                    insert_btc_diff(username, profile, str(check_user['namecoin_address']))

                else:
                    print "problem: %s" % username
                    print check_user['namecoin_address']

            print '-' * 5
            counter += 1

    print counter


def calculate_old_users_bug():

    counter = 0
    for old_user in old_users.find():

        username = old_user['username']

        new_user = users.find_one({"username": username})

        if new_user is not None:

            btc_address = address_to_new_cryptocurrency(str(old_user['namecoin_address']), 0)
            btc_user = btc_state.find_one({"username": username})

            if btc_user is not None:
                if btc_address == btc_user['btc_address']:
                    print username
                    insert_btc_diff(username, new_user['profile'], str(new_user['namecoin_address']))
                    counter += 1
    print counter


def reprocess_user(username):

    user = users.find_one({"username": username})
    process_user(user['username'], user['profile'], new_address=user['namecoin_address'])


def find_user_by_email(email):

    user = users.find_one({"email": email})
    print user['username']
    print user['namecoin_address']


def print_owner_addresses(username):

    old_user = old_users.find_one({"username": username})
    new_user = users.find_one({"username": username})
    btc_user = btc_state.find_one({"username": username})

    if old_user is not None:
        print old_user['namecoin_address']
    print new_user['namecoin_address']
    print btc_user['btc_address']


def test_namespace(btc_state_file):

    fin = open(btc_state_file, 'r')
    namespace_file = json.loads(fin.read())

    namespace = []

    counter = 0
    counter_double = 0
    for entry in namespace_file:

        check_entry = btc_state.find_one({"username": entry['username']})

        if check_entry is not None:
            counter_double += 1
        counter += 1

    print counter
    print counter_double


def prepare_diff_2(btc_state_file, btc_state_diff_file):

    fin = open(btc_state_file, 'r')
    first_import = json.loads(fin.read())
    fin.close()

    fin = open(btc_state_diff_file, 'r')
    diff_1 = json.loads(fin.read())
    fin.close()

    btc_namespace = first_import + diff_1
    counter = 0

    user_found = False

    for user in users.find():

        username = user['username']

        user_found = False

        if len(username) == 34 or len(username) == 33:
            continue

        if 'stormtrooper' in username or 'clone' in username:
            continue

        for check_user in btc_namespace:

            if username == check_user['username']:
                user_found = True
                break

        if user_found is True:
            continue

        namecoind = NamecoindClient()

        try:
            resp = namecoind.name_show('u/' + username)
        except Exception as e:
            print username
            print e
            continue

        if 'code' in resp:
            pass
            #print "not registered: %s" % username
            #print username
            #insert_btc_diff(username, user['profile'], str(user['namecoin_address']))
            #counter += 1
        else:
            print username

    print counter


def get_reserved_profile(name):

    profile = {}
    profile['status'] = 'reserved'
    profile['message'] = "This blockchain ID is reserved for %s. If this is \
                          you, please email support@onename.com to claim it \
                          for free." % name

    return profile


def insert_users(list_of_users):

    for username in list_of_users:

        check_user = migration_users.find_one({"username": username})

        print check_user

        insert_btc_diff(username, check_user['profile'], str(check_user['nmc_address']))


def check_user_state(username):

    check_user = btc_state_diff_2.find_one({"username": username})

    if check_user is None:
        check_user = btc_state_diff.find_one({"username": username})

        if check_user is None:
            check_user = btc_state.find_one({"username": username})

    return check_user


if __name__ == '__main__':

    print_reserved_users()
