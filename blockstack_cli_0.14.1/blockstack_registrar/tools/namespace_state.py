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

import json

from pymongo import MongoClient

from pybitcoin import hex_hash160, address_to_new_cryptocurrency
from pybitcoin.rpc import NamecoindClient
from pybitcoin.rpc.namecoind_cluster import check_address

from registrar.nameops import process_user, update_name, register_name
from registrar.nameops import get_namecoind
from registrar.transfer import transfer_name, nameTransferred


from registrar.config import NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD
from registrar.config import NAMECOIND_USE_HTTPS, NAMECOIND_SERVER
from registrar.config import NAMECOIND_WALLET_PASSPHRASE
from registrar.config import MONGODB_URI, OLD_DB, AWSDB_URI, MONGOLAB_URI


namecoind = NamecoindClient(NAMECOIND_SERVER, NAMECOIND_PORT,
                            NAMECOIND_USER, NAMECOIND_PASSWD,
                            NAMECOIND_WALLET_PASSPHRASE, NAMECOIND_USE_HTTPS)


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

namespace_db = c['namespace']
nmc_state = namespace_db.nmc_state
registrar_state = namespace_db.registrar_state
btc_state = namespace_db.btc_state


def get_hash(profile):

    if type(profile) is not dict:
        print "converting to json"
        profile = json.loads(profile)

    return hex_hash160(json.dumps(profile, sort_keys=True))


def create_test_namespace():

    reply = namecoind.name_filter('u/', 200)

    counter = 0

    namespace = []

    for entry in reply:
        username = entry['name'].lstrip('u/')

        if len(username) > 30:
            continue

        counter += 1

        if counter >= 100:
            break

        new_entry = {}
        new_entry['username'] = username

        profile = namecoind.get_full_profile('u/' + username)

        print username
        print profile

        new_entry['hash'] = hex_hash160(json.dumps(profile))
        print new_entry['hash']

        namespace.append(new_entry)

    fout = open('output_file.txt', 'w')

    fout.write(json.dumps(namespace))

    print counter
    print namespace


def check_test_namespace():

    fin = open('namespace_test4.json', 'r')
    namespace_file = json.loads(fin.read())

    namespace = []

    for entry in namespace_file:

        profile = entry['profile']

        test_hash = get_hash(profile)

        if test_hash != entry['profile_hash']:
            print "oops"
        else:
            print test_hash
            print entry['profile_hash']

        #new_entry = {}
        #new_entry['username'] = entry['username']

        #username = entry['username']
        #profile = namecoind.get_full_profile('u/' + username)
        #print json.dumps(profile)

        #data = namecoind.name_show('u/' + username)

        #nmc_address = data['address']
        #print nmc_address
        #print '-' * 5

        #new_entry['profile'] = profile

        #profile_hash = hex_hash160(json.dumps(profile))

        #new_entry['hash'] = profile_hash
        #new_entry['nmc_address'] = nmc_address

        #namespace.append(new_entry)

    #fout = open('output_file.txt', 'w')

    #fout.write(json.dumps(namespace))


def get_reserved_usernames():

    resp = namecoind.name_filter('u/')

    counter = 0

    for entry in resp:

        new_entry = {}

        try:
            profile = json.loads(entry['value'])
        except:
            profile = entry['value']

        if 'message' in profile:
            print entry['name']
            print profile
            print '-' * 5

            new_entry['username'] = entry['name'].lstrip('u/')
            new_entry['profile'] = profile

            migration_users.insert(new_entry)

            counter += 1

    print counter


def build_nmc_state():

    namecoind = NamecoindClient('named8')
    resp = namecoind.name_filter('u/')

    counter = 0

    for entry in resp:

        counter += 1

        print counter

        new_entry = {}

        new_entry['username'] = entry['name'].lstrip('u/')

        profile = entry['value']

        new_entry['profile'] = profile

        if 'message' in profile:
            new_entry['reservedByOnename'] = True
        else:
            new_entry['reservedByOnename'] = False

        nmc_state.insert(new_entry)

    print counter


def process_nmc_state():

    for entry in nmc_state.find():

        print entry['username']


def build_registrar_state():

    return


def fix_db():

    c = MongoClient()
    db = c['namespace']

    print db.collection_names()
    #print db.drop_collection('nmc_state')

if __name__ == '__main__':

    process_nmc_state()