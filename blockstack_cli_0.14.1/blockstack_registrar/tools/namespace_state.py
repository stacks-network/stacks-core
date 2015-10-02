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
from time import sleep

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
from registrar.config import IGNORE_USERNAMES


namecoind = NamecoindClient(NAMECOIND_SERVER, NAMECOIND_PORT,
                            NAMECOIND_USER, NAMECOIND_PASSWD,
                            NAMECOIND_WALLET_PASSPHRASE, NAMECOIND_USE_HTTPS)


# -----------------------------------
remote_db = MongoClient(MONGODB_URI).get_default_database()
users = remote_db.user

old_db = MongoClient(OLD_DB).get_default_database()
old_users = old_db.user

c = MongoClient()
namespace_db = c['namespace']
nmc_state = namespace_db.nmc_state
registrar_state = namespace_db.registrar_state
btc_state = namespace_db.btc_state
btc_state_diff = namespace_db.btc_state_diff
btc_state_diff_2 = namespace_db.btc_state_diff_2

nmc_state.ensure_index('username')
registrar_state.ensure_index('username')

migration_db = c['migration']
migration_users = migration_db.migration_users


def get_hash(profile):

    if type(profile) is not dict:
        try:
            print "WARNING: converting to json"
            profile = json.loads(profile)
        except:
            print "WARNING: not valid json"

    return hex_hash160(json.dumps(profile, sort_keys=True))


def fix_db():

    c = MongoClient()
    db = c['namespace']

    print db.collection_names()
    #print db.drop_collection('btc_state')


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


def check_total_users_in_states():

    print "Total users nmc state: %s" % nmc_state.count()
    print "Total users registrar state: %s" % registrar_state.count()
    print "Total users btc state: %s" % btc_state.count()


def fix_nmc_state():

    for entry in nmc_state.find():

        if 'nmc_address' not in entry:

            resp = namecoind.name_show('u/' + entry['username'])

            if 'code' in resp:
                nmc_state.remove(entry)


def create_migration_state():

    for entry in migration_users.find():

        check_entry = btc_state.find_one({"username": entry['username']})

        if check_entry is not None:
            print "%s already in btc_state" % entry['username']
            continue

        new_entry = {}
        new_entry['username'] = entry['username']
        new_entry['btc_address'] = entry['btc_address']
        new_entry['profile'] = entry['profile']
        new_entry['profile_hash'] = entry['profile_hash']

        btc_state.insert(new_entry)

    for entry in registrar_state.find():

        check_entry = btc_state.find_one({"username": entry['username']})

        if check_entry is not None:
            print "%s already in btc_state" % entry['username']
            continue

        if 'needsTransfer' in entry and entry['needsTransfer'] is True:

            new_entry = {}
            new_entry['username'] = entry['username']
            new_entry['btc_address'] = address_to_new_cryptocurrency(str(entry['nmc_address']), 0)
            new_entry['profile'] = entry['profile']
            new_entry['profile_hash'] = get_hash(entry['profile'])

            btc_state.insert(new_entry)

    for entry in nmc_state.find():

        check_entry = btc_state.find_one({"username": entry['username']})

        if check_entry is not None:
            print "%s already in btc_state" % entry['username']
            continue

        if 'reservedByOnename' in entry and entry['reservedByOnename'] is False:

            try:
                new_entry = {}
                new_entry['username'] = entry['username']
                resp = namecoind.name_show('u/' + entry['username'])

                new_entry['btc_address'] = address_to_new_cryptocurrency(str(entry['nmc_address']), 0)
                new_entry['profile'] = entry['profile']
                new_entry['profile_hash'] = entry['profile_hash']
            except:
                print "ERROR"
                print entry
            else:
                btc_state.insert(new_entry)
        else:
            print entry


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

    counter = 0

    # convert profile to json
    for entry in nmc_state.find():

        if type(entry['profile']) is not dict:

            try:
                profile = json.loads(entry['profile'])
                nmc_state.save(entry)
            except:
                pass

    # mark if profile is valid
    for entry in nmc_state.find():

        if type(entry['profile']) is not dict:
            entry['profileIsValid'] = False
        else:
            entry['profileIsValid'] = True

        nmc_state.save(entry)

    # pull full profiles for entries with next keys
    for entry in nmc_state.find():
        if entry['profileIsValid']:
            if 'next' in entry['profile']:
                counter += 1
                print counter
                profile = namecoind.get_full_profile('u/' + entry['username'])
                entry['full_profile'] = profile
                nmc_state.save(entry)

    # replace profiles with full profiles
    for entry in nmc_state.find():
        if entry['profileIsValid']:
            if 'next' in entry['profile']:
                # check if full_profile was fetched properly
                USE_FULL_PROFILE = False
                if len(json.dumps(entry['full_profile'])) >= len(json.dumps(entry['profile'])):
                    USE_FULL_PROFILE = True
                else:
                    if 'code' not in entry['full_profile']:
                        USE_FULL_PROFILE = True

                if USE_FULL_PROFILE:
                    entry['profile'] = entry['full_profile']
                    del entry['full_profile']
                    nmc_state.save(entry)

    # save profile hash
    for entry in nmc_state.find():

        entry['profile_hash'] = get_hash(entry['profile'])
        nmc_state.save(entry)

    counter = 0
    # save nmc owner address
    for entry in nmc_state.find():

        resp = namecoind.name_show('u/' + entry['username'])

        if 'address' in resp:
            entry['nmc_address'] = resp['address']
            nmc_state.save(entry)

        counter += 1
        print counter


def temp_process_nmc_state():

    return


def build_registrar_state():

    counter_users = 0

    for entry in users.find():

        new_entry = {}
        new_entry['username'] = entry['username']
        new_entry['profile'] = entry['profile']
        new_entry['nmc_address'] = entry['namecoin_address']

        registrar_state.insert(new_entry)

        counter_users += 1

        if counter_users % 10 == 0:
            print counter_users

    counter_old_users = 0

    for entry in old_users.find():

        check_entry = users.find_one({'username': entry['username']})

        if check_entry is None:

            new_entry = {}
            new_entry['username'] = entry['username']
            new_entry['profile'] = entry['profile']
            new_entry['nmc_address'] = entry['namecoin_address']

            registrar_state.insert(new_entry)

            counter_old_users += 1

            if counter_old_users % 10 == 0:
                print counter_old_users

    #print users.count()
    #print old_users.count()
    print counter_users
    print counter_old_users
    print registrar_state.count()


def process_registrar_state():

    for entry in registrar_state.find():

        entry['profile_hash'] = get_hash(entry['profile'])

        registrar_state.save(entry)


def compare_states():

    counter_not_registered = 0

    # check if registrar has pending registrations
    for entry in registrar_state.find():

        check_entry = nmc_state.find_one({"username": entry['username']})

        if check_entry is None:

            # special case: remove the junk bitcoin addresses
            if len(entry['username']) == 34:
                print entry['username']
                #registrar_state.remove(entry)

            counter_not_registered += 1

    print "Not registered on nmc: %s" % counter_not_registered

    # check if registrar's view matches nmc

    counter_profile_data_mismatch = 0
    counter_send_profile_update = 0

    for entry in registrar_state.find(timeout=False):

        nmc_entry = nmc_state.find_one({"username": entry['username']})

        if nmc_entry is None:
            continue

        if entry['profile_hash'] != nmc_entry['profile_hash']:
            #print entry['username']
            counter_profile_data_mismatch += 1

            if 'needsTransfer' in entry and entry['needsTransfer'] is True:
                counter_send_profile_update += 1
                if entry['username'] in IGNORE_USERNAMES:
                    continue
                else:
                    user = users.find_one({"username": entry['username']})
                    print user['username']
                    try:
                        process_user(user['username'], user['profile'], new_address=user['namecoin_address'])
                    except Exception as e:
                        print e

    print "Profile hash mismatch: %s" % counter_profile_data_mismatch
    print "Registrar profiles to update: %s" % counter_send_profile_update


def check_ownership_state():

    counter_needs_transfer = 0
    counter_transferred = 0

    for entry in registrar_state.find():

        nmc_entry = nmc_state.find_one({"username": entry['username']})

        if nmc_entry is None:
            continue

        if nmc_entry['nmc_address'] != entry['nmc_address']:
            print entry['username']
            counter_needs_transfer += 1
        else:
            counter_transferred += 1

    print counter_needs_transfer
    print counter_transferred


def check_transfer_state():

    from registrar.config import SERVER_FLEET, IGNORE_USERNAMES

    servers = SERVER_FLEET

    counter = 0

    for entry in registrar_state.find(timeout=False):

        counter += 1
        #print counter

        nmc_entry = nmc_state.find_one({"username": entry['username']})

        if nmc_entry is None:
            continue

        if 'needsTransfer' in entry and entry['needsTransfer'] is True:
            continue

        if nmc_entry['nmc_address'] != entry['nmc_address']:

            server_counter = 0

            while(server_counter != len(servers)):

                server = servers[server_counter]

                #print server

                namecoind = NamecoindClient(server)

                try:
                    resp = namecoind.validateaddress(nmc_entry['nmc_address'])
                except Exception as e:
                    print e
                    print server
                    server_counter += 1
                    sleep(3)
                    continue

                if 'ismine' in resp and resp['ismine'] is True:
                    entry['needsTransfer'] = True
                    entry['server'] = server
                    #print entry
                    registrar_state.save(entry)
                    break

                server_counter += 1

                if server_counter == 8:
                    print entry['username']


        #print entry['username']
        #print '-' * 5

def update_transfer_state():

    counter = 0

    for entry in registrar_state.find():

        if 'needsTransfer' in entry and entry['needsTransfer'] is True:

            profile = entry['profile']

            #print entry['username']
            #print entry['server']
            #print '-' * 5
            #continue

            namecoind = NamecoindClient()

            try:
                resp = namecoind.name_show('u/' + entry['username'])
            except Exception as e:
                print e
                continue
            current_nmc_address = resp['address']

            if current_nmc_address == entry['nmc_address']:
                print entry['username']

                entry['needsTransfer'] = False
                registrar_state.save(entry)

            counter += 1

    print counter


def dump_btc_state():

    namespace = []

    for entry in btc_state_diff_2.find():
        del entry['_id']
        namespace.append(entry)

    print namespace
    fout = open('btc_state_diff_2.txt', 'w')

    fout.write(json.dumps(namespace))
    fout.close()

if __name__ == '__main__':

    dump_btc_state()
    #update_transfer_state()
    #dump_btc_state()
    #check_total_users_in_states()  
    #create_migration_state()
    #check_transfer_state()
    #compare_states()
    #process_registrar_state()
    #process_nmc_state()
