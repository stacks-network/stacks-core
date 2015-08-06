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
from commontools import log, get_json

from pybitcoin.rpc import namecoind

from .nameops import update_name, process_user

from .loadbalancer import load_balance

from .config import MONGODB_URI, OLD_DB

from pymongo import MongoClient
remote_db = MongoClient(MONGODB_URI).get_default_database()
users = remote_db.user

old_db = MongoClient(OLD_DB).get_default_database()
old_users = old_db.user


# -----------------------------------
def get_overlap():

    reply = namecoind.name_filter('id/')

    counter = 0

    id_namespace = []

    for i in reply:
        if 'expired' in i:
            pass
        else:
            counter += 1
            id_namespace.append(i['name'].lstrip('id/'))

    reply = namecoind.name_filter('u/')

    counter = 0

    u_namespace = []

    for i in reply:
        if 'expired' in i:
            pass
        else:
            counter += 1
            u_namespace.append(i['name'].lstrip('u/'))

    from collections import Counter
    a_multiset = Counter(id_namespace)
    b_multiset = Counter(u_namespace)

    overlap = list((a_multiset & b_multiset).elements())

    for i in overlap:
        print i
    print len(overlap)


# -----------------------------------
def get_expiring_names(regrex, expires_in):

    expiring_names = []
    reply = namecoind.name_filter(regrex)

    counter_total = 0
    counter_expiring = 0
    for i in reply:
        counter_total += 1
        try:
            if i['expires_in'] < expires_in:
                expiring_names.append(i)
                print i['name']
                print i['expires_in']
                counter_expiring += 1
                #print i['value']
                #print '-' * 5
        except:
            print i

    print '-' * 5
    print "Total names: " + str(counter_total)
    print "Total expiring in " + str(expires_in) + " blocks: " + str(counter_expiring)

    return expiring_names


# -----------------------------------
def get_expired_names(regrex):

    expired_names = []
    reply = namecoind.name_filter(regrex, check_blocks=0)

    counter_total = 0
    counter_expired = 0
    for i in reply:
        counter_total += 1

        if 'expired' in i and i['expired'] == 1:
            print i['name']
            counter_expired += 1

            expired_names.append(i)

    print '-' * 5
    print "Total names: " + str(counter_total)
    print "Total expired: " + str(counter_expired)

    return expired_names


# -----------------------------------
def send_update(expiring_users):

    for i in expiring_users:
        key = i['name']
        try:
            value = json.loads(i['value'])
        except:
            value = i['value']

        if 'message' in value:
            value['message'] = value['message'].replace('This OneName username', 'This username')

            #print key
            #print value
            #print '-' * 5

            try:
                update_name(key, value)
            except Exception as e:

                if hasattr(e, 'error'):
                    print e.error
                else:
                    print e

            sleep(5)


# -----------------------------------
def re_register(current_server):

    expired_users = get_expired_names('u/')

    #ignore_users = ['frm','rfd','meng','bjorn']
    ignore_users = ['go']

    counter = 0

    for i in expired_users:

        if counter % 10 == 0:
            current_server = load_balance(current_server)
            counter += 1

        username = i['name'].lstrip('u/')

        if username in ignore_users:
            continue

        new_user = users.find_one({'username':username})

        if new_user is not None:
            print username + " in new DB"

            profile = get_json(new_user['profile'])
            try:
                process_user(username, profile, current_server)
            except Exception as e:
                print e
            print '-' * 5
            counter += 1
            continue

        old_user = old_users.find_one({'username': username})

        if old_user is not None:
            print username + " in old DB"
            profile = get_json(old_user['profile'])

            try:
                process_user(username, profile, current_server)
            except Exception as e:
                print e

            counter += 1
            continue

        profile = namecoind.name_show(i['name'])
        profile = profile['value']
        

        try:
            if 'status' in profile and profile['status'] == 'reserved':
                try:
                    process_user(username, profile, current_server)
                except Exception as e:
                    print e

                counter += 1
                continue
        except:
            print "error"
            print profile

        print username + " not our user"
        print '-' * 5

# -----------------------------------
if __name__ == '__main__':

    #expiring_users = get_expiring_names('u/',2000)
    #get_expired_names('u/')
    #send_update(expiring_users)

    re_register('named3')
