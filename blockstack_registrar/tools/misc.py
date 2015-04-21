#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------
# Copyright 2015 Halfmoon Labs, Inc.
# All Rights Reserved
# -----------------------

import os
import json

from registrar.config import MONGODB_URI, OLD_DB, AWSDB_URI

from registrar.nameops import process_user, update_name, register_name

from pymongo import MongoClient
from bson.objectid import ObjectId

from encrypt import bip38_decrypt

import datetime
import hashlib
from time import sleep

# from tools.sweep_btc import sweep_btc

FRONTEND_SECRET = os.environ['FRONTEND_SECRET']

from encrypt import bip38_decrypt
from coinkit import BitcoinKeypair, NamecoinKeypair

from coinrpc import namecoind
from coinrpc.namecoind_server import NamecoindServer
from registrar.config import NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD
from registrar.config import NAMECOIND_USE_HTTPS, NAMECOIND_SERVER
from registrar.config import NAMECOIND_WALLET_PASSPHRASE
from commontools import get_json, log
import requests

# -----------------------------------
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


# -----------------------------------
def print_user(user):
    for key, value in user.iteritems():
        print key + " : " + str(value)


# -----------------------------------
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


# -----------------------------------
def process_manually_alias(username, alias):

    user = users.find_one({'username': username})
    process_user(alias, user['profile'])


# -----------------------------------
def process_manually(username):

    user = users.find_one({'username': username})
    process_user(user['username'], user['profile'])
    # cleanup_user(username)


# -----------------------------------
def process_manually_old(username):

    user = old_users.find_one({'username': username})
    process_user(user['username'], json.loads(user['profile']))


# -----------------------------------
def make_alias(alias, target):

    value = {}
    value['next'] = 'u/' + target

    process_user(alias, value)


# -----------------------------------
def find_via_email(email):

    user = users.find_one({'email': email})
    print_user(user)


# -----------------------------------
def find_via_username(username):

    user = users.find_one({'username': username})
    print_user(user)


# -----------------------------------
def find_old_user(username):

    user = old_users.find_one({'username': username})
    print_user(user)


# -----------------------------------
def import_user(username):

    for transfer_user in transfer.find():

        user_id = transfer_user['user_id']
        new_user = users.find_one({"_id":user_id})

        if new_user is None:
            continue

        if new_user['username'] == username:
            old_user = old_users.find_one({'username':new_user['username']})
            print username
        else:
            continue

        old_nmc_address = old_user['namecoin_address']

        wif_pk = bip38_decrypt(str(transfer_user['encrypted_private_key']),FRONTEND_SECRET)

        keypair = NamecoinKeypair.from_private_key(wif_pk)

        if old_nmc_address == keypair.address():
            print old_nmc_address
            print namecoind.importprivkey(keypair.wif_pk())


# -----------------------------------
def import_update(username):

    for update_user in updates.find():

        user_id = update_user['user_id']
        new_user = users.find_one({"_id":user_id})

        if new_user is None:
            continue

        if new_user['username'] == username:
            print username
        else:
            continue

        nmc_address = new_user['namecoin_address']

        wif_pk = bip38_decrypt(str(update_user['encrypted_private_key']),FRONTEND_SECRET)

        keypair = NamecoinKeypair.from_private_key(wif_pk)

        if nmc_address == keypair.address():
            print nmc_address
            print namecoind.importprivkey(keypair.wif_pk())


# -----------------------------------
def get_unlock_url(username):

    for i in remote_db.username_reservation.find():
        if i['username'] == username:
            print 'http://onename.io/?c=' + i['access_code']


# -----------------------------------
def pending_transactions():

    reply = namecoind.listtransactions("",10000)

    counter = 0

    for i in reply:
        if i['confirmations'] == 0:
            counter += 1

        if counter == MAX_PENDING_TX:
            return True

    return False


# -----------------------------------
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


# -----------------------------------
def get_emails(expiring_users):

    emails = []

    for i in expiring_users:
        username = i["name"].lstrip("u/")
        reply = old_users.find_one({"username": username})

        if reply is not None and 'email' in reply:
            emails.append(reply['email'])
        # print '-' * 5

    print len(emails)

    from collections import Counter

    counter = Counter(emails)

    temp = counter.most_common()

    fout = open('expiring_emails.txt', 'w')

    for i in temp:

        fout.write(str(i[0]) + ", " + str(i[1]) + '\n')

    fout.close()


# -----------------------------------
def grab_expiring_names():

    usernames = ['fredwilson']

    while(1):
        for username in usernames:

            key = 'u/' + username
            reply = namecoind.name_show(key)

            value = get_json(reply['value'])

            print "key %s expires in %s" % (key, reply['expires_in'])

            if 'expired' in reply and int(reply['expired']) == 1:
                register_name(key,value)

            sleep(60)


# -----------------------------------
def transfer_key(key, nmc_address):

    from pybitcoin.rpc.namecoind_cluster import get_server

    serverinfo = get_server(key)

    server = None

    if 'registered' in serverinfo and serverinfo['registered']:
        server = serverinfo['server']

    if server is None:
        print "Don't own this key"
        return

    namecoind = NamecoindServer(server, NAMECOIND_PORT, NAMECOIND_USER,
                                NAMECOIND_PASSWD, NAMECOIND_USE_HTTPS,
                                NAMECOIND_WALLET_PASSPHRASE)

    print namecoind.name_transfer(key, nmc_address)


# -----------------------------------------
def get_blockchain_profile(username):

    auth = ('opennamesystem', 'opennamesystem')
    BASE_URL = 'http://ons-server.halfmoonlabs.com/ons/profile?openname='

    profile = None

    try:
        r = requests.get(BASE_URL + username, timeout=3, auth=auth)
        profile = json.loads(r.text)
    except Exception as e:
        print e
        log.error("User doesn't seem to exist.")

    return profile


# -----------------------------------------
def get_db_profile(username):

    try:
        user = users.find_one({"username": username})
        profile = get_json(user["profile"])

    except Exception as e:
        profile = None
        log.error("couldn't connect to database")

    return profile


# -----------------------------------
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


# -----------------------------------
def change_email(old_email, new_email):
    user = users.find_one({'email': old_email})
    user['email'] = new_email
    users.save(user)


# -----------------------------------
def change_username(old_username, new_username):
    user = users.find_one({'username': old_username})
    user['username'] = new_username
    users.save(user)


# -----------------------------------
def change_profile(username, profile):

    user = users.find_one({'username': username})
    user['profile'] = profile
    users.save(user)

# -----------------------------------
if __name__ == '__main__':

    username = 'justas'

    from registrar.config_local import problem_users

    '''
    for username in problem_users:
        print 'processing:' + username
        user = users.find_one({'username': username})
        try:
            process_manually(username)
        except Exception as e:
            print username
            print e

    exit(0)
    '''

    #transfer_key('u/paulw', 'N7KBT3qnnBjbFvdPdu8Uj1nVFnXidKXHEK')

    #exit(0)

    '''
    counter = 0
    from config_local import problem_users, banned_users
    for user in users.find():

        if user['username'] in problem_users or user['username'] in banned_users:
            continue

        if not profile_on_blockchain(user['username']):
            print user['username']
            entry = {}
            entry['username'] = user['username']
            pending_users.save(entry)
        counter += 1

        if counter % 25 == 0:
            print counter

    exit(0)
    '''

    #change_email('tstern@tulane.edu', 'tstern1@tulane.edu')
    #change_username('gbd', 'gabridome')
    #exit(0)

    #email = 'ItsikItsik@yahoo.com'
    
    user = users.find_one({'username': username})
    #process_manually(username)
    
    #print user
    #user['profile'] = '{}'
    #users.save(user)
    # user['username'] = 'kyle'
    # users.save(user)
    #print_user(user)

    #exit(0)

    '''
    from config_local import problem_users, banned_users

    for user in pending_users.find():

        if user['username'] in problem_users or user['username'] in banned_users:
            #pending_users.remove(user)
            continue

        if profile_on_blockchain(user['username']):
            print "Removing: " + user['username']
            pending_users.remove(user)
            continue

        print user['username']

        try:
            process_manually(user['username'])
        except:
            pass

    exit(0)
    '''

    process_manually(username)
    exit(0)
    # username = "winklevoss1"
    # alias = "winklevoss"
    # process_manually_alias(username,alias)

    # user = users.find_one({"username":username})

    # profile = user['profile']

    #process_manually_old(username)

    # cleanup_user(username)
    # print_user(user)
    # import_user(username)
    # cleanup_user(username)

    '''
    from blockdata.namecoind_cluster import get_server

    for i in skip_users.find():

        reply = get_server(i['key'])

        if reply['server'] == None:
            pass
        else:
            print i['key']
            print skip_users.remove(i)
    '''

    from blockdata.renew_names import get_expiring_names, get_expired_names
    expiring_users = get_expiring_names('u/', 1000)
    get_emails(expiring_users)
    expired_users = get_expired_names('u/')

    counter_squatted = 0

    MAX_PENDING_TX = 50

    need_update = []

    '''
    for i in expiring_users:

        try:
            profile = json.loads(i['value'])
            status = profile['status']
            if status == 'reserved':

                need_update.append(i)
        except:
            pass

    send_update(need_update)

    exit(0)
    '''

    for i in expiring_users:

        # if i['name'] in ignore_names:
        #   continue

        reply = skip_users.find_one({"key": i['name']})

        if reply is not None:
            print "Skipping: " + reply['key']
            continue

        username = i['name'].lstrip('u/')

        new_user = users.find_one({'username': username})

        if new_user is not None:
            try:
                process_manually(username)

            except Exception as e:
                if e.message == "cannot concatenate 'str' and \
                                NoneType' objects":
                    entry = {}
                    entry["key"] = i['name']
                    skip_users.insert(entry)
                else:
                    print e
            continue

        old_user = old_users.find_one({'username': username})

        if old_user is not None:
            try:
                process_manually_old(username)

            except Exception as e:
                if e.message == "cannot concatenate 'str' and \
                                NoneType' objects":
                    entry = {}
                    entry["key"] = i['name']
                    skip_users.insert(entry)
                else:
                    print e
            continue

        print "Not our user"
