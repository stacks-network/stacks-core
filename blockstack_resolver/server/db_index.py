#!/usr/bin/env python
# -*- coding: utf-8 -*-

from server.config import NAMECOIND_SERVER, NAMECOIND_PORT, NAMECOIND_USE_HTTPS
from server.config import NAMECOIND_USER, NAMECOIND_PASSWD

from pybitcoin.rpc import NamecoindClient
namecoind = NamecoindClient(NAMECOIND_SERVER, NAMECOIND_PORT,
                            NAMECOIND_USER, NAMECOIND_PASSWD,
                            NAMECOIND_USE_HTTPS)

from pymongo import MongoClient

db = MongoClient()['resolver_index']

namespaces = db.namespaces
profiles = db.profiles

namespaces.ensure_index('blocks')
profiles.ensure_index('username')

RECENT_BLOCKS = 100 
VALID_BLOCKS = 36000

from server.resolver import username_is_valid


def save_namespace(blocks):

    namespace = []

    info = namecoind.name_filter("u/", blocks)

    for entry in info:

        if 'expired' in entry and entry['expired'] == 1:
            continue 

        username = entry['name'].lstrip('u/').lower()

        if not username_is_valid(username):
            continue
        
        namespace.append(username)

    check_entry = namespaces.find_one({"blocks": blocks})

    if check_entry is None:

        new_entry = {}
        new_entry['blocks'] = blocks
        new_entry['namespace'] = namespace
    
        namespaces.insert(new_entry)
    else:
        check_entry['namespace'] = namespace 
        namespaces.save(check_entry)
        
    return namespace


def create_namespace_index():

    full_namespace = save_namespace(VALID_BLOCKS)
    recent_namespace = save_namespace(RECENT_BLOCKS)

    counter = 0

    for username in full_namespace:

        profile = namecoind.get_full_profile('u/' + username)

        check_entry = profiles.find_one({"username": username})

        if check_entry is None:
            new_entry = {}
            new_entry['username'] = username
            new_entry['profile'] = profile
            profiles.save(new_entry)
        else:
            check_entry['profile'] = profile
            profiles.save(check_entry)

        counter += 1

        if counter % 100 == 0:
            print counter

def get_namespace():

    results = {}

    namespace = namespaces.find_one({"blocks": VALID_BLOCKS})

    for username in namespace['namespace']:
        results[username] = profiles.find_one({'username': username})['profile']

    return results

if __name__ == '__main__':

    #create_namespace_index()
    print get_namespace()