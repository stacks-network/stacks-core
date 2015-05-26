#!/usr/bin/env python
# -*- coding: utf-8 -*-

from commontools import get_json

from .config import NAMECOIND_SERVER, NAMECOIND_PORT, NAMECOIND_USE_HTTPS
from .config import NAMECOIND_USER, NAMECOIND_PASSWD

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

from .resolver import username_is_valid


def save_profile(username, profile):

    check_entry = profiles.find({"username": username}).limit(1)

    if check_entry.count() == 0:
        new_entry = {}
        new_entry['username'] = username
        new_entry['profile'] = profile
        profiles.save(new_entry)
    else:
        check_entry = profiles.find_one({"username": username})
        check_entry['profile'] = profile
        profiles.save(check_entry)


def save_namespace(blocks, namespace):

    check_entry = namespaces.find_one({"blocks": blocks})

    if check_entry is None:

        new_entry = {}
        new_entry['blocks'] = blocks
        new_entry['namespace'] = namespace
    
        namespaces.insert(new_entry)
    else:
        check_entry['namespace'] = namespace 
        namespaces.save(check_entry)
        

def refresh_namespace(blocks, refresh_profiles=False):

    namespace = []

    info = namecoind.name_filter("u/", blocks)

    counter = 0 

    for entry in info:

        username = entry['name'].lstrip('u/').lower()

        if not username_is_valid(username):
            continue

        if 'expired' in entry and entry['expired'] == 1:
            continue 

        profile = get_json(entry['value'])

        if profile == {}:
            continue

        namespace.append(username)

        if not refresh_profiles:
            continue
        
        if 'next' in profile:

            profile = namecoind.get_full_profile('u/' + username)

        save_profile(username, profile)

        counter += 1

        if counter % 100 == 0:
            print counter
        
    save_namespace(blocks, namespace)



def remove_expired_names():

    #to get expired usernames, use 0 for blocks
    info = namecoind.name_filter("u/", 0)

    for entry in info:

        username = entry['name'].lstrip('u/').lower()

        if not username_is_valid(username):
            continue
        
        if 'expired' in entry and entry['expired'] == 1:

            check_entry = profiles.find({"username": username}).limit(1)

            if check_entry.count() != 0:
                print "removing: %s" % username 
                profiles.remove({"username": username}) 



def refresh_cache(blocks):

    results = {}

    namespace = namespaces.find_one({"blocks": blocks})

    for username in namespace['namespace']:
        try:
            results[username] = profiles.find_one({'username': username})['profile']
        except:
            #work around for a bug in namecoind, where it shows
            #certain keys as expired in name_filter(blocks=0) when they're not
            profile = namecoind.get_full_profile('u/' + username)
            save_profile(username, profile)
            results[username] = profile

    namespace['profiles'] = results
    namespaces.save(namespace) 


def refresh_index():

    remove_expired_names()
    refresh_namespace(VALID_BLOCKS)
    refresh_namespace(RECENT_BLOCKS, refresh_profiles=True)
    refresh_cache(VALID_BLOCKS)
    refresh_cache(RECENT_BLOCKS)

if __name__ == '__main__':


    #only on first run
    #refresh_namespace(VALID_BLOCKS, refresh_profiles=True)
    #refresh_index()
    #exit(0)
    check_entry = namespaces.find_one({"blocks": VALID_BLOCKS})

    namespace = check_entry['namespace']
    profiles = check_entry['profiles']

    from pprint import pprint
    pprint(profiles['muneeb'])
