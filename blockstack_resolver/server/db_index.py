# -*- coding: utf-8 -*-
"""
    Resolver
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

This file is part of Resolver.

    Resolver is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Resolver is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Resolver. If not, see <http://www.gnu.org/licenses/>.
"""

from commontools import get_json
from time import sleep

from .config import BITCOIND_SERVER, BITCOIND_PORT, BITCOIND_USE_HTTPS
from .config import BITCOIND_USER, BITCOIND_PASSWD

from .config import RECENT_BLOCKS, VALID_BLOCKS, REFRESH_BLOCKS

from .db import namespaces, profiles
from .resolver import username_is_valid, get_user_profile

from pybitcoin.rpc import BitcoindClient
bitcoind = BitcoindClient(BITCOIND_SERVER, BITCOIND_PORT,
                          BITCOIND_USER, BITCOIND_PASSWD,
                          BITCOIND_USE_HTTPS)




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

    info = 'xx'  # fetch namespace here

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

        save_profile(username, profile)

        counter += 1

        if counter % 100 == 0:
            print counter

    save_namespace(blocks, namespace)


def remove_expired_names():

    # to get expired usernames, use 0 for blocks
    info = 'xx'  # fetch namespace here

    for entry in info:

        username = entry['name'].lstrip('u/').lower()

        if not username_is_valid(username):
            continue

        if 'expired' in entry and entry['expired'] == 1:

            check_entry = profiles.find({"username": username}).limit(1)

            if check_entry.count() != 0:
                # print "removing: %s" % username
                profiles.remove({"username": username})


def refresh_cache(blocks):

    results = {}

    namespace = namespaces.find_one({"blocks": blocks})

    for username in namespace['namespace']:
        entry = {}

        entry["profile"] = profiles.find_one({'username': username})['profile']
        results[username] = entry

    namespace['profiles'] = results
    namespaces.save(namespace)


def refresh_index():

    remove_expired_names()
    refresh_namespace(VALID_BLOCKS)
    refresh_namespace(RECENT_BLOCKS, refresh_profiles=True)
    refresh_cache(VALID_BLOCKS)
    refresh_cache(RECENT_BLOCKS)

    print "Index refreshed"


def refresh_memory_cache():

    namespace = namespaces.find_one({"blocks": VALID_BLOCKS})

    print "Refreshing memory cache"

    counter = 0

    for username in namespace['namespace']:
        try:
            profile = get_user_profile(username, refresh=True)
        except Exception as e:
            print e

        counter += 1

        if counter % 100 == 0:
            print counter


def sync_with_blockchain():

    new_block = bitcoind.blocks()
    old_block = new_block - 1

    while(1):

        while(old_block == new_block):
            sleep(30)
            new_block = bitcoind.blocks()

        print 'current block: %s' % new_block

        refresh_index()
        old_block = new_block

        if new_block % REFRESH_BLOCKS == 0:
            refresh_memory_cache()


def format_response(response):

    response = response[0]
    return json.dumps(response, sort_keys=True, indent=4, separators=(',', ': '))


def v2_get_immutable_data(hash):

    blockstored = BlockstoreRPCClient('52.0.28.169', 6264)
    resp = blockstored.ping()

    return resp


def blockstored_dht_write(key, value):

    blockstored = BlockstoreRPCClient('52.0.28.169', 6264)

    resp = None

    try:
        resp = blockstored.set(key, value)
    except Exception as e:
        print e

    print entry['username']
    print resp


if __name__ == '__main__':

    import json
    from pybitcoin import hex_hash160

    print bitcoind.blocks()
    print v2_get_immutable_data('temp')

    fin = open('namespace_test1.json', 'r')
    namespace_file = json.loads(fin.read())

    namespace = []

    error_usernames = ['n4gn', 'pgrous', 'h4x0r3d', 'eddie_03']

    for entry in namespace_file:

        if entry['username'] not in error_usernames:
            continue

        profile_hash = hex_hash160(entry['profile'])

        if profile_hash != entry['hash']:
            print "ERROR!"
            print entry['username']
            print entry['hash']
            print profile_hash
        else:
            blockstored_dht_write(entry['hash'], entry['profile'])
    #only on first run
    #refresh_namespace(VALID_BLOCKS, refresh_profiles=True)
    #sync_with_blockchain()