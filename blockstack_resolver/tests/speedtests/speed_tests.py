#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os

#hack around absolute paths
current_dir =  os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from server.resolver import namecoind, namespaces, profiles
from multiprocessing.pool import Pool

from server.config import MEMCACHED_SERVERS, MEMCACHED_USERNAME, MEMCACHED_PASSWORD

import pylibmc
mc = pylibmc.Client(MEMCACHED_SERVERS, binary=True,
                    username=MEMCACHED_USERNAME, password=MEMCACHED_PASSWORD,
                    behaviors={"no_block": True, 
                               "connect_timeout": 500})

from pybitcoin.rpc import NamecoindClient

def fetch_profile_namecoind(username):

    profile = namecoind.get_full_profile('u/' + username)

    print profile
    print '-' * 5

    return profile


def fetch_profile_db(username):

    profile = profiles.find_one({"username": username})['profile']

    print profile
    print '-' * 5

    return profile


def fetch_profile_mem(username):

    profile = mc.get("profile_" + str(username))

    if profile is None: 
        print username
    else:
        print profile
    print '-' * 5

    return profile


# -----------------------------------
if __name__ == '__main__':

    #fetch_profile_namecoind("muneeb")
    #fetch_profile_resolver("ek")
    #exit(0)

    namespace = namespaces.find_one({"blocks": 36000})

    usernames = namespace['namespace']

    #usernames = usernames[:1000]

    #pool = Pool(100)

    #pool.map(fetch_profile_namecoind, usernames)
    #pool.map(fetch_profile_mem, usernames)

    for username in usernames:
        fetch_profile_namecoind(username)