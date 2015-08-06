#!/usr/bin/env python
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

import sys
import os
from multiprocessing.pool import Pool


# hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from server.resolver import namecoind, namespaces, profiles
from server.config import MEMCACHED_SERVERS, MEMCACHED_USERNAME, MEMCACHED_PASSWORD

import pylibmc
mc = pylibmc.Client(MEMCACHED_SERVERS, binary=True,
                    username=MEMCACHED_USERNAME, password=MEMCACHED_PASSWORD,
                    behaviors={"no_block": True,
                               "connect_timeout": 500})


def fetch_profile_namecoind(username):

    #profile = namecoind.name_show('u/' + username)
    profile = namecoind.get_full_profile('u/' + username)

    return profile


def fetch_profile_db(username):

    profile = profiles.find_one({"username": username})['profile']

    return profile


def fetch_profile_mem(username):

    profile = mc.get("profile_" + str(username))

    if profile is None:
        return username

    return profile


# -----------------------------------
if __name__ == '__main__':

    namespace = namespaces.find_one({"blocks": 36000})

    usernames = namespace['namespace']

    for username in usernames:
        print fetch_profile_namecoind(username)

    #pool = Pool(100)

    #pool.map(fetch_profile_mem, usernames)
