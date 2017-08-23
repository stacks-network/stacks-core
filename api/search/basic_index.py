#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Search
    ~~~~~

    copyright: (c) 2014-2017 by Blockstack Inc.
    copyright: (c) 2017 by Blockstack.org

This file is part of Blockstack.

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import json
import requests

from pymongo import MongoClient

from .utils import validUsername
from .utils import get_json, config_log, pretty_print

from api.config import SEARCH_BLOCKCHAIN_DATA_FILE, SEARCH_PROFILE_DATA_FILE

from .db import namespace, profile_data
from .db import search_profiles
from .db import people_cache, twitter_cache, username_cache

""" create the basic index
"""

log = config_log(__name__)


def fetch_profile_data_from_file():
    """ takes profile data from file and saves in the profile_data DB
    """

    with open(SEARCH_PROFILE_DATA_FILE, 'r') as fin:
        profiles = json.load(fin)

    counter = 0

    log.debug("-" * 5)
    log.debug("Fetching profile data from file")

    for entry in profiles:
        new_entry = {}
        new_entry['key'] = entry['fqu']
        new_entry['value'] = entry['profile']

        try:
            profile_data.save(new_entry)
        except Exception as e:
            log.exception(e)
            log.error("Exception on entry {}".format(new_entry))

        counter += 1

        if counter % 1000 == 0:
            log.debug("Processed entries: %s" % counter)

    profile_data.ensure_index('key')

    return


def fetch_namespace_from_file():

    blockchain_file = open(SEARCH_BLOCKCHAIN_DATA_FILE, 'r')

    blockchain_state = blockchain_file.read()
    blockchain_state = json.loads(blockchain_state)

    counter = 0

    log.debug("-" * 5)
    log.debug("Fetching namespace from file")

    for entry in blockchain_state:

        new_entry = {}

        username = entry.rstrip('id')
        username = username.rstrip('.')

        key = entry
        check_entry = profile_data.find_one({"key": key})

        if check_entry is None:

            # profile data not available, skip
            continue

        new_entry['username'] = username
        new_entry['profile'] = check_entry['value']
        namespace.save(new_entry)
        counter += 1

        if counter % 1000 == 0:
            log.debug("Processed entries: %s" % counter)

    blockchain_file.close()
    return


def flush_db():

    client = MongoClient()

    # delete any old cache/index
    client.drop_database('search_db')
    client.drop_database('search_cache')

    log.debug("Flushed DB")


def optimize_db():

    people_cache.ensure_index('name')
    twitter_cache.ensure_index('twitter_handle')
    username_cache.ensure_index('username')

    search_profiles.ensure_index('name')
    search_profiles.ensure_index('twitter_handle')
    search_profiles.ensure_index('username')

    log.debug("Optimized DB")


def create_search_index():
    """ takes people names from blockchain and writes deduped names in a 'cache'
    """

    # create people name cache
    counter = 0

    people_names = []
    twitter_handles = []
    usernames = []

    log.debug("-" * 5)
    log.debug("Creating search index")

    for user in namespace.find():
        # the profile/info to be inserted
        search_profile = {}

        counter += 1

        if(counter % 1000 == 0):
            log.debug("Processed entries: %s" % counter)

        if validUsername(user['username']):
            pass
        else:
            # print "ignoring: " + user['username']
            continue

        profile = get_json(user['profile'])


        hasBazaarId=False
        # search for openbazaar id in the profile
        if 'account' in profile:
            for accounts in profile['account']:
                if  accounts['service'] == 'openbazaar':
                   hasBazaarId = True
                   search_profile['openbazaar']=accounts['identifier']

        if (hasBazaarId == False):
            search_profile['openbazaar'] = None

        if 'name' in profile:
            try:
                name = profile['name']
            except:
                continue

            try:
                name = name['formatted'].lower()
            except:
                name = name.lower()
            people_names.append(name)
            search_profile['name'] = name

        else:
            search_profile['name'] = None

        if 'twitter' in profile:
            twitter_handle = profile['twitter']

            try:
                twitter_handle = twitter_handle['username'].lower()
            except:
                try:
                    twitter_handle = profile['twitter'].lower()
                except:
                    continue

            twitter_handles.append(twitter_handle)
            search_profile['twitter_handle'] = twitter_handle

        else:
            search_profile['twitter_handle'] = None

        search_profile['username'] = user['username']
        usernames.append(user['username'])

        search_profile['profile'] = profile
        search_profiles.save(search_profile)


    # dedup names
    people_names = list(set(people_names))
    people_names = {'name': people_names}

    twitter_handles = list(set(twitter_handles))
    twitter_handles = {'twitter_handle': twitter_handles}

    usernames = list(set(usernames))
    usernames = {'username': usernames}

    # save final dedup results to mongodb (using it as a cache)
    people_cache.save(people_names)
    twitter_cache.save(twitter_handles)
    username_cache.save(usernames)

    optimize_db()

    log.debug('Created name/twitter/username search index')

if __name__ == "__main__":

    if(len(sys.argv) < 2):
        print "Usage error"
        exit(0)

    option = sys.argv[1]

    if(option == '--flush'):
        # Step 0
        flush_db()

    elif(option == '--create_db'):
        # Step 2
        #fetch_profile_data_from_file()
        fetch_namespace_from_file()

    elif(option == '--create_index'):
        # Step 3
        create_search_index()

    elif(option == '--optimize'):
        optimize_db()

    elif(option == '--refresh'):
        flush_db()
        fetch_profile_data_from_file()
        fetch_namespace_from_file()
        create_search_index()

    else:
        print "Usage error"
