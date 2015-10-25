#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Search
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

This file is part of Search.

    Search is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Search is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Search. If not, see <http://www.gnu.org/licenses/>.
"""

""" create the DB index
"""

import requests

from search.config import RESOLVER_URL, ALL_USERS_ENDPOINT
from search.utils import validUsername
from search.utils import get_json, log

from pymongo import MongoClient
client = MongoClient()
search_db = client['search_db']
search_cache = client['search_cache']

search_profiles = search_db.profiles

people_cache = search_cache.people_cache
twitter_cache = search_cache.twitter_cache
username_cache = search_cache.username_cache


def get_namespace_from_resolver(url=RESOLVER_URL, endpoint=ALL_USERS_ENDPOINT):

    full_url = url + endpoint

    headers = {'Content-type': 'application/json'}

    r = requests.get(full_url, headers=headers)

    return r.json()['results']


def get_namespace_from_file():

    return


def flush_db():

    # delete any old cache/index
    client.drop_database('search_db')
    client.drop_database('search_cache')


def optimize_db():

    search_cache.people_cache.ensure_index('name')
    search_cache.twitter_cache.ensure_index('twitter_handle')
    search_cache.username_cache.ensure_index('username')

    search_db.profiles.ensure_index('name')
    search_db.profiles.ensure_index('twitter_handle')
    search_db.profiles.ensure_index('username')


def create_search_index(namespace):
    """ takes people names from blockchain and writes deduped names in a 'cache'
    """

    flush_db()

    # create people name cache
    counter = 0

    people_names = []
    twitter_handles = []
    usernames = []

    for user in namespace:

        # the profile/info to be inserted
        search_profile = {}

        counter += 1

        if(counter % 1000 == 0):
            print counter

        if validUsername(user['username']):
            pass
        else:
            # print "ignoring: " + user['username']
            continue

        profile = get_json(user['profile'])

        if 'name' in profile:
            name = profile['name']

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

    option = sys.argv[1]

    if(option == '--create_index'):
        create_search_index()
    else:
        print "Usage error"
