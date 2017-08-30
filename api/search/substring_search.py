#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Search
    ~~~~~

    copyright: (c) 2014-2017 by Blockstack Inc.
    copyright: (c) 2017 by Blockstack.org

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

""" functions for substring search
    usage: './substring_search --create_cache --search <query>'
"""

import os
import sys
import json


from api.search.db import search_db, search_profiles
from api.search.db import search_cache

from api.config import SEARCH_DEFAULT_LIMIT as DEFAULT_LIMIT
from .utils import get_json,pretty_print

def anyword_substring_search_inner(query_word, target_words):
    """ return True if ANY target_word matches a query_word
    """

    for target_word in target_words:

        if(target_word.startswith(query_word)):
            return query_word

    return False


def anyword_substring_search(target_words, query_words):
    """ return True if all query_words match
    """

    matches_required = len(query_words)
    matches_found = 0

    for query_word in query_words:

        reply = anyword_substring_search_inner(query_word, target_words)

        if reply is not False:

            matches_found += 1

        else:
            # this is imp, otherwise will keep checking
            # when the final answer is already False
            return False

    if(matches_found == matches_required):
        return True
    else:
        return False


def substring_search(query, list_of_strings, limit_results=DEFAULT_LIMIT):
    """ main function to call for searching
    """

    matching = []

    query_words = query.split(' ')

    # sort by longest word (higest probability of not finding a match)
    query_words.sort(key=len, reverse=True)

    counter = 0

    for s in list_of_strings:

        target_words = s.split(' ')

        # the anyword searching function is separate
        if(anyword_substring_search(target_words, query_words)):
            matching.append(s)

            # limit results
            counter += 1
            if(counter == limit_results):
                break

    return matching


def search_people_by_GUID(query, limit_results=DEFAULT_LIMIT):

    result={}
    
    for entry in search_profiles.find({"openbazaar":query}, {"profile":1,"username" : 1}):
         result["profile"] = entry["profile"]
         result["username"] = entry["username"]
    
    pretty_print(result)



def search_people_by_name(query, limit_results=DEFAULT_LIMIT):

    query = query.lower()

    people_names = []

    # using mongodb as a cache, load data in people_names


    
    for i in search_cache.people_cache.find():
        people_names += i['name']
        
          
    results = substring_search(query, people_names, limit_results)

    return order_search_results(query, results)


def search_people_by_twitter(query, limit_results=DEFAULT_LIMIT):

    query = query.lower()

    twitter_handles = []
    
    
    
    # using mongodb as a cache, load data
    for i in search_cache.twitter_cache.find():
        twitter_handles += i['twitter_handle']

       
    results = substring_search(query, twitter_handles, limit_results)

    return results


def search_people_by_username(query, limit_results=DEFAULT_LIMIT):

    query = query.lower()

    usernames = []

    # using mongodb as a cache, load data
    for i in search_cache.username_cache.find():
        usernames += i['username']

    results = substring_search(query, usernames, limit_results)

    return results


def search_people_by_bio(query, limit_results=DEFAULT_LIMIT,
                         index=['onename_people_index']):
    """ queries lucene index to find a nearest match, output is profile username
    """

    from pyes import QueryStringQuery, ES
    conn = ES()

    q = QueryStringQuery(query,
                         search_fields=['username', 'profile_bio'],
                         default_operator='and')

    results = conn.search(query=q, size=20, indices=index)
    count = conn.count(query=q)
    count = count.count

    # having 'or' gives more results but results quality goes down
    if(count == 0):

        q = QueryStringQuery(query,
                             search_fields=['username', 'profile_bio'],
                             default_operator='or')

        results = conn.search(query=q, size=20, indices=index)

    results_list = []
    counter = 0

    for profile in results:

        username = profile['username']
        results_list.append(username)

        counter += 1

        if(counter == limit_results):
            break

    return results_list


def fetch_profiles(search_results, search_type="name"):

    results = []

    for search_result in search_results:

        if search_type == 'name':
            response = search_profiles.find({"name": search_result})

        elif search_type == 'twitter':
            response = search_profiles.find({"twitter_handle": search_result})

        elif search_type == 'username':
            response = search_profiles.find({"username": search_result})

        for result in response:

            try:
                del result['name']
                del result['twitter_handle']
                del result['_id']
            except:
                pass

            results.append(result)

    return results


def order_search_results(query, search_results):
    """ order of results should be a) query in first name, b) query in last name
    """

    results = search_results

    results_names = []
    old_query = query
    query = query.split(' ')

    first_word = ''
    second_word = ''
    third_word = ''

    if(len(query) < 2):
        first_word = old_query
    else:
        first_word = query[0]
        second_word = query[1]

        if(len(query) > 2):
            third_word = query[2]

    # save results for multiple passes
    results_second = []
    results_third = []

    for result in results:

        result_list = result.split(' ')

        try:
            if(result_list[0].startswith(first_word)):
                results_names.append(result)
            else:
                results_second.append(result)
        except:
            results_second.append(result)

    for result in results_second:

        result_list = result.split(' ')

        try:
            if(result_list[1].startswith(first_word)):
                results_names.append(result)
            else:
                results_third.append(result)
        except:
            results_third.append(result)

    # results are either in results_names (filtered)
    # or unprocessed in results_third (last pass)
    return results_names + results_third


def dedup_search_results(search_results):
    """ dedup results
    """

    known = set()
    deduped_results = []

    for i in search_results:

        username = i['username']

        if username in known:
            continue

        deduped_results.append(i)

        known.add(username)

    return deduped_results


if __name__ == "__main__":

    if(len(sys.argv) < 2):
        print "Usage error"

    option = sys.argv[1]

    if(option == '--search_name'):
        query = sys.argv[2]
        name_search_results = search_people_by_name(query, DEFAULT_LIMIT)
        print name_search_results
        print '-' * 5
        print fetch_profiles(name_search_results, search_type="name")
    elif(option == '--search_twitter'):
    
        query = sys.argv[2]
        twitter_search_results = search_people_by_twitter(query, DEFAULT_LIMIT)
        print twitter_search_results
        print '-' * 5
        print fetch_profiles(twitter_search_results, search_type="twitter")
    elif(option == '--search_GUID'):
        print "searching by GUID"
        query = sys.argv[2]
        search_people_by_GUID(query, DEFAULT_LIMIT)
    elif(option == '--search_username'):
        query = sys.argv[2]
        username_search_results = search_people_by_username(query, DEFAULT_LIMIT)
        print username_search_results
        print '-' * 5
        print fetch_profiles(username_search_results, search_type="username")
    elif(option == '--search_bio'):
        query = sys.argv[2]
        usernames_list = search_people_by_bio(query, DEFAULT_LIMIT)
        print usernames_list
        print '-' * 5
        print fetch_profiles(usernames_list, search_type="username")
    else:
        print "Usage error"
