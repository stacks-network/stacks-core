#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Search
~~~~~

copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
copyright: (c) 2016 by Blockstack.org

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

import sys
import json
import threading

from time import time
from flask import request, jsonify, make_response, render_template, Blueprint
from flask_crossdomain import crossdomain

from api.config import DEFAULT_HOST, DEFAULT_PORT, DEBUG, DEFAULT_CACHE_TIMEOUT, EMPTY_CACHE_TIMEOUT
from api.config import SEARCH_DEFAULT_LIMIT as DEFAULT_LIMIT

from .substring_search import search_people_by_name, search_people_by_twitter
from .substring_search import search_people_by_username, search_people_by_bio
from .substring_search import fetch_profiles

from .attributes_index import search_proofs, validProofQuery

searcher = Blueprint('searcher', __name__, url_prefix='')

class QueryThread(threading.Thread):
    """ for performing multi-threaded search on three search sub-systems
    """
    def __init__(self, query, query_type, limit_results):
        threading.Thread.__init__(self)
        self.query = query
        self.query_type = query_type
        self.results = []
        self.limit_results = limit_results
        self.found_exact_match = False

    def run(self):
        if(self.query_type == 'people_search'):
            self.results = query_people_database(self.query, self.limit_results)
        elif(self.query_type == 'twitter_search'):
            self.results = query_twitter_database(self.query, self.limit_results)
        elif(self.query_type == 'username_search'):
            self.results = query_username_database(self.query, self.limit_results)
            #self.found_exact_match, self.results = query_company_database(self.query)


def error_reply(msg, code=-1):
    reply = {}
    reply['status'] = code
    reply['message'] = "ERROR: " + msg
    return jsonify(reply)


def query_people_database(query, limit_results=DEFAULT_LIMIT):

    name_search_results = search_people_by_name(query, limit_results)
    return fetch_profiles(name_search_results, search_type="name")


def query_twitter_database(query, limit_results=DEFAULT_LIMIT):

    twitter_search_results = search_people_by_twitter(query, limit_results)
    return fetch_profiles(twitter_search_results, search_type="twitter")


def query_username_database(query, limit_results=DEFAULT_LIMIT):

    username_search_results = search_people_by_username(query, limit_results)
    return fetch_profiles(username_search_results, search_type="username")


def test_alphanumeric(query):
    """ check if query has only alphanumeric characters or not
    """

    import re
    valid = re.match(r'^\w+[\s\w]*$', query) is not None

    return True


@searcher.route('/search', methods = ["GET", "POST"], strict_slashes = False)
@crossdomain(origin='*')
def search_by_name():

    query = request.args.get('query')

    results_people = []

    if query is None:
        return error_reply("No query given")
    elif query == '' or query == ' ':
        return json.dumps({})

    new_limit = DEFAULT_LIMIT

    try:
        new_limit = int(request.values['limit_results'])
    except:
        pass

    if validProofQuery(query):
        return search_proofs_index(query)

    elif test_alphanumeric(query) is False:
        pass

    else:

        threads = []

        t1 = QueryThread(query, 'username_search', new_limit)
        t2 = QueryThread(query, 'twitter_search', new_limit)
        t3 = QueryThread(query, 'people_search', new_limit)

        threads.append(t1)
        threads.append(t2)
        threads.append(t3)

        # start all threads
        [x.start() for x in threads]

        # wait for all of them to finish
        [x.join() for x in threads]

        # at this point all threads have finished and all queries have been performed

        results_username = t1.results
        results_twitter = t2.results
        results_people = t3.results

        results_people += results_username + results_twitter

        # dedup all results before sending out
        from substring_search import dedup_search_results
        results_people = dedup_search_results(results_people)

    results = {}
    results['results'] = results_people[:new_limit]

    resp = make_response(jsonify(results))
    if len(results['results']) > 0:
        cache_timeout = DEFAULT_CACHE_TIMEOUT
    else:
        cache_timeout = EMPTY_CACHE_TIMEOUT

    resp.headers['Cache-Control'] = 'public, max-age={:d}'.format(cache_timeout)

    return resp

def search_proofs_index(query):

    results = {}

    query = request.args.get('query')

    if query is None:
        return error_reply("No query given")
    elif query == '' or query == ' ':
        return json.dumps({})

    results['results'] = search_proofs(query)

    return jsonify(results)
