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

from pymongo import MongoClient

client = MongoClient()
search_db = client['search_db']
search_cache = client['search_cache']

namespace = search_db.namespace
profile_data = search_db.profile_data

# these are used by substring_search
search_profiles = search_db.profiles
people_cache = search_cache.people_cache
twitter_cache = search_cache.twitter_cache
username_cache = search_cache.username_cache


# these are used by payment_search
twitter_payment = search_db.twitter_payment
facebook_payment = search_db.facebook_payment
github_payment = search_db.github_payment
domain_payment = search_db.domain_payment
