# -*- coding: utf-8 -*-
"""
    Resolver
    ~~~~~

    :copyright: (c) 2015 by Blockstack.org
    :license: MIT, see LICENSE for more details.
"""

from pymongo import MongoClient

db = MongoClient()['resolver_index']

namespaces = db.namespaces
profiles = db.profiles

namespaces.ensure_index('blocks')
profiles.ensure_index('username')
