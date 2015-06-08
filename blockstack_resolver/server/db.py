# -*- coding: utf-8 -*-
"""
    BNS Resolver
    ~~~~~

    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

from pymongo import MongoClient

db = MongoClient()['resolver_index']

namespaces = db.namespaces
profiles = db.profiles

namespaces.ensure_index('blocks')
profiles.ensure_index('username')