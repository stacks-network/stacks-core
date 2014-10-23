# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

from pymongo import MongoClient

c = MongoClient()
db = c['onename_api_devs']
