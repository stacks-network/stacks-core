# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2015 Halfmoon Labs, Inc.
    ~~~~~
"""

from . import app

# MongoDB database for API account registrations
from mongoengine import connect
from flask.ext.mongoengine import MongoEngine

db = MongoEngine(app)

# MongoDB database for register queue, utxo index, etc.
from pymongo import MongoClient
from .settings import MONGODB_URI, INDEX_DB_URI, RESOLVER_URL, SEARCH_URL

namecoin_index = MongoClient(INDEX_DB_URI)['namecoin_index']
utxo_index = namecoin_index.utxo
address_to_utxo = namecoin_index.address_to_utxo
address_to_keys = namecoin_index.address_to_keys_new
