# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""
import os
from pymongo import MongoClient

from . import app

client = MongoClient(app.config['MONGODB_HOST'], app.config['MONGODB_PORT'])
db = client[app.config['MONGODB_DB']]

db.authenticate(app.config['MONGODB_USERNAME'], app.config['MONGODB_PASSWORD'])
