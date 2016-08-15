# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2015 Halfmoon Labs, Inc.
    ~~~~~
"""

import traceback
from pymongo import MongoClient

# MongoDB database for API account registrations
from mongoengine import connect
from flask.ext.mongoengine import MongoEngine

from . import app


try:
    connect(app.config['API_DB_NAME'], host=app.config['API_DB_URI'])
    db = MongoEngine(app)
    db_client = MongoClient(app.config['API_DB_URI'])[app.config['API_DB_NAME']]
except Exception as e:
    traceback.print_exc()
    print app.config['API_DB_URI']
