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

connect(app.config['API_DB_NAME'], host=app.config['API_DB_URI'])
db = MongoEngine(app)
