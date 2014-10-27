# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

from . import app

#from pymongo import MongoClient
#client = MongoClient(app.config['MONGODB_HOST'], app.config['MONGODB_PORT'])
#db = client[app.config['MONGODB_DB']]
#db.authenticate(app.config['MONGODB_USERNAME'], app.config['MONGODB_PASSWORD'])

# MongoDB + MongoEngine
from mongoengine import connect
from flask.ext.mongoengine import MongoEngine

if 'MONGODB_URI' in app.config:
    connect(app.config['MONGODB_DB'], host=app.config['MONGODB_URI'])
db = MongoEngine(app)
