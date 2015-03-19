# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

from . import app

# MongoDB + MongoEngine
from mongoengine import connect
from flask.ext.mongoengine import MongoEngine

db = MongoEngine(app)
