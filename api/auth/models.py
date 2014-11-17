# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

import json, datetime, binascii
from utilitybelt import dev_random_entropy, dev_urandom_entropy

from ..db import db

class User(db.Document):
    # metadata
    created_at = db.DateTimeField(default=datetime.datetime.now, required=True)
    # account/auth data
    email = db.StringField(max_length=255, unique=True, required=True)
    # api keys
    app_id = db.StringField(max_length=255, unique=True, required=True)
    app_secret = db.StringField(max_length=255, unique=True)
    app_secret_hash = db.StringField(max_length=255, unique=True, required=True)
    request_count = db.IntField(min_value=0, default=0)

