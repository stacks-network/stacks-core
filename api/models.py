# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

import datetime
from db import db


class User(db.Document):
    # metadata
    created_at = db.DateTimeField(default=datetime.datetime.now, required=True)
    # account/auth data
    username = db.StringField(max_length=255, required=True)
    profile = db.StringField(required=True)
    transfer_address = db.StringField(max_length=255, required=True)