# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

import datetime
from db import db


# note there already exists an object class "User" in api/auth/models.py

class Blockchainid(db.Document):
    # metadata
    created_at = db.DateTimeField(default=datetime.datetime.now, required=True)
    # account data
    username = db.StringField(max_length=255, required=True)
    profile = db.StringField(required=True)
    transfer_address = db.StringField(max_length=255, required=True)