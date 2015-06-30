# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

import json
import datetime
import binascii
from db import db


class Passcard(db.Document):
    # metadata
    created_at = db.DateTimeField(default=datetime.datetime.now, required=True)
    # account/auth data
    passname = db.StringField(max_length=255, required=True)
    payload = db.StringField(required=True)
    transfer_address = db.StringField(max_length=255, required=True)
