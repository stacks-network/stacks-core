# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

from flask import Flask

# Create app
app = Flask(__name__)

app.config.from_object('api.settings')

import docs
import auth
import errors
import decorators
import search
import profile

