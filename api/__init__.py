# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

from flask import Flask, Blueprint

# Create app
app = Flask(__name__)

app.config.from_object('api.settings')

from flask_sslify import SSLify
import os

if 'DYNO' in os.environ:
    sslify = SSLify(app)

# Import functions
import main

# Add in blueprints
from .docs import docs
from .auth import v1auth

blueprints = [
    docs, v1auth
]

for blueprint in blueprints:
    app.register_blueprint(blueprint)
