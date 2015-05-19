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

# Add in blueprints
from .auth import v1auth

blueprints = [v1auth]

for blueprint in blueprints:
    app.register_blueprint(blueprint)

# Import views
import docs
import api_v1
