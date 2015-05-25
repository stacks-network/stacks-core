# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

from flask import Flask, Blueprint
from https import RequireHTTPS

# Create app
app = Flask(__name__)

app.config.from_object('api.settings')

if app.config.get('DEBUG') is False:
    RequireHTTPS(app)

# Add in blueprints
from .auth import v1auth

blueprints = [v1auth]

for blueprint in blueprints:
    app.register_blueprint(blueprint)

# Import views
import index
import api_v1
