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
import views

# Add in blueprints
from .docs import docs
from .auth import v1auth
from .profile import v1profile
from .proofs import v1proofs
from .search import v1search
from .misc import v1misc

blueprints = [
    docs,
    v1auth, v1profile, v1proofs, v1search, v1misc
]

for blueprint in blueprints:
    app.register_blueprint(blueprint)
