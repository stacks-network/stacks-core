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

# Import functions
import views

# Add in blueprints
from .docs import docs
from .auth import v1auth
from .profile import v1profile
from .proofs import v1proofs
from .search import v1search

blueprints = [
    docs,
    v1auth, v1profile, v1proofs, v1search
]

for blueprint in blueprints:
    app.register_blueprint(blueprint)
