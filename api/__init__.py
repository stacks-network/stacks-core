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

import errors
import decorators
import views

from .docs import docs
from .v1 import v1

blueprints = [
	docs, v1
]

for blueprint in blueprints:
    app.register_blueprint(blueprint)
