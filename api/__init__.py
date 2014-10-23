# -*- coding: utf-8 -*-
"""
    Onename API
    ~~~~~
"""

from flask import Flask

# Create app
app = Flask(__name__)

app.config.from_object('api.settings')

import docs
import search
import errors
import decorators
