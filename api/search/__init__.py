# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

from flask import Blueprint

v1search = Blueprint('v1search', __name__, url_prefix='/v1')

import views
