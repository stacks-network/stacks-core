# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

from flask import Blueprint

v1auth = Blueprint('v1auth', __name__, url_prefix='')

import views
