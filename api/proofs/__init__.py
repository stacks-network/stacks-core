# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

from flask import Blueprint

v1proofs = Blueprint('v1proofs', __name__, url_prefix='/v1')

import views
