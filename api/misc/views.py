# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

import os, json, requests
from flask import jsonify

from . import v1misc
from ..errors import APIError
from ..crossdomain import crossdomain
from ..auth import auth_required

@v1misc.route('/versions', methods=['GET'])
@crossdomain(origin='*')
def versions():
    data = {
        'api': '1',
        'openname_specs': '0.2',
        'openname_directory': '0.1',
    }

    return jsonify(data), 200

