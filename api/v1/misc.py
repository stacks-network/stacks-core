# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

from flask import jsonify

from . import v1
from ..decorators import parameters_required

@v1.route('/latestversions', methods=['GET'])
def latest_versions():
	payload = {
		'onename_api': '1',
		'ons_specs': '0.3',
		'ons_directory': '0.1',
		'ons_server': '0.1'
	}
	return jsonify(payload), 200
