# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

from flask import request, jsonify

from . import v1
from ..rate_limit import save_user
from ..decorators import parameters_required

@v1.route('/gen_developer_key/', methods=['GET'])
@parameters_required(parameters=['developer_id'])
def create_account():
	""" creates a new dev. account
	"""
	access_token = save_user(request.values['developer_id'], 'basic')

	return jsonify({'developer_id': request.values['developer_id'],
					'access_token': access_token}), 200
