# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

import os, json, requests
from flask import render_template, send_from_directory, Response, url_for, \
	request, jsonify, make_response

from . import v1search
from ..errors import APIError
from ..decorators import access_token_required, parameters_required
from ..crossdomain import crossdomain

@v1search.route('/search', methods=['GET'])
@access_token_required
@parameters_required(parameters=['query'])
@crossdomain(origin='*')
def search_people():
	search_url = 'http://search.halfmoonlabs.com/search/name'

	name = request.values['query']

	try:
		results = requests.get(url=search_url, params={'query': name})
	except:
		raise APIError('Something went wrong', status_code=500)
	
	if results.status_code == 404:	
		raise APIError(status_code=404)
	else:
		return jsonify(results.json()), 200

	if not ('results' in results and isinstance(results['results'], list)):
		results = []
	else:
		results = results['results']

	return jsonify({'results': results}), 200