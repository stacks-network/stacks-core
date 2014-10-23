#!/usr/bin/env python
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

'''
	OneName Developer API  
'''

import os, json, requests
from flask import render_template, send_from_directory, Response, url_for, \
	request, jsonify, make_response
from pymongo import MongoClient

from . import app
from .errors import APIError
from .decorators import access_token_required, parameters_required
from rate_limit import save_user

@app.route('/v1.0/gen_developer_key/', methods=['GET'])
@parameters_required(parameters=['developer_id'])
def create_account():
	""" creates a new dev. account
	"""
	access_token = save_user(request.values['developer_id'], 'basic')

	return jsonify({'developer_id': request.values['developer_id'],
					'access_token': access_token}), 200

@app.route('/v1.0/search', methods=['GET'])
@access_token_required
@parameters_required(parameters=['query'])
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

