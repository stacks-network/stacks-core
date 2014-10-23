#!/usr/bin/env python
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

'''
	OneName Developer API  
'''

import os, json
from flask import render_template, send_from_directory, Response, url_for, \
	request, jsonify, make_response
from pymongo import MongoClient

from . import app
import rate_limit

#----------------------------------------------
@app.route('/onename/api/v1.0/gen_developer_key/', methods = ['GET'])
def create_account():
	""" creates a new dev. account
	"""
	
	#saves the ID and returns the access token
	request_val = request.values

	if 'developer_id' in request_val:
		access_token = rate_limit.save_user(request.values['developer_id'], 'basic')
	
	else:
		return make_response(jsonify( {'error': 'Invalid Request' } ), 400)

	return jsonify({'developer_id':request.values['developer_id'],
					  'access_token':access_token})

#--------------------------------------
@app.route('/onename/api/v1.0/people-search/', methods = ['GET'])
def search_people():
	
	import requests

	request_val = request.values
	access_token = ""

	if 'access_token' in request_val:
		access_token = request.values['access_token']
	
	else:
		return make_response(jsonify({'error': 'access Token is missing' }), 400)

	if not rate_limit.validate_token(access_token):
		return make_response(jsonify( { 'error': 'Invalid Token' } ), 400)

	if not rate_limit.decrement_quota(access_token):
		return make_response(jsonify( { 'error': 'Quota Exceeded' } ), 401)
	
	results = ""
	
	#handle keyword search
	if 'name' in request_val:
		search_name = request.values['name']

		search_url = 'http://search.halfmoonlabs.com/search/name'

		try:
			results = requests.get(url=search_url, params = {'query':search_name})
		except:
			return make_response(jsonify( { 'error': 'Internal Error' } ), 500)
		
		if results.status_code == 404:	
			return make_response(jsonify( { 'error': 'Internal Error' } ), 500)	
		else:
			return jsonify(results.json())

	else:
		return make_response(jsonify( { 'error': 'Name is missing' } ), 401)

	if results == "" or results == None:
		return make_response(jsonify({ 'empty': 'nothing found' }))
	else:
		return results

# error handlers
#-----------------------------------
@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

#-----------------------------------
@app.errorhandler(500)
def internal_error(error):

	reply = []
	return json.dumps(reply)

