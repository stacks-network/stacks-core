
#!/usr/bin/env python
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

'''
	Developer  API -- powers onename Search  
'''

from flask import request, jsonify, Flask
from search_api import get_people
from flask import make_response,Response
import json
from bson import json_util
from rate_limit import *

app = Flask(__name__)

DEFAULT_LIMIT = 35

from pymongo import MongoClient
c = MongoClient()

#----------------------------------------------
#Create Developer Account
#saves the user and generates the access_token
#----------------------------------------------
@app.route('/v1/gen_developer_key/', methods = ['GET'])
def create_account():
	#saves the ID and returns the access token
	request_val = request.values
	if 'developer_id' in request_val:
		access_token = save_user(request.values['developer_id'], 'basic')
	else:
		return make_response(jsonify( {'error': 'Invalid Request' } ), 400)

	return jsonify({'developer_id':request.values['developer_id'],
					  'access_token':access_token})

#----------------------------------------------
#Search API 
#The Search API returns the profiles based on keyword saerches.
#Results are retrieved through indexed data
#----------------------------------------------
@app.route('/v1/people-search/', methods = ['GET'])
def search_people():

	request_val = request.values
	access_token = ""

	if 'access_token' in request_val:
		access_token = request.values['access_token']
	else:
		return make_response(jsonify( { 'error': 'access token is missing' } ), 400)

	#1. verify access_token
	if not validate_token(access_token):
		return make_response(jsonify( { 'error': 'Invalid Token' } ), 400)

	#2. verify available quota and decrement
	if not verify_and_decrement_quota(access_token):
		return make_response(jsonify( { 'error': 'Quota Exceeded' } ), 401)
	
	results = ""
	
	#handle keyword search
	if 'keywords' in request_val:
		results = get_people(request.values['keywords'])
	elif 'full-name' in request_val:
		results = get_people(request.values['full-name'])
	elif 'twitter' in request_val:
		results = get_people(request.values['twitter'])
	elif 'btc_address' in request_val:
		results = get_people(request.values['btc_address'])
	else:
		return make_response(jsonify( { 'error': 'invalid request' } ), 401)

	if results == "" or results == None:
		return make_response(jsonify( { 'error': 'invalid request' } ), 401)
	else:
		return results

#---------------------------------------------
#Profile API 
#The Profile API returns the public Onename profile based.
#Results are retrieved from the onename_db
#---------------------------------------------
@app.route('/v1/people/', methods = ['GET'])
def get_onename_profile():

	request_val = request.values
	access_token = ""

	if 'access_token' in request_val:
		access_token = request.values['access_token']
	else:
		return make_response(jsonify({ 'error': 'access token is missing' }), 400)

	#verify access_token
	if not validate_token(access_token):
		return make_response(jsonify( { 'error': 'invalid token' } ), 402)

	#verify available quota and decrement if available
	if not verify_and_decrement_quota(access_token):
		return make_response(jsonify( { 'error': 'quota exceeded' } ), 401)

	if 'onename_id' in request_val:
		onename_id = request.values['onename_id']
		#returns onename_profile
		profile = query_people_database(onename_id)
	else:
		return make_response(jsonify( { 'error': 'onename_id is missing' } ), 400)

	
	
	if profile is not None:
		return json.dumps(profile)
	else:
		return make_response(jsonify( { 'error': 'profile not found' } ), 401)

#----------------------untested--not working----------------------
@app.route('/v1/people/url=<onename_profile_url>', methods = ['GET'])
def get_profile_from_url(onename_profile_url):
	#untested
	return ""#jsonify(query_people_database(onename_profile_url))

#-------------------------------------------
def query_people_database(onename_id,limit_results=DEFAULT_LIMIT):

	db = c['onename_search']
	
	nodes = db.nodes

	onename_profile = nodes.find_one({"name": 'u/' + onename_id})
	#onename_profile = nodes.find({'value': {"$elemMatch": {"website":"http://muneebali.com"} }})
	if onename_profile is None:
		return None
	else:
		profile_details = json.loads(onename_profile['value'])

	return profile_details

#custom error handling to return JSON error msgs
#----------------------------------------------
@app.errorhandler(404)
def not_found(error):
    '''
    Returns a jsonified 404 error message instead of a HTTP 404 error.
    '''
    return make_response(jsonify({ 'error': '404 not found' }), 404)

#----------------------------------------------
@app.errorhandler(503)
def not_found(error):
    '''
    Returns a jsonified 503 error message instead of a HTTP 404 error.
    '''
    return make_response(jsonify({ 'error': '503 something wrong' }), 503)

#----------------------------------------------
@app.errorhandler(500)
def not_found(error):
    '''
    Returns a jsonified 500 error message instead of a HTTP 404 error.
    '''
    return make_response(jsonify({ 'error': '500 something wrong' }), 500)
    
#----------------------------------------------
if __name__ == '__main__':
	app.run(debug=True, port=5003)

