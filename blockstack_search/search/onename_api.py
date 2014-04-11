
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
from flask import make_response
import json
from bson import json_util
from helpers import *

app = Flask(__name__)

DEFAULT_LIMIT = 35

from pymongo import MongoClient
c = MongoClient()
#----------------------------------------------
@app.route('/v1/gen_developer_key/<developer_id>', methods = ['GET'])
def create_account(developer_id):
	#saves the ID and returns the access token
	return save_user(developer_id, 'basic')

#----------------------------------------------
#Search API 
#The Search API returns the profiles based on keyword saerches.
#Results are retrieved through indexed data
#----------------------------------------------
@app.route('/v1/people-search/<developer_id>/<access_token>', methods = ['GET'])
def search_people(developer_id,access_token):
	#1. verify key
	if not is_key_valid(access_token):
		return make_response(jsonify( { 'error': 'Invalid Token' } ), 400)

	#2. verify available quota
	if is_overquota(developer_id):
		return make_response(jsonify( { 'error': 'Quota Exceeded' } ), 401)
	
	#TODO: Add error handling if keywords is missing
	query = request.values['keywords']

	results = get_people(query)

	return results

#----------------------------------------------
#Profile API 
#The Profile API returns the public Onename profile based.
#Results are retrieved from the onename_db
#-----------------------untested-not working---------------------
@app.route('/v1/people/id=<onename_id>', methods = ['GET'])
def get_onename_profile(onename_id):
	#untested
	return str(query_people_database(onename_id))

#----------------------untested--not working----------------------
@app.route('/v1/people/url=<onename_profile_url>', methods = ['GET'])
def get_profile_from_url(onename_profile_url):
	#untested
	return query_people_database(onename_profile_url)

#custom error handling to return JSON error msgs
#----------------------------------------------
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify( { 'error': 'Not found' } ), 404)

#----------------------untested---not working---------------------
def query_people_database(query,limit_results=DEFAULT_LIMIT):

	'''
		returns True, {names of employees} if exact match of company name
		else returns False, [list of possible companies]  
	'''
	

	from substring_search import search_people_by_name

	people = search_people_by_name(query, limit_results)

	results = []
	mongo_query = []
	
	if people is not None:
		
		if (len(people) == 0):
			return results 
		else:
			db = c['onename_search']
			db.nodes.find_one({'username' : username})

			#the $in query is much faster but messes up intended results order
			#reply = db.nodes.find({"value":{name:query}})

			#the reply is a cursor and need to load actual results first
			#for i in reply:
				#results.append(i)

	#temp = json.dumps(results, default=json_util.default)
	
	return results

#----------------------------------------------
if __name__ == '__main__':
	app.run(debug=True, port=5003)

