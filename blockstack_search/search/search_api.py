#!/usr/bin/env python
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

'''
	OneName Search 
'''

from flask import request, jsonify, Flask, make_response

app = Flask(__name__)

from config import DEFAULT_HOST, DEFAULT_PORT, DEBUG
import json
from bson import json_util

import sys
from config import DEFAULT_LIMIT

import pylibmc
mc = pylibmc.Client(["127.0.0.1:11211"],binary=True,
					behaviors={'tcp_nodelay':True,
								'connect_timeout':100,
								'no_block':True})

import threading

from substring_search import search_people_by_name, search_people_by_twitter, search_people_by_username, fetch_profiles

#-------------------------
#class for performing multi-threaded search on three search sub-systems
class QueryThread(threading.Thread):
	def __init__(self,query,query_type,limit_results):
		threading.Thread.__init__(self)
		self.query=query
		self.query_type=query_type
		self.results = [] 
		self.limit_results = limit_results
		self.found_exact_match = False

	def run(self):
		if(self.query_type == 'people_search'):
			self.results = query_people_database(self.query, self.limit_results)
		elif(self.query_type == 'twitter_search'):
			self.results = query_twitter_database(self.query, self.limit_results)
		elif(self.query_type == 'username_search'):
			self.results = query_username_database(self.query, self.limit_results)
			#self.found_exact_match, self.results = query_company_database(self.query)
		#if(self.query_type == 'lucene_search'):
		#	self.results = query_lucene_index(self.query,'onename_people_index', self.limit_results)

#---------------------------------
def error_reply(msg, code = -1):
	reply = {}
	reply['status'] = code
	reply['message'] = "ERROR: " + msg
	return jsonify(reply)

#-------------------------
def query_people_database(query,limit_results=DEFAULT_LIMIT):

	name_search_results = search_people_by_name(query, limit_results)
	return fetch_profiles(name_search_results,search_type="name")

#-------------------------
def query_twitter_database(query,limit_results=DEFAULT_LIMIT):

	twitter_search_results = search_people_by_twitter(query, limit_results)
	return fetch_profiles(twitter_search_results,search_type="twitter")

#-------------------------
def query_username_database(query,limit_results=DEFAULT_LIMIT):

	username_search_results = search_people_by_username(query, limit_results)
	return fetch_profiles(username_search_results,search_type="username")

"""
#-----------------------------------
def query_lucene_index(query,index,limit_results=DEFAULT_LIMIT):

	from pyes import StringQuery, ES 
	conn =  ES()

	q = StringQuery(query, search_fields = ['full_name','twitter','bitcoin'], default_operator = 'and')
	results = conn.search(query = q, size=20, indices=[index])
	count = results.total

	#having or gives more results but results quality goes down
	if(count == 0):
		q = StringQuery(query, search_fields = ['full_name','twitter','bitcoin'], default_operator = 'or')
		results = conn.search(query = q, size=20, indices=[index])		
		
	results_list = []
	counter = 0

	for i in results:

		temp = json.loads(i['details'])
		results_list.append(temp)

		counter += 1

		if(counter == limit_results):
			break

	return results_list 
"""

#----------------------------------
def test_alphanumeric(query):

	'''
		check if query has only alphanumeric characters or not 
	'''

	import re
	valid = re.match('^(\w+(\s)*\w*)+$', query) is not None

	#return valid 
	return True 

#-----------------------------------
@app.route('/search/name')
def search_by_name():

	query = request.args.get('query')

	results_people = []

	if query == None:
		return error_reply("No query given")
	elif query == '' or query == ' ':
		return json.dumps({})

	cache_key = str('onename_cache_' + query.lower())
	cache_reply = mc.get(cache_key)

	#if a cache hit, respond straight away
	if(cache_reply != None):
		return jsonify(cache_reply)

	new_limit = DEFAULT_LIMIT

	try:
		new_limit = int(request.values['limit_results'])
	except:
		pass

	if test_alphanumeric(query) is False:
		pass
	else:

		threads = [] 

		t1 = QueryThread(query,'username_search',new_limit)
		t2 = QueryThread(query,'twitter_search',new_limit)
		t3 = QueryThread(query,'people_search',new_limit)

		threads.append(t1)
		threads.append(t2)
		threads.append(t3)

		#start all threads
		[x.start() for x in threads]

		#wait for all of them to finish
		[x.join() for x in threads] 

		#at this point all threads have finished and all queries have been performed
		
		results_username = t1.results
		results_twitter = t2.results
		results_people = t3.results 

		results_people += results_username + results_twitter + results_people

		#dedup all results before sending out
		from substring_search import dedup_search_results
		results_people = dedup_search_results(results_people)

	results = {}
	results['results'] = results_people[:new_limit]

	#print results
	mc.set(cache_key,results)

	return jsonify(results)

#-----------------------------------
@app.route('/')
def index():
	return 'Welcome to the search API server of <a href="http://halfmoonlabs.com">Halfmoon Labs</a>.'

#-----------------------------------
@app.errorhandler(500)
def internal_error(error):

	reply = []
	return json.dumps(reply)

#-----------------------------------
@app.errorhandler(404)
def not_found(error):
	return make_response(jsonify( { 'error': 'Not found' } ), 404)

#-----------------------------------
if __name__ == '__main__':

	app.run(host=DEFAULT_HOST, port=DEFAULT_PORT,debug=DEBUG)