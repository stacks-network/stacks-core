#!/usr/bin/env python
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

'''
	a simple Flask based API for OneName 
'''

from flask import request, jsonify, Flask

import json
from bson import json_util

DEFAULT_LIMIT = 30

#-----------------------------------
from pymongo import MongoClient
c = MongoClient()

#import pylibmc
"""mc = pylibmc.Client(["127.0.0.1:11211"],binary=True,
					behaviors={'tcp_nodelay':True,
								'connect_timeout':100,
								'no_block':True})"""

import threading

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
		#if(self.query_type == 'people_search'):
			#self.results = query_people_database(self.query, self.limit_results)
		#elif(self.query_type == 'company_search'):
			#self.found_exact_match, self.results = query_company_database(self.query)
		if(self.query_type == 'lucene_search'):
			self.results = query_lucene_index(self.query,'onename_people_index', self.limit_results)

#-------------------------
"""
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

		if(len(people) == 0):
			return results 
		else:
			db = c['onename_search']

			#the $in query is much faster but messes up intended results order
			reply = db.nodes.find({"details":{'$in':people}})

			#the reply is a cursor and need to load actual results first
			for i in reply:
				results.append(i['data'])

	temp = json.dumps(results, default=json_util.default)
	return json.loads(temp)

"""
#-----------------------------------
def query_lucene_index(query,index,limit_results=DEFAULT_LIMIT):

	from pyes import StringQuery, ES 
	conn =  ES()

	q = StringQuery(query, search_fields = ['full_name','twitter'], default_operator = 'and')
	results = conn.search(query = q, size=20, indices=[index])
	count = results.total

	#having or gives more results but results quality goes down
	if(count == 0):
		q = StringQuery(query, search_fields = ['full_name','twitter'], default_operator = 'or')
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
def get_people(query):

	new_limit = DEFAULT_LIMIT

	try:
		new_limit = int(request.values['limit_results'])
	except:
		pass

	results_people = []

	if test_alphanumeric(query) is False:
		pass
	else:

		threads = [] 

		t3 = QueryThread(query,'lucene_search',new_limit)

		threads.append(t3)

		#start all threads
		[x.start() for x in threads]

		#wait for all of them to finish
		[x.join() for x in threads] 

		#at this point all threads have finished and all queries have been performed
		
		results_lucene = t3.results 

		results_people += results_lucene


	results = {'people':results_people[:new_limit]}

	#mc.set(cache_key,results)

	return jsonify(results)

#-------------------------
def debug(query):

	return

#------------------

