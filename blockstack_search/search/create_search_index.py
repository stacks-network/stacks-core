#!/usr/bin/env python
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

'''
	functions for building the ES/lucene search index and mappings   
'''
import sys,json
from pyes import *
conn = ES()

from pymongo import MongoClient
c = MongoClient()

INPUT_OPTIONS = '--create_index --search' 

from config import BULK_INSERT_LIMIT
from common import log

#-------------------------
def create_mapping(index_name,index_type):

	'''
		create lucene index and add/specify document type 
	'''

	try:
		#delete the old mapping, if exists
		conn.indices.delete_index(index_name)
	except:
		pass

	conn.indices.create_index(index_name)

	mapping = {u'profile_username': {'boost': 2.0,
						'index': 'analyzed',
						'store': 'yes',
						'type': u'string',
						"term_vector" : "with_positions_offsets"},
				u'profile_fullname': {'boost': 1.0,
						'index': 'analyzed',
						'store': 'yes',
						'type': u'string',
						"term_vector" : "with_positions_offsets"},
				u'profile_bio': {'boost': 3.0,
						'index': 'analyzed',
						'store': 'yes',
						'type': u'string',
						"term_vector" : "with_positions_offsets"}}

	conn.indices.put_mapping(index_type, {'properties':mapping}, [index_name])

#-------------------------
def create_people_index():

	'''
		create a lucene index from exisitng user data in mongodb  
	''' 

	create_mapping("onename_people_index","onename_profiles")
	conn.default_indices=["onename_people_index"]

	#-------------------------
	from pymongo import MongoClient
	from bson import json_util
	import json 

	mc = MongoClient()
	db = mc['search_db']

	counter = 0
	profile_bio = ''


	for profile in db.profiles.find():
		profile_data = profile['profile']

		if type(profile_data) is dict:
			profile_bio = profile_data.get('bio',None)

		if profile_bio:	
			try:
				res = conn.index({
					"profile_username": profile_data.get('username',None),
					"profile_fullname":profile_data.get('name',None),
					'profile_twitter_handle':profile_data.get('twitter_handle',None),
				'profile_bio': profile_bio,
				'_boost' : 3,},
				"onename_people_index","onename_profiles",bulk=True)

				counter += 1

			except Exception as e:
				print e

		if(counter % BULK_INSERT_LIMIT == 0):
			print '-' * 5
			print 'items indexed so far:' + str(counter) 
			print '-' * 5
				
			conn.indices.refresh(["onename_people_index"])
		conn.force_bulk()
			
#----------------------------------
def test_query(query,index=['onename_people_index']):

	q = QueryStringQuery(query, search_fields = ['profile_bio','profile_username'], default_operator = 'and')
	count = conn.count(query = q)
	count = count.count 

	if(count == 0):
		q = QueryStringQuery(query, search_fields = ['profile_bio','profile_username'], default_operator = 'or')
	
	#q = TermQuery("profile_bio",query)
	results = conn.search(query = q, size=20, indices=index)

	counter = 0

	results_list = []

	for i in results:
		counter += 1
		print i

		#temp = json.loads(i['details'])

		#results_list.append(temp)

	#print counter

	print results_list

#-------------------------    
if __name__ == "__main__":

	try:

		if(len(sys.argv) < 2): 
			print "Usage error"

		option = sys.argv[1]
	
		if(option == '--create_index'):
			create_people_index()
		elif(option == '--search'):
			test_query(query=sys.argv[2])
		else:
			print "Usage error"
			
	except Exception as e:
		print e
