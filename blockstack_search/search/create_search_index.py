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
conn =  ES()

from pymongo import MongoClient
c = MongoClient()

INPUT_OPTIONS = '--create_index --search' 

from config import BULK_INSERT_LIMIT
from common import log

#-------------------------
def create_mapping(index_name,index_type):

	'''
		for creating lucene mapping
		can add different mappings for different index_types 
	'''

	try:
		#delete the old mapping, if exists
		conn.indices.delete_index(index_name)
	except:
		pass

	conn.indices.create_index(index_name)

	mapping = { u'full_name': {'boost': 3.0,
						'index': 'analyzed',
						'store': 'yes',
						'type': u'string',
						"term_vector" : "with_positions_offsets"}}

	conn.indices.put_mapping(index_type, {'properties':mapping}, [index_name])

#-------------------------
def create_people_index(): 

	create_mapping("onename_people_index","onename_people_type")

	from pymongo import MongoClient
	from bson import json_util
	import json 

	c = MongoClient()

	db = c['onename_search']
	nodes = db.nodes

	counter = 0
	#print(json.loads(profile_temp['value']))

	#for profile in nodes.find():
		#profile_dict = json.loads(profile)
	profile_temp = nodes.find_one({'name':"u/muneeb"})
	try:
			profile_details = json.loads(profile_temp['value'])
			name_dict = profile_details["name"]
			name = name_dict['formatted']
			print(name)

			conn.index({'full_name':name_dict['formatted'],'_boost' : 1,},
						"onename_people_index",
						"onename_people_type",
					bulk=True)
			counter += 1
			conn.indices.refresh(["onename_people_index"])
        
	except Exception as e:
			print e
	conn.indices.refresh(["onename_people_index"])
		#write in bulk
	if(counter % BULK_INSERT_LIMIT == 0):
			print '-' * 5
			print counter 
			conn.refresh(["onename_people_index"])

	#conn.indices.force_bulk()

	#print(profile['name'])

	"""
	for i in nodes.find():

		data = i['data']

		print i
			
		conn.index({'full_name' : i['data']['name']['full'],
					'bio' : i['data']['bio'],
					'data': json.dumps(i['data'], sort_keys=True, default=json_util.default),
					'_boost' : 1,},
					"fg_people_index",
					"fg_people_type",
					bulk=True)

		counter += 1

		conn.indices.refresh(["fg_people_index"])

		#write in bulk
		if(counter % BULK_INSERT_LIMIT == 0):
			print '-' * 5
			print counter 
			conn.refresh(["fg_people_index"])
			
	conn.indices.force_bulk()
	"""

#----------------------------------
def test_query(query,index=['onename_people_index']):

	q = StringQuery(query, search_fields = ['full_name', 'bio', 'data'], default_operator = 'and')
	count = conn.count(query = q)
	count = count.count 

	if(count == 0):
		q = StringQuery(query, search_fields = ['full_name', 'bio', 'data'], default_operator = 'or')
	
	results = conn.search(query = q, size=20, indices=index)

	counter = 0

	results_list = []

	for i in results:
		counter += 1
		print i['full_name']

		temp = json.loads(i['data'])

		results_list.append(temp)

	#print counter

	#print results_list 

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
