#!/usr/bin/env python
#-----------------------
# Copyright 2013 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

'''
	functions for substring search  
	usage: './substring_search --create_cache --search <query>'
'''

import sys
import json
from common import log 
from commontools import get_json

from pymongo import MongoClient
client = MongoClient()
db = client['onename_user_db']
local_users = db.users

from config import DEFAULT_LIMIT

import requests 
import re

#---------------------------------
def get_namespace():

	url = 'http://ons-server.halfmoonlabs.com/resolver/namespace'

	auth_user = 'opennamesystem'
	auth_passwd = 'opennamesystem'

	headers = {'Content-type': 'application/json'}

	try:
		r = requests.get(url, headers=headers, auth=(auth_user,auth_passwd))

	except requests.exceptions.RequestException as e:
		log.debug(e)
		log.debug('reindexing failed...exiting..')
		sys.exit(1)

	if (r.status_code == requests.codes.ok):
		resp = r.json()

		#preventing a response with a small dataset
		if ('results' in resp) and (len(resp['results']) > 20000):
			return resp['results']
		else:
			return None
	else:
		return None

#-------------------------
def valid_username(username):

	a = re.compile("^[a-z0-9_]{1,60}$")

	if a.match(username):
		return True
	else:
		return False

#-------------------------
def create_search_index(): 

	'''
		takes people names from blockchain and writes deduped names in a 'cache'
	'''

	user_data = get_namespace()

	if not user_data:
		log.debug('reindexing failed...exiting now...')
		sys.exit(1)

	#delete any old cache/index
	client.drop_database('search_db')
	client.drop_database('search_cache')

	search_db = client['search_db']
	search_profiles = search_db.profiles 

	search_cache = client['search_cache']
	people_cache = search_cache.people_cache
	twitter_cache = search_cache.twitter_cache
	username_cache = search_cache.username_cache

	#------------------------------
	# create people name cache 

	counter = 0

	people_names = []
	twitter_handles = []
	usernames = []


	for user in user_data:

		#the profile/info to be inserted
		search_profile = {} 
		
		counter += 1

		if(counter % 1000 == 0):
			print str(counter) + ' items indexed so far..' 

		if valid_username(user['username']):
			pass
		else:
			#print "ignoring: " + user['username']
			continue 
			

		profile = get_json(user['profile'])

		if 'name' in profile:
			name = profile['name']

			try:
				name = name['formatted'].lower()
			except:
				name = name.lower()

			people_names.append(name)
			search_profile['name'] = name

		else:
			search_profile['name'] = None


		if 'twitter' in profile:
			twitter_handle = profile['twitter']

			try:
				twitter_handle = twitter_handle['username'].lower()
			except:
				try:
					twitter_handle = profile['twitter'].lower()
				except:
					continue 

			twitter_handles.append(twitter_handle)
			search_profile['twitter_handle'] = twitter_handle

		else:
			search_profile['twitter_handle'] = None

		search_profile['username'] = user['username']
		usernames.append(user['username'])

		search_profile['profile'] = profile
		search_profiles.save(search_profile)


	#dedup names
	people_names = list(set(people_names))
	people_names = {'name':people_names}

	twitter_handles = list(set(twitter_handles))
	twitter_handles = {'twitter_handle':twitter_handles}

	usernames = list(set(usernames))
	usernames = {'username':usernames}

	#save final dedup results to mongodb (using it as a cache)
	people_cache.save(people_names)
	twitter_cache.save(twitter_handles)
	username_cache.save(usernames)

	search_cache.people_cache.ensure_index('name')
	search_cache.twitter_cache.ensure_index('twitter_handle')
	search_cache.username_cache.ensure_index('username')

	search_db.profiles.ensure_index('name')
	search_db.profiles.ensure_index('twitter_handle')
	search_db.profiles.ensure_index('username')
	
	log.debug('Created name/twitter/username search index')

#-------------------------
def anyword_substring_search_inner(query_word,target_words):

	'''
		return True if ANY target_word matches a query_word 
	''' 

	for target_word in target_words:

		if(target_word.startswith(query_word)):
			return query_word

	return False 

#-------------------------
def anyword_substring_search(target_words,query_words):

	'''
		return True if all query_words match 
	'''

	matches_required = len(query_words)
	matches_found = 0

	for query_word in query_words:

		reply = anyword_substring_search_inner(query_word,target_words) 

		if reply is not False:

			matches_found += 1

		else:
			#this is imp, otherwise will keep checking when the final answer is already False
			return False

	if(matches_found == matches_required):
		return True  
	else:
		return False

#-------------------------
def substring_search(query,list_of_strings,limit_results=DEFAULT_LIMIT): 

	'''
		main function to call for searching
	'''

	matching = []

	query_words = query.split(' ')
	#sort by longest word (higest probability of not finding a match)
	query_words.sort(key=len, reverse=True)

	counter = 0

	for s in list_of_strings:

		target_words = s.split(' ')
	
		#the anyword searching function is separate
		if(anyword_substring_search(target_words,query_words)):
			matching.append(s)

			#limit results
			counter += 1
			if(counter == limit_results):
				break

	return matching

#-------------------------
def search_people_by_name(query,limit_results=DEFAULT_LIMIT):

	query = query.lower()

	#---------------------
	#using mongodb as a cache, load data in people_names
	search_cache = client['search_cache']

	people_names = []

	for i in search_cache.people_cache.find():
		people_names += i['name']
	
	results = substring_search(query,people_names,limit_results)

	return order_search_results(query,results)

#-------------------------
def search_people_by_twitter(query,limit_results=DEFAULT_LIMIT):

	query = query.lower()

	#---------------------
	#using mongodb as a cache, load data 
	search_cache = client['search_cache']

	twitter_handles = []

	for i in search_cache.twitter_cache.find():
		twitter_handles += i['twitter_handle']
	#---------------------

	results = substring_search(query,twitter_handles,limit_results)

	return results

#-------------------------------------
def search_people_by_username(query,limit_results=DEFAULT_LIMIT):

	query = query.lower()

	#---------------------
	#using mongodb as a cache, load data 
	search_cache = client['search_cache']

	usernames = []

	for i in search_cache.username_cache.find():
		usernames += i['username']
	#---------------------

	results = substring_search(query,usernames,limit_results)

	return results

#---------------------------------------
def search_people_by_bio(query,limit_results=DEFAULT_LIMIT,index=['onename_people_index']):
	'''queries lucene index to find a nearest match, output is profile username''' 

	from pyes import QueryStringQuery, ES 
	conn =  ES()

	q = QueryStringQuery(query, search_fields = ['username','profile_bio'], default_operator = 'and')
	results = conn.search(query = q, size=20, indices=index)
	count = conn.count(query = q)
	count = count.count

	#having or gives more results but results quality goes down
	if(count == 0):
		q = QueryStringQuery(query, search_fields = ['username','profile_bio'], default_operator = 'or')
		results = conn.search(query = q, size=20, indices=index)		


	results_list = []
	counter = 0

	for profile in results:

		username = profile['username']
		results_list.append(username)

		counter += 1

		if(counter == limit_results):
			break

	return results_list
#-------------------------
def fetch_profiles(search_results,search_type="name"):

	search_db = client['search_db']
	search_profiles = search_db.profiles 

	results = [] 

	for search_result in search_results:

		if search_type == 'name':
			response = search_profiles.find({"name":search_result})
			
		elif search_type == 'twitter':
			response = search_profiles.find({"twitter_handle":search_result})
		
		elif search_type == 'username':
			response = search_profiles.find({"username":search_result})
		
		for result in response:

			try:
				del result['name']
				del result['twitter_handle']
				del result['_id']
			except:
				pass 

			results.append(result)

	return results 

#-------------------------
def order_search_results(query, search_results):

	'''
		order of results should be a) query in first name, b) query in last name
	'''

	results = search_results

	results_names = []
	old_query = query
	query = query.split(' ')

	first_word = ''
	second_word = ''
	third_word = ''

	if(len(query) < 2):
		first_word = old_query
	else:
		first_word = query[0]
		second_word = query[1]

		if(len(query) > 2): 
			third_word = query[2]

	#save results for multiple passes 
	results_second = []
	results_third = []

	#------------------------
	for result in results:

		result_list = result.split(' ')

		try:
			if(result_list[0].startswith(first_word)):
				results_names.append(result)
			else:
				results_second.append(result)
		except:
			results_second.append(result)

	#------------------------
	for result in results_second:

		result_list = result.split(' ')

		try:
			if(result_list[1].startswith(first_word)):
				results_names.append(result)
			else:
				results_third.append(result)
		except:
			results_third.append(result)
	#------------------------

	#results are either in results_names (filtered) or unprocessed in results_third (last pass)
	return results_names + results_third

#-------------------------
def dedup_search_results(search_results):
	'''
		dedup results
	'''

	known = set()
	deduped_results = []

	for i in search_results:

		username = i['username']
			
  		if username in known:
  			continue
  		
  		deduped_results.append(i)

  		known.add(username)

	return deduped_results

#-------------------------    
if __name__ == "__main__":

	if(len(sys.argv) < 2): 
		print "Usage error"

	option = sys.argv[1]

	if(option == '--create_index'):
		create_search_index()
	elif(option == '--search_name'):
		query = sys.argv[2]
		name_search_results = search_people_by_name(query,DEFAULT_LIMIT)
		print name_search_results
		print '-' * 5
		print fetch_profiles(name_search_results,search_type="name")
	elif(option == '--search_twitter'):
		query = sys.argv[2]
		twitter_search_results = search_people_by_twitter(query,DEFAULT_LIMIT)
		print twitter_search_results
		print '-' * 5
		print fetch_profiles(twitter_search_results,search_type="twitter")
	elif(option == '--search_username'):
		query = sys.argv[2]
		username_search_results = search_people_by_username(query,DEFAULT_LIMIT)
		print username_search_results
		print '-' * 5
		print fetch_profiles(username_search_results,search_type="username")
	elif(option == '--search_bio'):
		query = sys.argv[2]
		usernames_list = search_people_by_bio(query,DEFAULT_LIMIT)
		print usernames_list
		print '-' * 5
		print fetch_profiles(usernames_list,search_type="username")
	else:
		print "Usage error"

