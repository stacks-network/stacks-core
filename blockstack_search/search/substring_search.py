#!/usr/bin/env python
#-----------------------
# Copyright 2013 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

'''
	functions for substring search  
'''
import sys

from pymongo import MongoClient
c = MongoClient()

from config import DEFAULT_LIMIT

INPUT_OPTIONS = '--create_cache --search <query>'

#-------------------------
def create_dedup_names_cache(): 
	 
	'''
		takes people/company names from crunchbase DB and writes deduped names in a 'cache'
	'''

	fg = c['freegraph']

	#delete any old cache
	c.drop_database('fg_search_cache')

	search_cache = c['fg_search_cache']
	people_cache = search_cache.people_cache

	nodes = fg.nodes
	
	#------------------------------
	#for creating people cache 

	counter = 0

	people_names = [] 

	for i in nodes.find():

		counter += 1

		if(counter % 1000 == 0):
			print counter

		try:
			name = i['data']['name']['first'].lower() + ' ' + i['data']['name']['last'].lower()  
		except:
			pass
		else:
			people_names.append(name)


	dedup_people_names = list(set(people_names))

	insert_people_names = {'dedup_people_names':dedup_people_names}

	#save final dedup results to mongodb (using it as a cache)
	people_cache.save(insert_people_names)

	#print '-' * 5
	#log.debug('Created deduped people_cache: %s from %s', len(dedup_people_names), len(people_names))
	#log.debug('Creating company cache ...')

	#db.posts.ensure_index('full_name')
	#log.debug('DONE! All set for searching now.')

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
	search_cache = c['fg_search_cache']

	people_names = []

	for i in search_cache.people_cache.find():
		people_names = i['dedup_people_names']
	#---------------------

	results = substring_search(query,people_names,limit_results)

	return results

#-------------------------
def fix_search_order(query, search_results):

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

		result_list = result['full_name'].split(' ')

		try:
			if(result_list[0].startswith(first_word)):
				results_names.append(result)
			else:
				results_second.append(result)
		except:
			results_second.append(result)

	#------------------------
	for result in results_second:

		result_list = result['full_name'].split(' ')

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
		dedup results based on 'slug'
	'''

	known_links = set()
	deduped_results = []

	for i in search_results:

		link = i['url']
			
  		if link in known_links: 
  			continue
  		
  		deduped_results.append(i)

  		known_links.add(link)

	return deduped_results

#-------------------------    
if __name__ == "__main__":

	try:

		if(len(sys.argv) < 2): 
			print "Usage error"

		option = sys.argv[1]

		if(option == '--create_cache'):
			create_dedup_names_cache()
		elif(option == '--search'):
			query = sys.argv[2]
			print search_people_by_name(query,DEFAULT_LIMIT)

		else:
			print "Usage error"

	except Exception as e:
		print e 
