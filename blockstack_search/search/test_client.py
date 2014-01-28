#!/usr/bin/env python
#-----------------------
# Copyright 2013 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

'''
	For testing the search API from command line 
'''

import sys
import requests
import json  

#-------------------------
def search_client(query,server):

 
 	print '-' * 10
 	print "Searching for: " + query
	print '-' * 10

	url = 'http://localhost:5000/search/people'

	if(server == 'remote'):
		url = 'http://54.200.209.148/search/people'
	
	print url 

	data = {'query': query, 'limit_results': 35}
	
	headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

	r = requests.get(url, params=data, headers=headers)

	print r 

	temp = r.json()

	print '-' * 10

	print "People: "

	for i in temp['people']:

		print i
		#print i['first_name'] + ' ' + i['last_name'] + ' | ' + 'http://www.crunchbase.com/person/' + i['crunchbase_slug']

	if(len(temp['companies']) > 0):

		print '-' * 10
		print "Companies: "

		for i in temp['companies']:
			print i
		
	print '-' * 10

#-------------------------    
if __name__ == "__main__":

	if(len(sys.argv) < 2): print "Error more arguments needed"

	query=sys.argv[1]
	server = 'local'

	try:
		server = sys.argv[2] 
	except:
		pass

	search_client(query, server)