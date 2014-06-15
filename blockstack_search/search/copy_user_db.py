#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
	make a local copy of DB and run basic analytics
'''

REFRESH = False 

import os 
import json

from pymongo import MongoClient
client = MongoClient()
if REFRESH:
	client.drop_database('onename_user_db')
db = client['onename_user_db']
local_users = db.users 

#-----------------------------------
MONGODB_URI = os.environ['MONGODB_URI']
HEROKU_APP = os.environ['HEROKU_APP'] 
remote_client = MongoClient(MONGODB_URI)
users = remote_client[HEROKU_APP].user
private_key = remote_client[HEROKU_APP].private_key

#-----------------------------------
if __name__ == '__main__':

	github_count = 0
	twitter_count = 0
	website_count = 0
	bio_count = 0
	counter = 0

	for i in users.find(): 
		new_user = {}
		new_user['username'] = i['username']
		new_user['profile'] = i['profile']
		#print new_user
		#print '----'
		profile = json.loads(i['profile'])

		if 'github' in profile:
			github_count += 1
		elif 'twitter' in profile:
			twitter_count += 1
		elif 'website' in profile:
			website_count += 1
		elif 'bio' in profile:
			bio_count += 1

		counter += 1

		if REFRESH:
			local_users.insert(new_user)

	print '-' * 5
	print "Total users registered: " + str(counter) 
	print "Users with github accounts: " + str(github_count)
	print "Users with twitter accounts: " + str(twitter_count)
	print "Users with websites: " + str(website_count)
	print "Users with bios: " + str(bio_count)
	print '-' * 5
	