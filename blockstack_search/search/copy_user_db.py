#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
	make a local copy of DB and run basic analytics
'''

REFRESH = True

import os 
import json

from pymongo import MongoClient
client = MongoClient()

db = client['onename_user_db']
local_users = db.users 

#-----------------------------------

MONGODB_URI = os.environ['MONGODB_URI']
OLD_DB = os.environ['OLD_DB']

remote_client = MongoClient(MONGODB_URI)
remote_db = remote_client.get_default_database()
users = remote_db.user

old_client = MongoClient(OLD_DB)
old_db = old_client.get_default_database()
old_users = old_db.user

#-----------------------------------
def get_old_db_users():

	github_count = 0
	twitter_count = 0
	website_count = 0
	bio_count = 0
	counter = 0

	for i in old_users.find(): 
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

		if counter % 100 == 0:
			print counter

		if REFRESH:
			local_users.insert(new_user)

	print '-' * 5
	print "Total users registered: " + str(counter) 
	print "Users with github accounts: " + str(github_count)
	print "Users with twitter accounts: " + str(twitter_count)
	print "Users with websites: " + str(website_count)
	print "Users with bios: " + str(bio_count)
	print '-' * 5

#-----------------------------------
def remove_duplicates():

	counter = 0 

	for i in users.find():

		username = i['username']

		temp = local_users.find_one({"username":username})

		if temp is not None:
			print temp['username']
			#local_users.remove(temp)

		counter += 1

		if counter % 100 == 0:
			print counter

#-----------------------------------
def drop_db():
	client.drop_database('onename_user_db')

#-----------------------------------
def get_new_db_users():

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
		profile = i['profile']

		if 'github' in profile:
			github_count += 1
		elif 'twitter' in profile:
			twitter_count += 1
		elif 'website' in profile:
			website_count += 1
		elif 'bio' in profile:
			bio_count += 1

		counter += 1

		if counter % 100 == 0:
			print counter

		if REFRESH:
			#pass
			local_users.insert(new_user)

	print '-' * 5
	print "Total users registered: " + str(counter) 
	print "Users with github accounts: " + str(github_count)
	print "Users with twitter accounts: " + str(twitter_count)
	print "Users with websites: " + str(website_count)
	print "Users with bios: " + str(bio_count)
	print '-' * 5

#-----------------------------------
if __name__ == '__main__':

	#get_old_db_users()

	#remove_duplicates()

	#get_new_db_users()

	print "read instructions before running"
