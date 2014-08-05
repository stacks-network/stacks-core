#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from pymongo import MongoClient
from register import process_user, utf8len
from coinrpc import namecoind 
from config import MONGODB_URI

import os 

LOAD_BALANCER = os.environ['LOAD_BALANCER']

remote_client = MongoClient(MONGODB_URI)
remote_db = remote_client.get_default_database()
users = remote_db.user
private_key = remote_client.private_key

from datetime import datetime

#-----------------------------------
def update_profile(username,profile):
 
	#update_name does json.dumps internally
	process_user(username,profile)

#-----------------------------------
def update_profile_from_DB(username):

	entry = users.find_one({'username':username})

	profile = json.loads(entry['profile'])

	#print profile
	update_profile(username,profile)

#-----------------------------------
def update_profile_from_file(username,file_name='tools/json_profile.json'):

	json_data=open(file_name)

	try:
		profile = json.load(json_data)
	except Exception as e:
		print e
		return 

	update_profile(username,profile)

#-----------------------------------
def private_key_expired(time):
	
	now = datetime.now()
	diff = now - time
	day_diff = diff.days

	if diff.days < -1:
		return True
	else:
		return False

#-----------------------------------
def delete_expired_private_keys():
	print "Private keys: "
	for user in private_key.find():

		print user['username']
		if private_key_expired(user['created_at']):
			private_key.remove(user)
			
	print '-' * 5
	
#-----------------------------------
def update_profile_from_private_key(username):

	user_private_key = private_key.find_one({"username":username})
	user = users.find_one({"username":username})

	if ('backend_server' in user) and (user['backend_server'] == int(LOAD_BALANCER)):
		process_user(user['username'],json.loads(user['profile']))
		user['profile_update_pending'] = False
		users.save(user)
		private_key.remove(user_private_key)

#-----------------------------------
def process_profile_updates():
	
	print "Profile update pending: "
	for user in users.find(): 

		if 'name_transferred' in user and user['name_transferred'] is True:
			#print "name already transferred: " + user['username']
			continue 

		if 'profile_update_pending' in user and user['profile_update_pending']:

			if not namecoind.check_registration('u/' + user['username']):
				print "Not registered yet: " + user['username']
				continue
			else:
				print "Updating user: " + user['username']
				print user['backend_server']
				update_profile_from_private_key(user['username'])

	print '-' * 5

	#delete_expired_private_keys()

#-----------------------------------
if __name__ == '__main__':

	username = 'gordonhall'
	#user = users.find_one({"username":username})
	#print user['backend_server'] 
	#update_profile_from_DB(username)
	update_profile_from_file(username)
	#process_profile_updates()