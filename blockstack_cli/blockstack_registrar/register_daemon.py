#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

import os
import json

from config import MONGODB_URI, LOAD_BALANCER, OLD_DB

from coinrpc.namecoin.namecoind_wrapper import namecoind_name_show, get_full_profile
from blockdata.register import process_user

from pymongo import MongoClient
from bson.objectid import ObjectId

from encrypt.bip38 import bip38_decrypt

import datetime
import hashlib

#-----------------------------------
remote_client = MongoClient(MONGODB_URI)
remote_db = remote_client.get_default_database()
users = remote_db.user
registrations = remote_db.user_registration
updates = remote_db.profile_update

old_client = MongoClient(OLD_DB)
old_db = old_client.get_default_database()
print old_db.collection_names()
old_users = old_db.user

local_client = MongoClient() 
local_db = local_client['namecoin']
queue = local_db.queue

#-----------------------------------
def profile_on_blockchain(username,DB_profile):

	block_profile = get_full_profile('u/' + username)
	block_profile = json.dumps(block_profile,sort_keys=True)
	DB_profile = json.dumps(DB_profile,sort_keys=True)

	if len(block_profile) == len(DB_profile):
		#check hash for only profiles where length is the same
		if hashlib.md5(block_profile).hexdigest() == hashlib.md5(DB_profile).hexdigest():
			return True
		else:
			return False 
	else:
		return False

#-----------------------------------
def process_users(): 

	CHECK_BLOCKCHAIN = False

	for new_user in registrations.find():

		user_id = new_user['user_id']
		user = users.find_one({"_id":user_id})

		if 'stormtrooper' in user['username'] or 'clone' in user['username']:
			continue
			
		if 'dispatched' in new_user and new_user['dispatched'] is False: 
	
			if datetime.datetime.utcnow() - new_user['created_at'] > datetime.timedelta(minutes=15):
				print "Dispatch: " + user['username']
				process_user(user['username'],user['profile'])
				new_user['dispatched'] = True 
				registrations.save(new_user)
			else:
				print "New user (within 15 mins): " + user['username']
		
		elif 'dispatched' in new_user and new_user['dispatched'] is True:
		
			try:
				block_profile = get_full_profile('u/' + user['username'])
			except:
				print user['username']
			
			if profile_on_blockchain(user["username"],user["profile"]):
				registrations.remove(new_user)
			else:
				print "Not on blockchain yet: " + user['username']
				if datetime.datetime.utcnow() - new_user['created_at'] > datetime.timedelta(minutes=90):
				
					print "Re-sending"
					#process_user(user['username'],user['profile'])
			
		else:
			print "Random: " + user['username']
			#registrations.remove(new_user)

	counter = 0 

	for user in users.find():

		if 'stormtrooper' in user['username'] or 'clone' in user['username']:
			continue

		if 'username_activated' in user and user['username_activated'] is False:
			continue

		counter += 1

		if CHECK_BLOCKCHAIN:
			pass
		else:
			continue 

		if profile_on_blockchain(user["username"],user["profile"]):
			#print "Fine: " + user["username"]
			pass
		else:
			print "Problem: " + user["username"]
			#process_user(user['username'],user['profile'])

	print "Users: " + str(counter)

#-----------------------------------
def update_users(): 

	for new_user in updates.find():
		
		user_id = new_user['user_id']
		user = users.find_one({"_id":user_id})

		if profile_on_blockchain(user["username"],user["profile"]):
			updates.remove(new_user)
		else:
			print "Update: " + str(user['username'])
			old_user = old_users.find_one({"username":user["username"]})

			if old_user is not None:
				if old_user['backend_server'] == int(LOAD_BALANCER):
					process_user(user['username'],user['profile'])

#-----------------------------------
if __name__ == '__main__':

	#queue.remove({"activated":True})

	#process_users()
	update_users()
	








