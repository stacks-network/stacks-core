#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

import os
import json

from config import MONGODB_URI

from coinrpc.namecoin.namecoind_wrapper import namecoind_name_show, get_full_profile
from blockdata.register import process_user

from pymongo import MongoClient
from bson.objectid import ObjectId

from encrypt.bip38 import bip38_decrypt

import datetime
import hashlib

#-----------------------------------
remote_client = MongoClient(MONGODB_URI)
client = MongoClient()

remote_db = remote_client.get_default_database()
users = remote_db.user
registrations = remote_db.user_registration
updates = remote_db.profile_update

#-----------------------------------
def profile_on_blockchain(username,DB_profile):

	block_profile = get_full_profile('u/' + user['username'])
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
if __name__ == '__main__':

	for i in updates.find():
		print "Update: " 
		print i

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
				#print '-' * 5
		elif 'dispatched' in new_user and new_user['dispatched'] is True:
			#process_user(user['username'],user['profile']) 

			block_profile = get_full_profile('u/' + user['username'])
			
			if profile_on_blockchain(user["username"],user["profile"]):
				registrations.remove(new_user)
			else:
				print "Not on blockchain yet: " + user['username']
			
		else:
			print "Random: " + user['username']
			#registrations.remove(new_user)

	for user in users.find():

		if 'stormtrooper' in user['username'] or 'clone' in user['username']:
			continue

		if 'username_activated' in user and user['username_activated'] is False:
			continue

		if profile_on_blockchain(user["username"],user["profile"]):
			#print "Fine: " + user["username"]
			pass
		else:
			print "Problem: " + user["username"]
			#process_user(user['username'],user['profile'])