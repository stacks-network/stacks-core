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

from time import sleep

#-----------------------------------
remote_client = MongoClient(MONGODB_URI)
remote_db = remote_client.get_default_database()
users = remote_db.user
registrations = remote_db.user_registration
updates = remote_db.profile_update
transfer = remote_db.name_transfer

old_client = MongoClient(OLD_DB)
old_db = old_client.get_default_database()
old_users = old_db.user

local_client = MongoClient() 
local_db = local_client['namecoin']
queue_register = local_db.queue
queue_update = local_db.queue_update

problem_users = ['madmoneymachine', 'drmox', 'emiljohansson','xfaure','megaz28','maxweiss','kh','patrickcines']

#-----------------------------------
def process_profile(username,profile):

	if username in problem_users:
		return

	#check if already in register queue (name_new) 
	check_queue = queue_register.find_one({"key":'u/' + username})

	if check_queue is not None:
		print "Already in register queue: " + str(username)
		return

	#check if already in update queue (name_update) 
	check_queue = queue_update.find_one({"key":'u/' + username})

	if check_queue is not None:
		print "Already in update queue: " + str(username)
		return

	#check if load-balancer is correct
	old_user = old_users.find_one({"username":username})	

	if old_user is not None:
		if old_user['backend_server'] != int(LOAD_BALANCER):
			print "Not on this server: " + str(username) 
			print "Run on server: " + str(old_user['backend_server'])
			return			

	process_user(username,profile)

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
def register_users(): 

	for new_user in registrations.find():

		user_id = new_user['user_id']
		user = users.find_one({"_id":user_id})

		if 'stormtrooper' in user['username'] or 'clone' in user['username']:
			continue
			
		if 'dispatched' in new_user and new_user['dispatched'] is False: 
	
			if datetime.datetime.utcnow() - new_user['created_at'] > datetime.timedelta(minutes=15):
				print "Dispatch: " + user['username']
				
				process_profile(user['username'],user['profile'])
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
				if datetime.datetime.utcnow() - new_user['created_at'] > datetime.timedelta(minutes=90):
				
					print "Problem (90 mins): " + user['username']
					#print "Re-sending after 180 mins: " + user['username']
					#process_profile(user['username'],user['profile'])
			
		else:
			print "Random: " + user['username']
			#registrations.remove(new_user)

		sleep(1)

#-----------------------------------
def check_users(): 

	counter = 0 

	for user in users.find():

		if 'stormtrooper' in user['username'] or 'clone' in user['username']:
			continue

		if 'username_activated' in user and user['username_activated'] is False:
			continue

		counter += 1

		if profile_on_blockchain(user["username"],user["profile"]):
			#print "Fine: " + user["username"]
			pass
		else:
			print "Problem: " + user["username"]
			#process_profile(user['username'],user['profile'])

	print "Users: " + str(counter)

#-----------------------------------
def check_transfer(): 

	for new_user in transfer.find():
	
		user_id = new_user['user_id']
		user = users.find_one({"_id":user_id})

		if profile_on_blockchain(user["username"],user["profile"]):
			transfer.remove(new_user)
		else:
			print "Problem: " + user["username"]
			process_profile(user['username'],user['profile'])

#-----------------------------------
def update_users(): 

	for new_user in updates.find():
		
		user_id = new_user['user_id']
		user = users.find_one({"_id":user_id})

		if profile_on_blockchain(user["username"],user["profile"]):
			updates.remove(new_user)
		else:
			print "Update: " + str(user['username'])
			process_profile(user['username'],user['profile'])

#-----------------------------------
def cleanup_db(): 

	print "----------"
	print "Cleaning DB"

	for new_user in updates.find():
		
		user_id = new_user['user_id']
		user = users.find_one({"_id":user_id})

		if profile_on_blockchain(user["username"],user["profile"]):
			print "cleaning: " + user["username"]
			updates.remove(new_user)
	
	for new_user in transfer.find():
		
		user_id = new_user['user_id']
		user = users.find_one({"_id":user_id})

		if profile_on_blockchain(user["username"],user["profile"]):
			print "cleaning: " + user["username"]
			transfer.remove(new_user)
	
	for new_user in registrations.find():
		
		user_id = new_user['user_id']
		user = users.find_one({"_id":user_id})

		if profile_on_blockchain(user["username"],user["profile"]):
			print "cleaning: " + user["username"]
			registrations.remove(new_user)

	print "----------"
	
#-----------------------------------
if __name__ == '__main__':

	#check_users()
	#check_transfer()
	#update_users()
	
	register_users()
	
	cleanup_db()




