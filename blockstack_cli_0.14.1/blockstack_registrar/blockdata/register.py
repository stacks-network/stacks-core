#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

#520 is the real limit
VALUE_MAX_LIMIT = 512

import requests
import json

from coinrpc.namecoin.namecoind_wrapper import namecoind_blocks, namecoind_name_new, check_registration
from coinrpc.namecoin.namecoind_wrapper import namecoind_name_update, namecoind_name_show

from config import LOAD_BALANCER

#-----------------------------------
from pymongo import MongoClient
client = MongoClient() 

local_db = client['namecoin']
queue = local_db.queue
codes = local_db.codes

from config import MONGODB_URI
remote_client = MongoClient(MONGODB_URI)
remote_db = remote_client.get_default_database()
users = remote_db.user
registrations = remote_db.user_registration

#-----------------------------------
def utf8len(s):

	if type(s) == unicode:
		return len(s)
	else:
		return len(s.encode('utf-8'))

#-----------------------------------
def save_name_new_info(info,key,value):
	reply = {}
  
	try:
		
		reply['longhex'] = info[0]
		reply['rand'] = info[1]
		reply['key'] = key
		reply['value'] = value
		reply['backend_server'] = int(LOAD_BALANCER)

		#get current block...
		blocks = namecoind_blocks()

		reply['current_block'] = blocks['blocks']
		reply['wait_till_block'] = blocks['blocks'] + 12
		reply['activated'] = False
		
		#save this data to Mongodb...
		queue.insert(reply)

		reply['message'] = 'Your registration will be completed in roughly two hours'
		del reply['_id']        #reply[_id] is causing a json encode error
	
	except Exception as e:
		reply['message'] = "ERROR:" + str(e)
	
	return reply 

#-----------------------------------
def slice_profile(username, profile, old_keys=None):

	keys = []
	values = [] 

	key = 'u/' + username.lower()
	keys.append(key)

	def max_size(username):
		return VALUE_MAX_LIMIT - len('next: i-' + username + '000000')

	#-----------------------------------
	def splitter(remaining,username):

		split = {} 

		if utf8len(json.dumps(remaining)) < max_size(username):
			return remaining, None 
		else:
			for key in remaining.keys(): 
				split[key] = remaining[key]

				if utf8len(json.dumps(split)) < max_size(username):
					del remaining[key]
				else:
					del split[key]
					break 
			return split, remaining

	#-----------------------------------
	def get_key(key_counter):
		return 'i/' + username.lower() + '-' + str(key_counter)

	split, remaining = splitter(profile, username) 
	values.append(split)

	key_counter = 0
	counter = 0 

	while(remaining is not None):
		
		key_counter += 1
		key = get_key(key_counter)

		if old_keys is not None and key in old_keys:
			pass
		else:
			while check_registration(key):
				key_counter += 1 
				key = get_key(key_counter)

		split, remaining = splitter(remaining, username)
		keys.append(key) 
		values.append(split)

		values[counter]['next'] = key
		counter += 1

	return keys, values 

#-----------------------------------
def register_name(key,value):

	info = namecoind_name_new(key,json.dumps(value))

	reply = save_name_new_info(info,key,json.dumps(value))
	
	print reply
	print '---'

#-----------------------------------
def update_name(key,value):

	reply = {}

	info = namecoind_name_update(key,json.dumps(value))

	reply['key'] = key
	reply['value'] = value
	reply['activated'] = True
	reply['backend_server'] = int(LOAD_BALANCER) 

	#save this data to Mongodb...
	check = queue.find_one({'key':key})

	if check is None:
		queue.insert(reply)
	else:
		queue.save(reply)

	print reply
	print info
	print '---'

#----------------------------------
def get_old_keys(username):

	#----------------------------------
	def get_next_key(key): 
	
		check_profile = namecoind_name_show(key)

		try:
			check_profile = check_profile['value']

			if 'next' in check_profile:
				return check_profile['next']
		except:
			pass 

		return None 


	old_keys = []
	key1 = "u/" + username

	old_keys.append(str(key1))
	next_key = get_next_key(key1)

	while(next_key is not None):
		old_keys.append(str(next_key))
		next_key = get_next_key(next_key)
		
	return old_keys

#-----------------------------------
def process_user(username,profile):

	old_keys = get_old_keys(username) 

	keys, values = slice_profile(username,profile,old_keys)

	index = 0
	key1 = keys[index]
	value1 = values[index]

	print utf8len(json.dumps(value1))

	if check_registration(key1):
		
		#if name is registered
		print "name update: " + key1
		update_name(key1,value1)

	else: 
		#if not registered 
		print "name new: " + key1 
		register_name(key1,value1)

	process_additional_keys(keys, values)

#-----------------------------------
def process_additional_keys(keys,values):

	#register/update remaining keys
	size = len(keys)
	index = 1
	while index < size: 
		next_key = keys[index]
		next_value = values[index]

		if check_registration(next_key):
			print "name update: " + next_key
			print utf8len(json.dumps(next_value))
			update_name(next_key,next_value)
		else: 
			print "name new: " + next_key
			print utf8len(json.dumps(next_value))
			register_name(next_key,next_value)
			
		index += 1

#-----------------------------------
def set_backend_server(DISTRIBUTE=True):

	DEFAULT_SERVER = 2	
	BACKEND_SERVER_FOR_RESERVER = 1
	loadbalancer_counter = 0

	for i in users.find():

		if 'dispatched' in i and i['dispatched'] is False:

			loadbalancer_counter += 1

			if(loadbalancer_counter == 8):
				loadbalancer_counter = 0

			#hardcoded backend_server for reserved names
			if 'backend_server' not in i:
				selected_server = DEFAULT_SERVER

				if 'accesscode' in i:
					print "found reserved user, " + i['username'] + " using backend_server ", BACKEND_SERVER_FOR_RESERVER
					selected_server = BACKEND_SERVER_FOR_RESERVER
				else:
					if DISTRIBUTE:
						selected_server = loadbalancer_counter

				i['backend_server'] = selected_server
				users.save(i)

				print "sending " + i['username'] + " to backend_server " + str(selected_server)
				
#-----------------------------------
def check_new_registrations(LIVE=True):

	registered_counter = 0
	unregistered_counter = 0

	print '-' * 5
	print "Checking for new users"
	for user in registrations.find():

		if 'dispatched' in user and user['dispatched'] is False:

			unregistered_counter += 1

			if ('backend_server' in user) and (user['backend_server'] == int(LOAD_BALANCER)):
				if LIVE:
					try:
						process_user(user['username'],json.loads(user['profile']))
						print user['backend_server']
					except Exception as e:
						print e
						continue 
				
				username = 'u/' + user['username'].lower()
				extended = 'i/' + user['username'].lower() + '-1'

				local = queue.find_one({'key':username})
				if local is not None:
					print "in local DB"
					if LIVE:
						user['dispatched'] = True
						user['accepted'] = True
						users.save(user)
			
				print '-' * 5
		else:
			registered_counter += 1


	print "Registered users: ", registered_counter
	print "Not registered users: ", unregistered_counter

#-----------------------------------
if __name__ == '__main__':

	LIVE = True
	DISTRIBUTE = False
	set_backend_server(DISTRIBUTE)
	check_new_registrations(LIVE)