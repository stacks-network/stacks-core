#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

#520 is the real limit
#hardcoded here instead of some config file
VALUE_MAX_LIMIT = 512

import json

from common import utf8len, log
from common import users, register_queue

from coinrpc.namecoin.namecoind_server import NamecoindServer 
from blockdata.namecoind_cluster import get_server

from config import NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD, WALLET_PASSPHRASE, NAMECOIND_USE_HTTPS, NAMECOIND_SERVER
from config import MAIN_SERVER, LOAD_SERVERS
from config import DEFAULT_HOST, MEMCACHED_PORT, MEMCACHED_TIMEOUT

from coinrpc import namecoind

import pylibmc
from time import time
mc = pylibmc.Client([DEFAULT_HOST + ':' + MEMCACHED_PORT],binary=True)
 
#-----------------------------------
def register_name(key,value,server=NAMECOIND_SERVER):

	reply = {}

	#check if already in register queue (name_new) 
	check_queue = register_queue.find_one({"key":key})

	if check_queue is not None:
		reply['message'] = "ERROR: " + "already in register queue: " + str(key)
	else:

		namecoind = NamecoindServer(server, NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD, NAMECOIND_USE_HTTPS, WALLET_PASSPHRASE)			

		info = namecoind.name_new(key,json.dumps(value))

		try:
		
			reply['longhex'] = info[0]
			reply['rand'] = info[1]
			reply['key'] = key
			reply['value'] = json.dumps(value)

			#get current block...
			blocks = namecoind.blocks()

			reply['current_block'] = blocks['blocks']
			reply['wait_till_block'] = blocks['blocks'] + 12
			reply['activated'] = False
			reply['server'] = server
		
			#save this data to Mongodb...
			register_queue.insert(reply)

			#reply[_id] is causing a json encode error
			del reply['_id']
	
		except Exception as e:
			reply['message'] = "ERROR: " + str(e)
	
	log.debug(reply)
	log.debug('-' * 5)

	return reply 

#-----------------------------------
def update_name(key,value):

	reply = {}

	cache_reply = mc.get("name_update_" + str(key))

	if cache_reply is None: 
	
		#server = get_server(key)
		#server = server['server']
		log.debug(value)

		namecoind = NamecoindServer(NAMECOIND_SERVER, NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD, NAMECOIND_USE_HTTPS, WALLET_PASSPHRASE)

		info = namecoind.name_update(key,json.dumps(value))

		if 'code' in info: 
			reply = info 
		else:
			reply['tx'] = info
			mc.set("name_update_" + str(key),"in_memory",int(time() + MEMCACHED_TIMEOUT))
		
	else:
		reply['message'] = "ERROR: " + "recently sent name_update: " + str(key)

	log.debug(reply)
	log.debug('-' * 5)
		
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

		split, remaining = splitter(remaining, username)
		keys.append(key) 
		values.append(split)

		values[counter]['next'] = key
		counter += 1

	return keys, values 

#----------------------------------
def get_old_keys(username):

	#----------------------------------
	def get_next_key(key): 
	
		check_profile = namecoind.name_show(key)

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
def process_user(username,profile,server=NAMECOIND_SERVER):

	#old_keys = get_old_keys(username) 

	keys, values = slice_profile(username,profile)

	index = 0
	key1 = keys[index]
	value1 = values[index]

	if namecoind.check_registration(key1):
		
		#if name is registered
		log.debug("name update: %s", key1)
		log.debug("size: %s", utf8len(json.dumps(value1)))
		update_name(key1,value1)

	else: 
		#if not registered 
		log.debug("name new: %s", key1)
		log.debug("size: %s", utf8len(json.dumps(value1)))
		register_name(key1,value1,server)

	process_additional_keys(keys, values,server)

#-----------------------------------
def process_additional_keys(keys,values,server):

	#register/update remaining keys
	size = len(keys)
	index = 1
	while index < size: 
		next_key = keys[index]
		next_value = values[index]

		log.debug(utf8len(json.dumps(next_value)))

		if namecoind.check_registration(next_key):
			log.debug("name update: " + next_key)
			update_name(next_key,next_value)
		else: 
			log.debug("name new: " + next_key)
			register_name(next_key,next_value,server)
			
		index += 1
