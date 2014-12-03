#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

import os
import json

from config import MONGODB_URI, OLD_DB

from blockdata.register import process_user, update_name, register_name

from pymongo import MongoClient
from bson.objectid import ObjectId

from encrypt import bip38_decrypt

import datetime
import hashlib
from time import sleep

#from tools.sweep_btc import sweep_btc

FRONTEND_SECRET = os.environ['FRONTEND_SECRET']

from encrypt import bip38_decrypt
from coinkit import BitcoinKeypair, NamecoinKeypair

from coinrpc import namecoind 
from commontools import get_json

#-----------------------------------
remote_client = MongoClient(MONGODB_URI)
client = MongoClient()

remote_db = remote_client.get_default_database()
users = remote_db.user
registrations = remote_db.user_registration
updates = remote_db.profile_update
transfer = remote_db.name_transfer

client = MongoClient() 
local_db = client['namecoin']
queue = local_db.queue
local_transfer = local_db.transfer
skip_users = local_db.skip_users

old_client = MongoClient(OLD_DB)
old_db = old_client.get_default_database()
old_users = old_db.user

reservation = remote_db.username_reservation

#-----------------------------------
def print_user(user):

	for key, value in user.iteritems():
		print key + " : " + str(value)

#-----------------------------------
def cleanup_user(username): 

	user = users.find_one({"username":username})

	user_id = user['_id']
	
	cleanup_user = updates.find_one({"user_id":user_id})
	
	if cleanup_user is not None:
		print "cleaning update: " + user["username"]
		updates.remove(cleanup_user)

	cleanup_user = transfer.find_one({"user_id":user_id})
	
	if cleanup_user is not None:
		print "cleaning transfer: " + user["username"]
		transfer.remove(cleanup_user)

	cleanup_user = registrations.find_one({"user_id":user_id})
	
	if cleanup_user is not None:
		print "cleaning register: " + user["username"]
		registrations.remove(cleanup_user)

#-----------------------------------
def process_manually_alias(username,alias):

	user = users.find_one({'username':username})
	process_user(alias,user['profile'])

#-----------------------------------
def process_manually(username):

	user = users.find_one({'username':username})
	process_user(user['username'],user['profile'])
	#cleanup_user(username)

#-----------------------------------
def process_manually_old(username):

	user = old_users.find_one({'username':username})
	process_user(user['username'],json.loads(user['profile']))

#-----------------------------------
def make_alias(alias,target):

	value = {}
	value['next'] = 'u/' + target

	process_user(alias,value)

#-----------------------------------
def find_via_email(email):

	user = users.find_one({'email':email})

	print_user(user)

#-----------------------------------
def find_via_username(username):

	user = users.find_one({'username':username})
	print_user(user)

#-----------------------------------
def find_old_user(username):

	user = old_users.find_one({'username':username})
	print_user(user)


#-----------------------------------
def change_profile(username,profile):

	user = users.find_one({'username':username})
	user['profile'] = profile
	users.save(user)

#-----------------------------------
def import_user(username):
	
	for transfer_user in transfer.find():

		user_id = transfer_user['user_id']
		new_user = users.find_one({"_id":user_id})

		if new_user is None:
			continue
		
		if new_user['username'] == username:
			old_user = old_users.find_one({'username':new_user['username']})
			print username
		else:
			continue

		old_nmc_address = old_user['namecoin_address']

		wif_pk = bip38_decrypt(str(transfer_user['encrypted_private_key']),FRONTEND_SECRET)

		keypair = NamecoinKeypair.from_private_key(wif_pk)

		if old_nmc_address == keypair.address():
			print old_nmc_address
			print namecoind.importprivkey(keypair.wif_pk())


#-----------------------------------
def import_update(username):
	
	for update_user in updates.find():

		user_id = update_user['user_id']
		new_user = users.find_one({"_id":user_id})

		if new_user is None:
			continue
		
		if new_user['username'] == username:
			print username
		else:
			continue

		nmc_address = new_user['namecoin_address']

		wif_pk = bip38_decrypt(str(update_user['encrypted_private_key']),FRONTEND_SECRET)

		keypair = NamecoinKeypair.from_private_key(wif_pk)

		if nmc_address == keypair.address():
			print nmc_address
			print namecoind.importprivkey(keypair.wif_pk())

#-----------------------------------
def get_unlock_url(username):

	for i in remote_db.username_reservation.find():
		if i['username'] == username:
			print 'http://onename.io/?c=' + i['access_code']

#-----------------------------------
def pending_transactions(): 

	reply = namecoind.listtransactions("",10000)

	counter = 0 

	for i in reply:
		if i['confirmations'] == 0:
			counter += 1 


		if counter == MAX_PENDING_TX:
			return True 

	return False

#-----------------------------------
def send_update(expiring_users):

	for i in expiring_users:
		key = i['name']
		try:
			value = json.loads(i['value'])
		except:
			value = i['value']
			
		if 'message' in value: 

			value['message'] = value['message'].replace('This OneName username','This username')

			print key
			print value 
			print '-' * 5

			try:
				update_name(key,value)
				sleep(5)
			except Exception as e:
				print e 

#-----------------------------------
def get_emails(expiring_users):
	
	emails = [] 

	for i in expiring_users:
		username = i["name"].lstrip("u/")
		reply = old_users.find_one({"username":username})

		if reply is not None and 'email' in reply:
			emails.append(reply['email']) 
		#print '-' * 5

	print len(emails)

	from collections import Counter

	counter = Counter(emails)

	temp = counter.most_common()

	fout = open('expiring_emails.txt','w')

	for i in temp:

		fout.write(str(i[0]) + ", " + str(i[1]) + '\n')

	fout.close()

#-----------------------------------
def grab_expiring_names():

	usernames = ['fredwilson']

	while(1):
		for username in usernames:

			key = 'u/' + username
			reply = namecoind.name_show(key)

			value = get_json(reply['value']) 

			print "key %s expires in %s" % (key, reply['expires_in'])

			if 'expired' in reply and int(reply['expired']) == 1:
				register_name(key,value)

			sleep(60)

#-----------------------------------
if __name__ == '__main__':

	username = 'misterigl'

	#email = 'robertandrewsmith@gmail.com'


	#user = users.find_one({'email':email})
	#user['email'] = 'robertandrewsmith@gmail.com'
	#users.save(user)
	#print_user(user)

	process_manually(username)
	exit(0)

	#username = "winklevoss1"
	#alias = "winklevoss"
	#process_manually_alias(username,alias)

	
	#user = users.find_one({"username":username})

	#profile = user['profile']

	
	#process_manually_old(username)

	#cleanup_user(username)
	#print_user(user)
	#import_user(username)
	#cleanup_user(username)
	
	'''
	from blockdata.namecoind_cluster import get_server

	for i in skip_users.find():

		reply = get_server(i['key'])

		if reply['server'] == None:
			pass
		else:
			print i['key']
			print skip_users.remove(i)	
	'''

	from blockdata.renew_names import get_expiring_names, get_expired_names
	expiring_users = get_expiring_names('u/',5000)
	get_emails(expiring_users)
	expired_users = get_expired_names('u/')

	exit(0)

	counter_squatted = 0 


	MAX_PENDING_TX = 50 
	
	for i in expiring_users:

		#if i['name'] in ignore_names:
		#	continue

		reply = skip_users.find_one({"key":i['name']})

		if reply is not None:
			print "Skipping: " + reply['key']
			continue

		username = i['name'].lstrip('u/')

		print '-' * 5
		print username
		print i['expires_in']

		new_user = users.find_one({'username':username})

		if new_user is not None: 
			try:
				process_manually(username)

			except Exception as e: 
				if e.message == "cannot concatenate 'str' and 'NoneType' objects":
					entry = {}
					entry["key"] = i['name'] 
					skip_users.insert(entry)
				else:
					print e
		
			continue

		old_user = old_users.find_one({'username':username})

		if old_user is not None:
			try:
				process_manually_old(username)
				
			except Exception as e:
				if e.message == "cannot concatenate 'str' and 'NoneType' objects":
					entry = {}
					entry["key"] = i['name'] 
					skip_users.insert(entry)
				else:
					print e
			continue

		print "Not our user" 
		
	#process_manually(username)
	#process_manually_old(username)
	#process_manually_alias(username,alias)
	

	#update_name(key,value)	
	
