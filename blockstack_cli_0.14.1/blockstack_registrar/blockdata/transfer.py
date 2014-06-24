#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from pymongo import Connection
from coinrpc.coinrpc import namecoind_transfer, namecoind_name_show, check_registration
from onename_register import process_user
from pymongo import MongoClient
import os 

LOAD_BALANCER = os.environ['LOAD_BALANCER']
import ssl

MONGODB_URI = os.environ['MONGODB_URI']
HEROKU_APP = os.environ['HEROKU_APP'] 
remote_client = MongoClient(MONGODB_URI)
users = remote_client[HEROKU_APP].user

#-----------------------------------
def test_private_key(passphrase,nmc_address):

	from coinkit.keypair import NamecoinKeypair

	keypair = NamecoinKeypair.from_passphrase(passphrase)
	
	print keypair.wif_pk()
	
	generated_nmc_address = keypair.address()

	if(generated_nmc_address == nmc_address):
		print "found a match"
		return True
	else:
		print "don't match"
		return False

#-----------------------------------
def do_name_transfer(username,live=False):

	try:
		entry = users.find_one({'username':username})
		nmc_address = entry['namecoin_address']
		backend_server = entry['backend_server']
	except:
		print "no such user in DB"
		return 

	key = 'u/' + username

	if check_registration(key):

		value = namecoind_name_show(key)['value']

		next_blob = None 

		try:
			next_blob = value['next']
		except:
			pass

		if(live):
			reply = namecoind_transfer(key,nmc_address)
			if 'message' in reply:
				print reply['message']
			else:
				print reply
				entry['name_transferred'] = True
				users.save(entry)
		
		print key, nmc_address
		print backend_server

		passphrase = ''
		#test_private_key(passphrase,nmc_address)

		if next_blob is not None: 
			print next_blob, nmc_address
			if(live):
				print namecoind_transfer(next_blob,nmc_address)	
				
	else:	
		print "activate the name first"

#-----------------------------------
if __name__ == '__main__':

	live = True

	username = "grapeape"

	user = users.find_one({"username":username})

	do_name_transfer(user['username'],live)

	'''

	MyWbJHsddjgqvzY22Z7Qiupwin3TiEoXkf

	user_list = ['ryanshea','samsmith','leena','saqib','ali','darthvader','ibrahim','mohammed','asjad']

	for user in users.find():

		if 'accepted' in user and user['accepted'] is True:

			if user['username'] in user_list:
				pass
			elif user['backend_server'] != int(LOAD_BALANCER):
				pass
			elif 'name_transferred' in user and user['name_transferred'] is True:
				print "already transferred: " + user['username']
			else:
				try:
					#print user
					do_name_transfer(user['username'],live)
				except ssl.SSLError:
					pass 
				except KeyError:
					pass
				print '-' * 5

	'''
