#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

import json
from coinrpc import namecoind 
from .register import process_user
from pymongo import MongoClient
from config import MONGODB_URI

users = MongoClient(MONGODB_URI).get_default_database().user

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
		entry = users.find({'username':username})
		for i in entry:
			user = i 
			break
		nmc_address = user['namecoin_address']
	except Exception as e:
		print e
		print "No such user in DB"
		return 

	#-----------------------------
	def name_transfer_inner(key):

		print key, nmc_address
		if(live):
			print namecoind.transfer(key,nmc_address)
	
	key = 'u/' + username

	name_transfer_inner(key)

	while(1):
		value = namecoind.name_show(key)['value']

		next_blob = None 

		try:
			next_blob = value['next']
		except:
			break

		if next_blob is not None: 
			key = next_blob 
			name_transfer_inner(key)	
				
#-----------------------------------
if __name__ == '__main__':

	live = True

	username = "clone66"

	do_name_transfer(username,live)
