#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

import json
import requests 

from config import MONGODB_URI, OLD_DB, FRONTEND_SECRET

from encrypt import bip38_decrypt
from coinkit import BitcoinKeypair, NamecoinKeypair

from commontools import log
from coinrpc import bitcoind 

#-----------------------------------
from pymongo import MongoClient

remote_db = MongoClient(MONGODB_URI).get_default_database()
new_users = remote_db.user
transfer = remote_db.name_transfer

local_db = MongoClient()['bitcoin-data'] 

old_db = MongoClient(OLD_DB).get_default_database()
old_users = old_db.user

#-----------------------------------
def sweep_btc(transfer_user):

	user_id = transfer_user['user_id']
	new_user = new_users.find_one({"_id":user_id})
		
	if new_user is None:
		return		
	

	old_user = old_users.find_one({'username':new_user['username']})
	
	if old_user is None:
		return
	
	new_btc_address = new_user['bitcoin_address']
	old_btc_address = json.loads(old_user['profile'])['bitcoin']['address']

	wif_pk = bip38_decrypt(str(transfer_user['encrypted_private_key']),FRONTEND_SECRET)

	keypair = BitcoinKeypair.from_private_key(wif_pk)

	if old_btc_address == keypair.address():
		balance = fetch_balance(old_btc_address)

		if balance is None:
			return True 
			
		if balance > float(0):
			log.debug(new_user['username'])
			log.debug("old btc address: " + old_btc_address)
			#print bitcoind.unlock_wallet()
			#print bitcoind.importprivkey(keypair.wif_pk())
			log.debug("final balance: %s", balance) 
			log.debug('-' * 5)
			return True

	return False
		
#-----------------------------------
def fetch_balance(btc_address):

	try:
		r = requests.get('http://blockchain.info/address/' + btc_address + '?format=json')
	except Exception as e:
		return None

	return r.json()['final_balance'] * 0.00000001 #convert to BTC from Satoshis 

