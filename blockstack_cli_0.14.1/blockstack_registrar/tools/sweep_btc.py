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
	
	new_btc_address = new_user['bitcoin_address']
	old_btc_address = json.loads(old_user['profile'])['bitcoin']['address']

	log.debug(new_user['username'])
	wif_pk = bip38_decrypt(str(transfer_user['encrypted_private_key']),FRONTEND_SECRET)

	keypair = BitcoinKeypair.from_private_key(wif_pk)

	if old_btc_address == keypair.address():
		log.info("match")
		process_balance(old_btc_address)

	log.info('-' * 5)

#-----------------------------------
def fetch_balance(address):

	try:
		r = requests.get('http://blockchain.info/address/' + address + '?format=json')
		return r.json()
	
	except Exception as e:
		return None

#-----------------------------------
def process_balance(btc_address):

	result = fetch_balance(btc_address)
	final_balance = result['final_balance']
	final_balance = 0.00000001 * final_balance

	log.info("final balance: %s", final_balance) 


#-----------------------------------
if __name__ == '__main__':

	for i in transfer.find():
		sweep_btc(i)
		
