#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

import json
import requests 

from config import MONGODB_URI, OLD_DB, FRONTEND_SECRET
from config_local import CHAIN_API_KEY

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
def sweep_btc(transfer_user,LIVE=False):

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

		if balance == float(0):
			return False

		log.debug(new_user['username'])
		log.debug("old btc address: " + old_btc_address)
		bitcoind.importprivkey(keypair.wif_pk())
		
		if LIVE: 
			log.debug("sending " + str(balance) + " to " + new_btc_address)
			tx = bitcoind.sendtoaddress(new_btc_address,balance)
			log.debug(tx)
		else:
			log.debug("need to send " + str(balance) + " to " + new_btc_address)
			
		log.debug("final balance: %s", balance) 
		log.debug('-' * 5)
			
		return True

	return False

#-----------------------------------
def fetch_balance(btc_address):

	try:
		r = requests.get('https://api.chain.com/v1/bitcoin/addresses/' + btc_address + '?api-key-id=' + CHAIN_API_KEY)
		balance = r.json()['balance'] * 0.00000001 #convert to BTC from Satoshis
	except Exception as e:
		return None

	return balance

