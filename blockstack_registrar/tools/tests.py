#!/usr/bin/env python
# -*- coding: utf-8 -*-


import json
import csv

from coinrpc.coinrpc import check_registration, namecoind_name_show
from tools.onename_register import process_user, utf8len

from pymongo import MongoClient
import os 

MONGODB_URI = os.environ['MONGODB_URI']
HEROKU_APP = os.environ['HEROKU_APP'] 
remote_client = MongoClient(MONGODB_URI)
users = remote_client[HEROKU_APP].user

local_client = MongoClient()
registered = local_client['onename'].registered
queue = local_client['namecoin'].queue

#-----------------------------------
def check_linked_list(key):

	if check_registration(key):

		check_profile = namecoind_name_show(key)
		
		check_profile = check_profile['value']
		
		if 'next' in check_profile:
			return check_linked_list(check_profile['next'])
		else:
			return True 
	else:
		return False 

#-----------------------------------
if __name__ == '__main__':

	for user in users.find():

		username = user['username']
		key = 'u/' + username 

		check = registered.find_one({"username":username})

		if check is not None:
			continue 

		in_queue = queue.find_one({"username":username})

		if in_queue is not None:
			continue 

		process_user(user['username'],json.loads(user['profile']))

		'''
		if check_linked_list(key):
			print "Registered: " + username 
			registered.insert(user)
		else:
			print "Not registered: " + username
		'''
#-----------------------------------
