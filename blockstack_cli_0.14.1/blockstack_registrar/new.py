#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

from blockdata.namecoind_cluster import get_server
from blockdata.register import update_name
from commontools import setup_logging

import json 

import logging
setup_logging()
log = logging.getLogger()

from pymongo import MongoClient
client = MongoClient() 
local_db = client['temp_db']
expiring_users = local_db.users

from time import sleep

#-----------------------------------
def send_update():

	for i in expiring_users.find():
		key = i['name']
		try:
			value = json.loads(i['value'])

			value['message'] = value['message'].replace('This OneName username','This username')
		except:
			value = i['value']
			
		print key
		print value 
		print '-' * 5

		try:
			update_name(key,value)
		except Exception as e:
			print e 
		sleep(5)

#-----------------------------------
if __name__ == '__main__':

	key = 'u/goldmansachs'
	log.debug(get_server(key))
	#value = json.loads('{"next":"u/awright"}')
	#update_name(key,value)

	#send_update()