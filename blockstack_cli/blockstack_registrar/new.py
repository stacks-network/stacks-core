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

from time import sleep


#-----------------------------------
if __name__ == '__main__':

	key = 'u/muneeb'
	log.debug(get_server(key))
	#value = json.loads('{"next":"u/awright"}')
	#update_name(key,value)

	#expiring_users = 
	#send_update()