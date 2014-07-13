#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

import os
import json

from coinrpc.namecoin.namecoind_server import NamecoindServer 

from config import NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD
from config import MAIN_SERVER, LOAD_SERVERS

from multiprocessing.pool import ThreadPool 

reply = {}
reply["registered"] = False
reply["server"] = None
reply["ismine"] = False 
		
#-----------------------------------
def check_address(address): 

	reply['registered'] = True

	#--------------------------
	def check_address_inner(server):

		try:
			namecoind = NamecoindServer(server, NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD)

			info = json.loads(namecoind.validate_address(address))
		except:
			return

		if info['ismine'] is True: 
			reply['server'] = server 
			reply['ismine'] = True

	#first check the main server
	check_address_inner(MAIN_SERVER)

	if reply['ismine'] is True:
		return reply

	#if not main server, check others
	pool = ThreadPool(len(LOAD_SERVERS))

	pool.map(check_address_inner, LOAD_SERVERS)
	pool.close()
	pool.join() 

	return reply

#-----------------------------------
def get_server(key): 

	namecoind = NamecoindServer(MAIN_SERVER, NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD)

	info = namecoind.name_show(key)

	if 'namecoin_address' in info:	
		return check_address(info['namecoin_address'])
	else:
		return reply
