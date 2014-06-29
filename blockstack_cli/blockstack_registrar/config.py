#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

'''
    configuration file
'''

try: 
	from config_local import *
except:

	import os

	DEBUG = True

	#--------------------------------------------------
	NAMECOIND_READONLY = False

	NAMECOIND_USE_HTTPS = True

	NAMECOIND_PORT = os.environ['NAMECOIND_PORT']
	NAMECOIND_SERVER = os.environ['NAMECOIND_SERVER']
	NAMECOIND_USER = os.environ['NAMECOIND_USER']
	NAMECOIND_PASSWD = os.environ['NAMECOIND_PASSWD']
	WALLET_PASSPHRASE = os.environ['WALLET_PASSPHRASE']
	#--------------------------------------------------

	MONGODB_URI = os.environ['MONGODB_URI']
	LOAD_BALANCER = os.environ['LOAD_BALANCER']