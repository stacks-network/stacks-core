#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
	Openname-resolver
	~~~~~

	:copyright: (c) 2014 by Openname.org
	:license: MIT, see LICENSE for more details.
"""

try: 
	from config_local import *
except:

	import os
	from commontools import log

	DEBUG = True

	DEFAULT_PORT =5000
	DEFAULT_HOST = '127.0.0.1'

	MEMCACHED_PORT = '11211'
	MEMCACHED_TIMEOUT = 15 * 60
	MEMCACHED_ENABLED = True

	#--------------------------------------------------
	NAMECOIND_USE_HTTPS = True

	try:
		NAMECOIND_SERVER = os.environ['NAMECOIND_SERVER']
		NAMECOIND_PORT = os.environ['NAMECOIND_PORT']
		NAMECOIND_USER = os.environ['NAMECOIND_USER']
		NAMECOIND_PASSWD = os.environ['NAMECOIND_PASSWD']
	except:
		#log.debug("Namecoind not configured")
		NAMECOIND_PORT = 5005
		NAMECOIND_SERVER = NAMECOIND_USER = NAMECOIND_PASSWD = ''

	#--------------------------------------------------
	
	try:
		API_USERNAME = os.environ['API_USERNAME']
		API_PASSWORD = os.environ['API_PASSWORD']
	except: 
		API_USERNAME = 'opennamesystem'
		API_PASSWORD = 'opennamesystem'
