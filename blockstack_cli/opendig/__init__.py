#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
	OpenDig
	~~~~~

	:copyright: (c) 2014 by OpenNameSystem.org
	:license: MIT, see LICENSE for more details.
"""

import os 
import ConfigParser

__version__ = '0.1.0'

home_dir = os.path.expanduser('~')
current_dir =  os.path.abspath(os.path.dirname(__file__))

config_local = home_dir + '/.opendig'
config_default = current_dir + '/config_default.py'

config = ConfigParser.ConfigParser()

#------------------------------
def get_list(data):

	output = []
	data = data.rsplit(',')

	for item in data:
		item = item.lstrip(' ')
		item = item.rstrip(' ')
		output.append(item)

	return output

#------------------------------	
#if no local configuration then use the default servers
try:
	config.read(config_local)
	DNS_SERVERS = get_list(config.get('dns','servers'))
	ONS_SERVERS = get_list(config.get('ons','servers'))
	NAMECOIND_PORT = config.get('namecoind','port')
	NAMECOIND_USER = config.get('namecoind','user')
	NAMECOIND_PASSWD = config.get('namecoind','passwd')
	USE_HTTPS = config.get('namecoind','use_https')
except Exception as e:
	print "got except: "
	print e
	from config_default import * 
	
from .dns_resolver import dns_resolver
from .ons_resolver import ons_resolver
