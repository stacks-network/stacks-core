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
config_default = current_dir + '/config_default'

config = ConfigParser.ConfigParser()

#if no local configuration then use the default servers
try:
	config.read(config_local)
	DNS_SERVER = config.get('dns','server1')
	ONS_SERVER = config.get('ons','server1')
	NAMECOIND_PORT = config.get('namecoind','port')
	NAMECOIND_USER = config.get('namecoind','user')
	NAMECOIND_PASSWD = config.get('namecoind','passwd')
	USE_HTTPS = config.get('namecoind','use_https')
except:
	config.read(config_default)
	DNS_SERVER = config.get('dns','server1')
	ONS_SERVER = config.get('ons','server1')
	NAMECOIND_PORT = config.get('namecoind','port')
	NAMECOIND_USER = config.get('namecoind','user')
	NAMECOIND_PASSWD = config.get('namecoind','passwd')
	USE_HTTPS = config.get('namecoind','use_https')

from .dns_resolver import dns_resolver
from .ons_resolver import ons_resolver