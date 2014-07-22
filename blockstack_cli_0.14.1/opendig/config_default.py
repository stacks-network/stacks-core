# -*- coding: utf-8 -*-
"""
	OpenDig
	~~~~~

	:copyright: (c) 2014 by OpenNameSystem.org
	:license: MIT, see LICENSE for more details.
"""

#these default options are provided only for the convenience of users
#users should really specify their own servers in ~/.opendig (in ini format)

DNS_SERVERS = ['8.8.8.8','8.8.4.4'] #use a Google DNS servers as default backup 
ONS_SERVERS = ['162.243.253.65','107.170.167.141'] #use a OneName ONS servers as default backup 
NAMECOIND_PORT = 8332
NAMECOIND_USER = 'opennamesystem'
NAMECOIND_PASSWD = 'opennamesystem'
USE_HTTPS = True
