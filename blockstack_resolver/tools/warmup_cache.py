#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
	ONS Server
	~~~~~

	:copyright: (c) 2014 by OpenNameSystem.org
	:license: MIT, see LICENSE for more details.
"""

from coinrpc import namecoind 
from server.config import DEFAULT_HOST, MEMCACHED_TIMEOUT, MEMCACHED_PORT

import pylibmc
mc = pylibmc.Client([DEFAULT_HOST + ':' + MEMCACHED_PORT],binary=True)

from commontools import log 

#-----------------------------------
def warmup_cache(regrex,check_blocks=0):

	log.debug("processing namespace %s",regrex)

	reply = namecoind.name_filter(regrex,check_blocks)

	counter = 0 
	for i in reply: 

		try:
			#set to no expiry i.e., 0
			mc.set("name_" + str(i['name']),i['value'],0)
			log.debug("inserting %s in cache",i['name'])
			counter += 1
		except:
			log.debug("not putting %s in cache",i['name'])
	
	log.debug("inserted %s entries in cache",counter)
	log.debug('-'*5)

#-----------------------------------
if __name__ == '__main__':

	warmup_cache('u/')
	warmup_cache('i/')