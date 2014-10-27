#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
	ONS Server
	~~~~~

	:copyright: (c) 2014 by OpenNameSystem.org
	:license: MIT, see LICENSE for more details.
"""

from time import sleep
from coinrpc import namecoind 
from commontools import log
from .warmup_cache import warmup_cache


#-----------------------------------
def log_to_file(file, message):
	f = open(file, "a")
	f.write(message)
	f.write("\n")
	f.close()
#-----------------------------------
def sync_cache():

	file = "debug_logs.txt"
	
	old_block = namecoind.blocks() - 10
	new_block = namecoind.blocks()

	log.debug("starting sync from block: %s", old_block) 
	log_to_file(file, "starting sync from block: %s", old_block)

	while(1):
		
		while(old_block == new_block):
			sleep(30)
			new_block = namecoind.blocks()

		log.debug('current block: %s',new_block)
		log_to_file(file, 'current block: %s',new_block)

		check_blocks = new_block - old_block
		log.debug('checking last %s block(s)', check_blocks)
		log_to_file(file, 'checking last %s block(s)', check_blocks)

		warmup_cache('u/',check_blocks)
		warmup_cache('i/',check_blocks)

		old_block = new_block

#-----------------------------------
import daemon

with daemon.DaemonContext():
	sync_cache()