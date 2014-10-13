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
if __name__ == '__main__':

	old_block = namecoind.blocks() - 10
	new_block = namecoind.blocks()

	log.debug("starting sync from block: %s", old_block) 

	while(1):
		
		while(old_block == new_block):
			sleep(30)
			new_block = namecoind.blocks()

		log.debug('current blcok: %s',new_block)
		check_blocks = new_block - old_block
		log.debug('checking last %s block(s)', check_blocks)

		warmup_cache('u/',check_blocks)
		warmup_cache('i/',check_blocks)

		old_block = new_block