#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
	ONS Server
	~~~~~

	:copyright: (c) 2014 by OpenNameSystem.org
	:license: MIT, see LICENSE for more details.
"""

import os 
from time import sleep
from coinrpc import namecoind 
from commontools import log
from .warmup_cache import warmup_cache

current_dir =  os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

file_name = parent_dir + "/log/debug_log.txt"

#-----------------------------------
def log_to_file(message):
	f = open(file_name, "a")
	f.write(message)
	f.write("\n")
	f.close()

#-----------------------------------
def sync_cache():

	old_block = namecoind.blocks() - 10
	new_block = namecoind.blocks()

	message = "starting sync from block: %s" %old_block
	log_to_file(message)

	while(1):
		
		while(old_block == new_block):
			sleep(30)
			new_block = namecoind.blocks()

		message = 'current block: %s' %new_block
		log_to_file(message)

		check_blocks = new_block - old_block
		message = 'checking last %s block(s)' %check_blocks
		log_to_file(message)

		warmup_cache('u/',check_blocks)
		warmup_cache('i/',check_blocks)

		old_block = new_block

#-----------------------------------
import daemon

with daemon.DaemonContext():
	sync_cache()