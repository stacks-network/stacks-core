#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
	ONS Server
	~~~~~

	:copyright: (c) 2014 by OpenNameSystem.org
	:license: MIT, see LICENSE for more details.
"""

import os 
import logging
from logging.handlers import RotatingFileHandler
from time import sleep
from coinrpc import namecoind 
from commontools import log
from .warmup_cache import warmup_cache

current_dir =  os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

file_name = parent_dir + "/log/debug_log.txt"


#-----------------------------------
def create_rotating_file(path, maxBytes, backupCount):

	logger = logging.getLogger("Rotating Log")
	logger.setLevel(logging.DEBUG)
 
	# add a rotating handler
	handler = RotatingFileHandler(path, maxBytes=maxBytes, backupCount=backupCount)
 	logger.addHandler(handler)
 	
	return logger
#-----------------------------------
def log_to_file(logger, message):
	logger.debug(message)

#-----------------------------------
def sync_cache():

	#create a rotating logger
	logger = create_rotating_file(file_name, 10 * 1024 * 1024, 1)

	old_block = namecoind.blocks() - 10
	new_block = namecoind.blocks()

	message = "starting sync from block: %s" %old_block
	log_to_file(logger, message)

	while(1):
		
		while(old_block == new_block):
			sleep(30)
			new_block = namecoind.blocks()

		message = 'current block: %s' %new_block
		log_to_file(loger, message)

		check_blocks = new_block - old_block
		message = 'checking last %s block(s)' %check_blocks
		log_to_file(logger, message)

		warmup_cache('u/',check_blocks)
		warmup_cache('i/',check_blocks)

		old_block = new_block

#-----------------------------------
import daemon

with daemon.DaemonContext():
	sync_cache()