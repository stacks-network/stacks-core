#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

from blockdata.namecoind_cluster import get_server
from commontools import setup_logging

import logging
setup_logging()
log = logging.getLogger()

#-----------------------------------
if __name__ == '__main__':

	key = 'u/clone71'

	log.debug(get_server(key))