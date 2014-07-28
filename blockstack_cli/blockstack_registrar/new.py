#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

from blockdata.namecoind_cluster import get_server
from common import log

#-----------------------------------
if __name__ == '__main__':

	key = 'u/stevenmichaels'

	log.debug(get_server(key))