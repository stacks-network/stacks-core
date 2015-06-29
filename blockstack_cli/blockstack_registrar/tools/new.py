#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------
# Copyright 2015 Halfmoon Labs, Inc.
# All Rights Reserved
# -----------------------

from pybitcoin.rpc.namecoind_cluster import get_server
from registrar.nameops import update_name
from commontools import setup_logging

import json

import logging
setup_logging()
log = logging.getLogger()

from time import sleep

from registrar.config import MAIN_SERVER, LOAD_SERVERS


# -----------------------------------
if __name__ == '__main__':

    key = 'i/2drewlee-1'
    log.debug(get_server(key, MAIN_SERVER, LOAD_SERVERS))
    #value = json.loads('{"next":"u/awright"}')
    #update_name(key,value)

    #expiring_users = 
    #send_update()