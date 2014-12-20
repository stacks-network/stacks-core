#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Openname-resolver
    ~~~~~

    :copyright: (c) 2014 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

import sys
import os

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")
sys.path.insert(0, parent_dir)

from coinrpc import namecoind
from server.config import MEMCACHED_SERVERS, MEMCACHED_USERNAME
from server.config import MEMCACHED_PASSWORD, MEMCACHED_TIMEOUT

import pylibmc
mc = pylibmc.Client(MEMCACHED_SERVERS, binary=True,
                    username=MEMCACHED_USERNAME, password=MEMCACHED_PASSWORD)

from commontools import log


# -----------------------------------
def warmup_cache(regrex, check_blocks=0):

    log.debug("processing namespace %s", regrex)

    reply = namecoind.name_filter(regrex, check_blocks)

    counter = 0
    for i in reply:

        try:
            # set to no expiry i.e., 0
            mc.set("name_" + str(i['name']),i['value'],0)
            log.debug("inserting %s in cache",i['name'])
            counter += 1
        except:
            log.debug("not putting %s in cache",i['name'])

    log.debug("inserted %s entries in cache",counter)
    log.debug('-'*5)

# -----------------------------------
if __name__ == '__main__':

    warmup_cache('u/')
    warmup_cache('i/')
