#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------
# Copyright 2015 Halfmoon Labs, Inc.
# All Rights Reserved
# -----------------------

from config import LOAD_SERVERS, MAX_PENDING_TX

from coinrpc.namecoind_cluster import pending_transactions

from commontools import log

from time import sleep

# -----------------------------------
def load_balance(current_server):

    counter = 0

    for server in LOAD_SERVERS:
        if current_server == server:
            server_number = counter

        counter += 1

    log.debug("current server: %s", LOAD_SERVERS[server_number])

    while(1):
        if pending_transactions(LOAD_SERVERS[server_number]) > MAX_PENDING_TX:

            if server_number == len(LOAD_SERVERS) - 1:
                server_number = 0
            else:
                server_number += 1

            log.debug("load balancing: switching to %s", LOAD_SERVERS[server_number])
            sleep(5)

        else:
            break

    return LOAD_SERVERS[server_number]

# -----------------------------------
if __name__ == '__main__':

    load_balance('named3')