# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

This file is part of Registrar.

    Registrar is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Registrar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Resolver. If not, see <http://www.gnu.org/licenses/>.
"""

from config import LOAD_SERVERS, MAX_PENDING_TX

from coinrpc.namecoind_cluster import pending_transactions

from commontools import log

from time import sleep


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
