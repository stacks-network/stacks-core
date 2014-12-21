#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    OpenDig
    ~~~~~

    :copyright: (c) 2014 by OpenNameSystem.org
    :license: MIT, see LICENSE for more details.
"""

from opendig import ONS_SERVERS, NAMECOIND_PORT, NAMECOIND_USER, \
    NAMECOIND_PASSWD, USE_HTTPS

import json
import hashlib
from coinrpc.namecoind_server import NamecoindServer
from multiprocessing.pool import ThreadPool
from collections import Counter

SERVER_CONFIRMATION_PERCENTAGE = 60

# currently using namecoind for storing data (but ONS can use any blockchain)
# ---------------------------------------


def error_reply(msg, code=-1):
    reply = {}
    reply['status'] = code
    reply['message'] = "ERROR: " + msg
    return reply

# -----------------------------------


def ons_resolver(key):

    def check_server(server):

        try:
            namecoind = NamecoindServer(server, NAMECOIND_PORT, NAMECOIND_USER,
                                        NAMECOIND_PASSWD)
            return_data = namecoind.get_full_profile('u/' + key)
            return return_data
        except:
            return error_reply("Couldn't connect to namecoind")

    pool = ThreadPool(len(ONS_SERVERS))

    replies = pool.map(check_server, ONS_SERVERS)
    pool.close()
    pool.join()

    data_hashes = []
    for reply in replies:
        data_hashes.append(hashlib.md5(json.dumps(reply)).hexdigest())

    count = Counter(data_hashes)
    max_repeated_times = count.most_common()[0][1]

    if max_repeated_times >= (SERVER_CONFIRMATION_PERCENTAGE/100.0) * len(ONS_SERVERS):
        return replies[0]
    else:
        return error_reply("Data from different ONS servers doens't match")

# ------------------------------------

if __name__ == "__main__":
    key = "ibrahim"
    print ons_resolver(key)
